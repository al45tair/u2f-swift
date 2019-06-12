//
//  U2FHIDTransport.swift
//  nteractClient
//
//  Created by Alastair Houghton on 09/10/2017.
//  Copyright © 2017 Alastair's Place. All rights reserved.
//

import Foundation

class U2FHIDTransport : U2FTransport {
  
  enum State : Equatable {
    case inactive
    case initialising
    case active
    case disconnected
    case failed(reason: String)
  
    static func ==(lhs: State, rhs: State) -> Bool {
      switch (lhs, rhs) {
      case (.inactive, .inactive):
        return true
      case (.initialising, .initialising):
        return true
      case (.active, .active):
        return true
      case (.disconnected, .disconnected):
        return true
      case (.failed(_), .failed(_)):
        return true
      default:
        return false
      }
    }
  }
  
  private var _hidDevice : IOHIDDevice
  var hidDevice : IOHIDDevice { return _hidDevice }
  
  private var state : State
  private var channel : UInt32
  private var packetSize : Int
  private var nonce : Data
  private var u2fVersion : UInt8?
  private var deviceVersion : (UInt8, UInt8, UInt8)?
  private var deviceCaps : UInt8?
  
  private var queuedMessages : [Data] = []
  private var queuedCallbacks : [(U2FTransportStatus, Data?) -> Void] = []

  private var buffer = Data()
  private var command : UInt8 = 0
  private var expectedLength : UInt16 = 0
  private var expectedSequence : UInt8 = 0
  private var maxInputSize : Int = 0
  
  private var report : Data!
  
  init(device: IOHIDDevice) {
    _hidDevice = device
    channel = u2f.cidBroadcast
    state = .inactive
    nonce = urandom(length: 8)

    let maxSizeCF = IOHIDDeviceGetProperty(device, kIOHIDMaxOutputReportSizeKey as CFString)
    packetSize = maxSizeCF as! Int
    
    let maxReportCF = IOHIDDeviceGetProperty(device, kIOHIDMaxInputReportSizeKey as CFString)
    maxInputSize = maxReportCF as! Int
    
    report = Data(count: maxInputSize)
  }
  
  deinit {
    _close()
  }
  
  var usesShortEncoding: Bool { return false }
  
  private func _failed(_ reason: String) {
    _close()
    state = .failed(reason: reason)
    queuedMessages = []
    for callback in queuedCallbacks {
      callback(.failed(reason: reason), nil)
    }
    queuedCallbacks = []
  }
  
  private func _deviceRemoved() {
    _close()
    state = .disconnected
    queuedMessages = []
    for callback in queuedCallbacks {
      callback(.disconnected, nil)
    }
    queuedCallbacks = []
  }
  
  private func _close() {
    switch (state) {
    case .active, .initialising:
      report.withUnsafeMutableBytes { (ptr) in
        IOHIDDeviceRegisterInputReportCallback(_hidDevice, ptr, maxInputSize,
                                               nil, Unmanaged.passUnretained(self).toOpaque())
      }
      IOHIDDeviceRegisterRemovalCallback(_hidDevice, nil,
                                         Unmanaged.passUnretained(self).toOpaque())
      IOHIDDeviceUnscheduleFromRunLoop(_hidDevice,
                                       RunLoop.current.getCFRunLoop(),
                                       RunLoopMode.commonModes as CFString)
      IOHIDDeviceClose(_hidDevice, 0)
    default:
      break
    }
  }
  
  private func _uint32FromBytes(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) -> UInt32 {
    var result : UInt32
    
    result = UInt32(a) << 24
    result |= UInt32(b) << 16
    result |= UInt32(c) << 8
    result |= UInt32(d)
    
    return result
  }
  
  private func _recv(result: IOReturn, type: IOHIDReportType,
                     reportID: UInt32, report: Data) {
    if report.count < 7 {
      _failed("Bad report (data too short)")
      return
    }
    
    let cid = _uint32FromBytes(report[0],
                               report[1],
                               report[2],
                               report[3])
    let cmd = report[4]
    
    if cid != channel {
      _failed("Incorrect channel in response")
      return
    }
    
    if cmd & UInt8(0x80) != 0 {
      if expectedLength > buffer.count {
        _failed("Bad report (truncated multi-part report)")
        return
      }
      
      command = cmd
      buffer.removeAll()
      expectedSequence = 0
      expectedLength = (UInt16(report[5]) << 8) | UInt16(report[6])

      let needed = expectedLength - UInt16(buffer.count)
      let avail = UInt16(report.endIndex - 7)
      let todo = avail > needed ? needed : avail

      buffer.append(report[7..<todo + 7])
    } else {
      if command == 0 {
        _failed("Bad report (continuation but no command)")
        return
      }
      
      if cmd != expectedSequence {
        _failed("Bad report (unexpected sequence number)")
        return
      }
      
      let needed = expectedLength - UInt16(buffer.count)
      let avail = UInt16(report.endIndex - 5)
      let todo = avail > needed ? needed : avail
      
      buffer.append(report[5..<todo + 5])
      
      expectedSequence += 1
    }
    
    if expectedLength > buffer.count {
      if expectedSequence == 128 {
        _failed("Bad report (over length, too many fragments")
      }
      return
    }
    
    if state == .initialising {
      // This is the response to our U2F_HID_INIT message
      if buffer.count < 17 || cmd != u2f.hidInit {
        _failed("Bad U2F_HID_INIT response (too short or wrong command)")
        return
      }

      if nonce != buffer[0..<8] {
        _failed("Bad nonce")
        return
      }
      
      channel = _uint32FromBytes(buffer[8], buffer[9],
                                 buffer[10], buffer[11])
      u2fVersion = buffer[12]
      deviceVersion = (buffer[13], buffer[14], buffer[15])
      deviceCaps = buffer[16]
      
      state = .active
      
      _processQueue()
    } else {
      let callback = queuedCallbacks.removeFirst()
      
      callback(.ok, buffer)
    }
  }
  
  private func _send(cid: UInt32, cmd: UInt8, payload: Data) {
    var len = payload.count
    var offset = 0
    var packet = Data(count: packetSize)
    var seq : UInt8 = 0
    
    repeat {
      var packetStart : Int
      
      packet[0] = UInt8((cid >> 24) & 0xff)
      packet[1] = UInt8((cid >> 16) & 0xff)
      packet[2] = UInt8((cid >> 8) & 0xff)
      packet[3] = UInt8(cid & 0xff)
      if offset == 0 {
        packet[4] = cmd
        packet[5] = UInt8((payload.count >> 8) & 0xff)
        packet[6] = UInt8(payload.count & 0xff)
        packetStart = 7
      } else {
        packet[4] = seq
        seq += 1
        packetStart = 5
      }
      
      let space = packetSize - packetStart
      let todo = len > space ? space : len
      
      packet[packetStart..<packetStart+todo] = payload[offset..<offset+todo]

      for n in packetStart+todo..<packetSize {
        packet[n] = 0
      }
      
      packet.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> Void in
        IOHIDDeviceSetReport(_hidDevice, kIOHIDReportTypeOutput, 0,
                             ptr, packetSize)
      }
      
      len -= todo
      offset += todo
    } while len > 0
  }
  
  private func _processQueue() {
    while queuedMessages.count > 0 && state == .active {
      let message = queuedMessages.removeFirst()

      _send(cid: channel, cmd: u2f.hidMsg, payload: message)
    }
  }
  
  private func _activate() {
    if IOHIDDeviceOpen(_hidDevice, 0) != noErr {
      state = .failed(reason: "Unable to open device")
      packetSize = 0
      return
    }
    
    report.withUnsafeMutableBytes { (ptr) -> Void in
      IOHIDDeviceRegisterInputReportCallback(_hidDevice, ptr, maxInputSize,
      { (context, result, sender, type, reportID, report, reportLength) in
        let this = Unmanaged<U2FHIDTransport>.fromOpaque(context!).takeUnretainedValue()
        let reportData = Data(bytesNoCopy: report, count: reportLength,
                              deallocator: Data.Deallocator.none)
        this._recv(result: result, type: type, reportID: reportID, report: reportData)
      }, Unmanaged.passUnretained(self).toOpaque())
    }
    
    IOHIDDeviceRegisterRemovalCallback(_hidDevice, { (context, result, sender) in
      let this = Unmanaged<U2FHIDTransport>.fromOpaque(context!).takeUnretainedValue()
      this._deviceRemoved()
    }, Unmanaged.passUnretained(self).toOpaque())
    
    IOHIDDeviceScheduleWithRunLoop(_hidDevice,
                                   RunLoop.current.getCFRunLoop(),
                                   RunLoopMode.commonModes as CFString)

    command = 0
    expectedLength = 0
    expectedSequence = 0
    
    _send(cid: u2f.cidBroadcast, cmd: u2f.hidInit, payload: nonce)
    state = .initialising
  }
  
  func sendRecv(message: Data, callback: @escaping (_ status: U2FTransportStatus,
                                                    _ response: Data?) -> Void) {
    switch (state) {
    case .disconnected:
      callback(.disconnected, nil)
      return
    case let .failed(reason):
      callback(.failed(reason: reason), nil)
      return
    case .inactive:
      _activate()
      fallthrough
    default:
      queuedMessages.append(message)
      queuedCallbacks.append(callback)
      _processQueue()
    }
  }
  
  func close() {
    _close()
    state = .inactive
    queuedMessages = []
    for callback in queuedCallbacks {
      callback(.closed, nil)
    }
    queuedCallbacks = []
  }
}
