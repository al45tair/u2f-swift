//
//  U2FManager.swift
//  nteractClient
//
//  Created by Alastair Houghton on 03/10/2017.
//  Copyright © 2017 Alastair's Place. All rights reserved.
//

import Foundation
import IOKit
import IOKit.hid

extension NSNotification.Name {
  static let U2FDeviceListDidChange = NSNotification.Name("U2FDeviceListDidChange")
}

enum U2FManagerState {
  case normal
  case registering
  case authenticating
}

enum U2FAuthenticateStatus {
  case noError
  case failed
}

struct U2FAuthResponse {
  var flags : U2FAuthResponseFlags
  var counter : UInt32
  var keyHandle : Data
  var signature : Data
  
  init(_ flags : U2FAuthResponseFlags, _ counter: UInt32,
       _ keyHandle: Data, _ signature: Data) {
    self.flags = flags
    self.counter = counter
    self.keyHandle = keyHandle
    self.signature = signature
  }
}

class U2FManager {
  private var hidManager : IOHIDManager?
  private var _u2fDevices : [U2FDevice] = []
  private var state : U2FManagerState = .normal
  private var challenge : Any?
  private var challengeJSON : Data?
  private var challengeHash : Data?
  private var transaction : UInt32 = 0
  private var registerCallback : ((U2FDevice, Data, Data, Data, SecCertificate, Data) -> Void)?
  private var authCallback : ((U2FAuthenticateStatus, Data, [U2FAuthResponse]) -> Void)?
  private var keyHandles : [Data] = []
  private var authResponses : [U2FAuthResponse] = []
  private var authRepliesRemaining : Int = 0
  private var authRepliesFailed : Int = 0
  
  var u2fDevices : [U2FDevice] {
    return _u2fDevices
  }
  var appID : String

  init(appID: String) {
    self.appID = appID
    hidManager = IOHIDManagerCreate(kCFAllocatorDefault, 0)
    if hidManager != nil {
      let matchingDict = [ kIOHIDPrimaryUsagePageKey: fido.usagePage,
                           kIOHIDPrimaryUsageKey: fido.usageU2FHID ] as CFDictionary
      IOHIDManagerSetDeviceMatching(hidManager!, matchingDict)
      IOHIDManagerRegisterDeviceMatchingCallback(hidManager!,
      { (context, result, sender, device) in
        let manager = Unmanaged<U2FManager>.fromOpaque(context!).takeUnretainedValue()
        manager.u2fDeviceConnected(device)
      }, Unmanaged.passUnretained(self).toOpaque())
      IOHIDManagerRegisterDeviceRemovalCallback(hidManager!,
      { (context, result, sender, device) in
        let manager = Unmanaged<U2FManager>.fromOpaque(context!).takeUnretainedValue()
        manager.u2fDeviceDisconnected(device)
      }, Unmanaged.passUnretained(self).toOpaque())
      IOHIDManagerScheduleWithRunLoop(hidManager!, CFRunLoopGetCurrent(),
                                      CFRunLoopMode.defaultMode.rawValue)
      IOHIDManagerOpen(hidManager!, 0)
    }
    
/*  let newdev = U2FDevice(name: "My Fake Device", transport: U2FFakeTransport())
    
    _u2fDevices.append(newdev) */
  }
  
  deinit {
    if hidManager != nil {
      IOHIDManagerClose(hidManager!, 0)
    }
  }
  
  private func doRegister(_ device: U2FDevice) {
    let tid = transaction
    device.register(appId: appID, challenge: challengeHash!,
                    requestUserPresence: true) {
      (status, publicKey, keyHandle, attestationCert, signature) in
      // Ignore late responses after the transaction is complete
      if tid != self.transaction {
        return
      }
                      
      // Ignore anything other than success
      switch (status) {
      case .noError:
        self.transaction = self.transaction &+ 1
        self.state = .normal
        
        self.registerCallback!(device, self.challengeJSON!,
                               publicKey!, keyHandle!,
                               attestationCert!, signature!)
      default:
        break
      }
    }
  }
  
  private func doAuthenticate(_ device: U2FDevice) {
    let tid = transaction
    authRepliesRemaining += keyHandles.count
    for keyHandle in keyHandles {
      device.authenticate(mode: .enforceUserPresenceAndSign,
                          appId: appID,
                          challenge: challengeHash!,
                          keyHandle: keyHandle) {
        (status, flags, counter, signature) in
        // Ignore late responses after the transaction is complete
        if tid != self.transaction {
          return
        }
        
        switch (status) {
        case .noError:
          let response = U2FAuthResponse(flags, counter, keyHandle,
                                         signature!)
          
          self.authResponses.append(response)
          
          self.authRepliesRemaining -= 1
        default:
          self.authRepliesFailed += 1
          self.authRepliesRemaining -= 1
        }
                            
        if self.authRepliesRemaining == 0 {
          self.transaction = self.transaction &+ 1
          self.state = .normal
          
          var status : U2FAuthenticateStatus = .noError
          
          if self.authRepliesFailed != 0 && self.authResponses.count == 0 {
            status = .failed
          }
          
          self.authCallback!(status, self.challengeJSON!, self.authResponses)
        }
      }
    }
  }
  
  private func u2fDeviceConnected(_ device: IOHIDDevice) {
    let name = IOHIDDeviceGetProperty(device,
                                      kIOHIDProductKey as CFString) as! String
    let transport = U2FHIDTransport(device: device)
    let u2fdev = U2FDevice(name: name, transport: transport)
    
    _u2fDevices.append(u2fdev)

    switch (state) {
    case .normal:
      break
    case .authenticating:
      doAuthenticate(u2fdev)
    case .registering:
      doRegister(u2fdev)
    }
    
    NotificationCenter.default.post(name: NSNotification.Name.U2FDeviceListDidChange,
                                    object: self,
                                    userInfo: ["connected": u2fdev])
  }
  
  private func u2fDeviceDisconnected(_ device: IOHIDDevice) {
    var ndx : Int?
    for (n, dev) in _u2fDevices.enumerated() {
      if let transport = dev.transport as? U2FHIDTransport {
        if transport.hidDevice === device {
          ndx = n
          break
        }
      }
    }
    
    if let ndx = ndx {
      let u2fdev = _u2fDevices[ndx]
      _u2fDevices.remove(at: ndx)
      NotificationCenter.default.post(name: NSNotification.Name.U2FDeviceListDidChange,
                                      object: self,
                                      userInfo: ["disconnected": u2fdev])
    }
  }
  
  func register(challenge: [String:Any],
                callback: @escaping (_ device: U2FDevice,
                                     _ challenge: Data,
                                     _ publicKey: Data, _ keyHandle: Data,
                                     _ attestationCertificate: SecCertificate,
                                     _ signature: Data) -> Void) {
    assert(state == .normal)
    
    self.state = .registering
    self.challenge = challenge
    self.challengeJSON = try! JSONSerialization.data(withJSONObject: challenge)
    self.challengeHash = self.challengeJSON!.sha256()
    
    self.registerCallback = callback
    
    for device in _u2fDevices {
      doRegister(device)
    }
  }
  
  func authenticate(challenge: [String:Any],
                    keyHandles: [Data],
                    callback: @escaping (_ status: U2FAuthenticateStatus,
                                         _ challenge: Data,
                                         _ responses: [U2FAuthResponse]) -> Void) {
    assert(state == .normal)
    
    self.state = .authenticating
    self.keyHandles = keyHandles
    self.challenge = challenge
    self.challengeJSON = try! JSONSerialization.data(withJSONObject: challenge)
    self.challengeHash = self.challengeJSON!.sha256()
    self.authCallback = callback
    self.authResponses = []
    self.authRepliesRemaining = 0
    self.authRepliesFailed = 0
    
    for device in _u2fDevices {
      doAuthenticate(device)
    }
  }
  
  func cancel() {
    if state != .normal {
      state = .normal
      transaction = transaction &+ 1

      for device in _u2fDevices {
        device.close()
      }
    }
  }
}
