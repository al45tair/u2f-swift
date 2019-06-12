//
//  U2FDevice.swift
//  nteractClient
//
//  Created by Alastair Houghton on 09/10/2017.
//  Copyright © 2017 Alastair's Place. All rights reserved.
//

import Foundation

enum U2FStatus {
  case noError
  case userPresenceRequired
  case invalidKeyHandle
  case invalidLength
  case classNotSupported
  case instructionNotSupported
  case disconnected
  case transportFailed
  case badResponse
  case other(UInt16)
  
  static func == (lhs: U2FStatus, rhs: U2FStatus) -> Bool {
    switch (lhs, rhs) {
    case (.noError, .noError),
         (.userPresenceRequired, .userPresenceRequired),
         (.invalidKeyHandle, .invalidKeyHandle),
         (.invalidLength, .invalidLength),
         (.classNotSupported, .classNotSupported),
         (.instructionNotSupported, .instructionNotSupported),
         (.disconnected, .disconnected),
         (.badResponse, .badResponse):
      return true
    case let (.other(x), .other(y)):
      return x == y
    default:
      return false
    }
  }
}

enum U2FTransportStatus {
  case ok
  case disconnected
  case failed(reason: String)
  case closed
}

enum U2FAuthenticateMode {
  case checkOnly
  case enforceUserPresenceAndSign
  case dontEnforceUserPresenceAndSign
}

struct U2FAuthResponseFlags : OptionSet {
  let rawValue : UInt8
  static let userPresent = U2FAuthResponseFlags(rawValue: 1)
}

protocol U2FTransport {
  var usesShortEncoding : Bool { get }
  func sendRecv(message: Data,
                callback: @escaping (_ status: U2FTransportStatus,
                                     _ response: Data?) -> Void)
  func close()
}

fileprivate func mapStatus(_ status: UInt16) -> U2FStatus {
  switch (status) {
  case u2f.swNoError:
    return .noError
  case u2f.swConditionsNotSatisfied:
    return .userPresenceRequired
  case u2f.swWrongData:
    return .invalidKeyHandle
  case u2f.swWrongLength:
    return .invalidLength
  case u2f.swClassNotSupported:
    return .classNotSupported
  case u2f.swInstructionNotSupported:
    return .instructionNotSupported
  default:
    return .other(status)
  }
}

fileprivate class U2FRegistrationOperation {
  let maxTries = 15
  var tries : Int
  var message : Data
  var requestUserPresence : Bool
  var callback : (U2FStatus, Data?, Data?, SecCertificate?, Data?) -> Void
  var transport : U2FTransport
  
  init(transport t: U2FTransport,
       message msg: Data, requestUserPresence rup: Bool,
       callback cb: @escaping (_ status: U2FStatus,
                               _ publicKey: Data?,
                               _ keyHandle: Data?,
                               _ attestationCertificate: SecCertificate?,
                               _ signature: Data?) -> Void) {
    tries = 0
    transport = t
    message = msg
    requestUserPresence = rup
    callback = cb
  }
  
  func processResponse(status: U2FTransportStatus,
                       response: Data?) {
    switch (status) {
    case .disconnected:
      callback(.disconnected, nil, nil, nil, nil)
      return
    case .failed(_):
      callback(.transportFailed, nil, nil, nil, nil)
      return
    default:
      break
    }
    
    guard let data = response else {
      callback(.badResponse, nil, nil, nil, nil)
      return
    }
    
    if data.count == 2 {
      let sw2 = data[data.endIndex - 1]
      let sw1 = data[data.endIndex - 2]
      let respStatus = (UInt16(sw1) << 8) | UInt16(sw2)
      
      if (requestUserPresence && respStatus == u2f.swConditionsNotSatisfied
        && tries < maxTries) {
        tries += 1
        let when = DispatchTime.now() + 1
        DispatchQueue.main.asyncAfter(deadline: when) {
          self.transport.sendRecv(message: self.message) { status, response in
            self.processResponse(status: status, response: response)
          }
        }
        return
      }
      
      callback(mapStatus(respStatus), nil, nil, nil, nil)
      return
    }
    
    if data.count < 1 + 65 + 1 + 71 {
      callback(.badResponse, nil, nil, nil, nil)
      return
    }
    
    let base = data.startIndex
    
    if data[base] != 0x05 {
      callback(.badResponse, nil, nil, nil, nil)
      return
    }
    
    let sw2 = data[data.endIndex - 1]
    let sw1 = data[data.endIndex - 2]
    let respStatus = (UInt16(sw1) << 8) | UInt16(sw2)
    let publicKey = data[base + 1 ..< base + 66]
    let khLen = Int(data[base + 66])
    let keyHandle = data[base + 67 ..< base + 67 + khLen]
    
    // Find the extent of the certificate
    let certStart = base + 67 + khLen
    
    // The certificate starts with a SEQUENCE tag
    if data[certStart] != 0x30 {
      callback(.badResponse, nil, nil, nil, nil)
    }
    
    var certLen = Int(data[certStart + 1])
    var certLenExtraLen = 0
    
    if certLen > 0x7f {
      if certLen < 0x81 || certLen > 0x84 {
        callback(.badResponse, nil, nil, nil, nil)
        return
      }
      
      certLenExtraLen = certLen & 0x7f
      certLen = 0
      
      for n in 0..<certLenExtraLen {
        let ndx = certStart + 2 + n
        certLen = (certLen << 8) | Int(data[ndx])
      }
    }
    
    let certEnd = certStart + 2 + certLenExtraLen + certLen
    
    if certLen < 0 || certEnd > data.endIndex - 2 {
      callback(.badResponse, nil, nil, nil, nil)
      return
    }
    
    let certData = data[certStart ..< certEnd]
    guard let certificate = SecCertificateCreateWithData(kCFAllocatorDefault,
                                                         certData as CFData) else {
      callback(.badResponse, nil, nil, nil, nil)
      return
    }
    
    let signature = data[certEnd ..< data.endIndex - 2]
    
    if signature.count < 70 || signature.count > 73 {
      callback(.badResponse, nil, nil, nil, nil)
      return
    }
    
    callback(mapStatus(respStatus), publicKey, keyHandle, certificate, signature)
  }
}

fileprivate class U2FAuthenticateOperation {
  let maxTries = 15
  var tries : Int
  var message : Data
  var transport : U2FTransport
  var mode : U2FAuthenticateMode
  var callback: (_ status: U2FStatus,
                 _ flags: U2FAuthResponseFlags,
                 _ counter: UInt32,
                 _ signature: Data?) -> Void
  
  
  init(transport t: U2FTransport,
       message msg: Data,
       mode m: U2FAuthenticateMode,
       callback cb: @escaping (_ status: U2FStatus,
                               _ flags: U2FAuthResponseFlags,
                               _ counter: UInt32,
                               _ signature: Data?) -> Void) {
    tries = 0
    transport = t
    message = msg
    mode = m
    callback = cb
  }
  
  func processResponse(status: U2FTransportStatus,
                       response: Data?) {
    switch (status) {
    case .disconnected:
      callback(.disconnected, [], 0, nil)
      return
    case .failed(_):
      callback(.transportFailed, [], 0, nil)
      return
    default:
      break
    }
    
    guard let data = response else {
      callback(.badResponse, [], 0, nil)
      return
    }
    
    if data.count == 2 {
      let sw2 = data[data.endIndex - 1]
      let sw1 = data[data.endIndex - 2]
      let respStatus = (UInt16(sw1) << 8) | UInt16(sw2)

      if (mode == .enforceUserPresenceAndSign
          && respStatus == u2f.swConditionsNotSatisfied
          && tries < maxTries) {
        tries += 1
        let when = DispatchTime.now() + 1
        DispatchQueue.main.asyncAfter(deadline: when) {
          self.transport.sendRecv(message: self.message) { status, response in
            self.processResponse(status: status, response: response)
          }
        }
        return
      }
      
      callback(mapStatus(respStatus), [], 0, nil)
      return
    }
    
    if data.count < 1 + 4 + 71 {
      callback(.badResponse, [], 0, nil)
      return
    }
    
    let sw2 = data[data.endIndex - 1]
    let sw1 = data[data.endIndex - 2]
    let respStatus = (UInt16(sw1) << 8) | UInt16(sw2)

    let flags = U2FAuthResponseFlags(rawValue: data[data.startIndex])
    var counter : UInt32
    
    counter = UInt32(data[data.startIndex + 1]) << 24
    counter |= UInt32(data[data.startIndex + 2]) << 16
    counter |= UInt32(data[data.startIndex + 3]) << 8
    counter |= UInt32(data[data.startIndex + 4])

    let signature = data[data.startIndex + 5 ..< data.endIndex - 2]
    
    if signature.count < 70 || signature.count > 73 {
      callback(.badResponse, [], 0, nil)
      return
    }
    
    callback(mapStatus(respStatus), flags, counter, signature)
  }
}

@objc class U2FDevice : NSObject {

  private var _name : String
  var name : String { return _name }
  
  private var _transport : U2FTransport
  var transport : U2FTransport { return _transport }
  
  init(name n: String, transport tp: U2FTransport) {
    _name = n
    _transport = tp
  }
  
  override var description : String {
    return name
  }
  
  override var debugDescription : String {
    return "<U2FDevice \(name)>"
  }
  
  func close() {
    transport.close()
  }
  
  func register(appId: String, challenge: Data,
                requestUserPresence: Bool,
                callback: @escaping (_ status: U2FStatus,
                                     _ publicKey: Data?,
                                     _ keyHandle: Data?,
                                     _ attestationCertificate: SecCertificate?,
                                     _ signature: Data?) -> Void) {
    var message = Data()
    let p1: UInt8 = requestUserPresence ? 3 : 0
    
    message.append(contentsOf: [0, u2f.cmdRegister, p1, 0])
    
    if _transport.usesShortEncoding {
      message.append(64)
    } else {
      message.append(contentsOf: [0, 0, 64])
    }
    
    assert(challenge.count == 32, "Challenge must be 32 bytes")
    message.append(challenge)
    
    let appIdUTF8 = appId.data(using: String.Encoding.utf8)!
    message.append(appIdUTF8.sha256())

    // Max length of expected data (0 means 65536)
    if _transport.usesShortEncoding {
      message.append(0)
    } else {
      message.append(contentsOf: [0, 0])
    }
    
    let op = U2FRegistrationOperation(transport: _transport,
                                      message: message,
                                      requestUserPresence: requestUserPresence,
                                      callback: callback)
    
    _transport.sendRecv(message: message) { (status, response) in
      op.processResponse(status: status, response: response)
    }
  }

  func authenticate(mode: U2FAuthenticateMode,
                    appId: String, challenge: Data, keyHandle: Data,
                    callback: @escaping (_ status: U2FStatus,
                                         _ flags: U2FAuthResponseFlags,
                                         _ counter: UInt32,
                                         _ signature: Data?) -> Void) {
    var p1 : UInt8
    
    switch (mode) {
    case .checkOnly:
      p1 = UInt8(0x07)
      break
    case .enforceUserPresenceAndSign:
      p1 = UInt8(0x03)
      break
    case .dontEnforceUserPresenceAndSign:
      p1 = UInt8(0x08)
      break
    }
    
    var message = Data(bytes: [ 0, u2f.cmdAuthenticate, p1, 0 ])
    let payloadLen = 65 + keyHandle.count
    
    if _transport.usesShortEncoding {
      assert(payloadLen <= 255, "In short encoding mode, the maximum payload is 255 bytes")
      
      message.append(UInt8(payloadLen))
    } else {
      assert(payloadLen <= 65535, "Maximum payload is 65535 bytes")
      
      message.append(contentsOf: [0,
                                  UInt8((payloadLen >> 8) & 0xff),
                                  UInt8(payloadLen & 0xff)])
    }
    
    assert(challenge.count == 32, "Challenge must be 32 bytes")
    message.append(challenge)
    
    let appIdUTF8 = appId.data(using: String.Encoding.utf8)!
    message.append(appIdUTF8.sha256())
    
    assert(keyHandle.count <= 255, "Key handle too long")
    
    message.append(UInt8(keyHandle.count))
    message.append(keyHandle)
    
    // Max length of expected data (0 means 65536)
    if _transport.usesShortEncoding {
      message.append(0)
    } else {
      message.append(contentsOf: [ 0, 0 ])
    }
    
    let op = U2FAuthenticateOperation(transport: _transport,
                                      message: message,
                                      mode: mode,
                                      callback: callback)
    
    _transport.sendRecv(message: message) { (status, response) in
      op.processResponse(status: status, response: response)
    }
  }
  
  func version(callback: @escaping (_ status: U2FStatus, _ version: String?) -> Void) {
    var message : Data!
    if _transport.usesShortEncoding {
      message = Data(bytes: [0, u2f.cmdVersion, 0, 0, 0])
    } else {
      message = Data(bytes: [0, u2f.cmdVersion, 0, 0, 0, 0, 0])
    }
    
    _transport.sendRecv(message: message) { (status: U2FTransportStatus,
                                             response: Data?) in
      switch (status) {
      case .disconnected:
        callback(.disconnected, "Device disconnected")
        return
      case let .failed(reason):
        callback(.transportFailed, reason)
        return
      default:
        break
      }
      
      guard let data = response else {
        callback(.badResponse, "Nil response")
        return
      }
      
      if data.count < 2 {
        callback(.badResponse, "Bad response from U2F device")
        return
      }
      
      let sw2 = data[data.endIndex - 1]
      let sw1 = data[data.endIndex - 2]
      let status = (UInt16(sw1) << 8) | UInt16(sw2)
      
      if status != u2f.swNoError {
        callback(mapStatus(status), nil)
      } else {
        let range = data.startIndex..<(data.endIndex - 2)
        let versionData = data[range]
        let version = String(data: versionData, encoding: String.Encoding.utf8)
        callback(mapStatus(status), version)
      }
    }
  }
  
}
