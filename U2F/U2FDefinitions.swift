//
//  U2FDefinitions.swift
//  nteractClient
//
//  Created by Alastair Houghton on 04/10/2017.
//  Copyright © 2017 Alastair's Place. All rights reserved.
//

enum fido {
  static let usagePage    : UInt16 = 0xf1d0
  static let usageU2FHID  : UInt8  = 0x01
  static let usageDataIn  : UInt8  = 0x20
  static let usageDataOut : UInt8  = 0x21
}

enum u2f {
  static let typeMask : UInt8 = 0x80
  static let typeInit : UInt8 = 0x80
  static let typeCont : UInt8 = 0x00

  static let hidIFVersion = 2
  static let hidFrameTimeout = 500
  static let hidTransTimeout = 3000

  static let hidPing  : UInt8 = typeInit | 0x01
  static let hidMsg   : UInt8 = typeInit | 0x03
  static let hidLock  : UInt8 = typeInit | 0x04
  static let hidInit  : UInt8 = typeInit | 0x06
  static let hidWink  : UInt8 = typeInit | 0x08
  static let hidError : UInt8 = typeInit | 0x3f

  static let hidVendorFirst = typeInit | 0x40
  static let hidVendorLast = typeInit | 0x7f

  static let cidReserved = UInt32(0)
  static let cidBroadcast = UInt32(0xffffffff)
  
  static let initNonceSize = 8
  
  static let capFlagWink : UInt8 = 0x01
  static let capFlagLock : UInt8 = 0x02
  
  static let errNone         : UInt8 = 0x00
  static let errInvalidCmd   : UInt8 = 0x01
  static let errInvalidPar   : UInt8 = 0x02
  static let errInvalidLen   : UInt8 = 0x03
  static let errInvalidSeq   : UInt8 = 0x04
  static let errMsgTimeout   : UInt8 = 0x05
  static let errChannelBusy  : UInt8 = 0x06
  static let errLockRequired : UInt8 = 0x0a
  static let errInvalidCid   : UInt8 = 0x0b
  static let errOther        : UInt8 = 0x7f
  
  static let cmdRegister     : UInt8 = 0x01
  static let cmdAuthenticate : UInt8 = 0x02
  static let cmdVersion      : UInt8 = 0x03
  static let cmdVendorFirst  : UInt8 = 0x40
  static let cmdVendorLast   : UInt8 = 0xbf
  
  static let swNoError                 : UInt16 = 0x9000
  static let swConditionsNotSatisfied  : UInt16 = 0x6985
  static let swWrongData               : UInt16 = 0x6a80
  static let swWrongLength             : UInt16 = 0x6700
  static let swClassNotSupported       : UInt16 = 0x6e00
  static let swInstructionNotSupported : UInt16 = 0x6d00
}
