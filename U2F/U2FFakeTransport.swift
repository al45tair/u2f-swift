//
//  U2FFakeTransport.swift
//  nteractClient
//
//  Created by Alastair Houghton on 26/10/2017.
//  Copyright © 2017 Alastair's Place. All rights reserved.
//

import Foundation

class U2FFakeTransport : U2FTransport {
  var usesShortEncoding : Bool { return true }
  func sendRecv(message: Data,
                callback: @escaping (_ status: U2FTransportStatus,
    _ response: Data?) -> Void) {
    callback(U2FTransportStatus.failed(reason: "Not a real device"), nil)
  }
  func close() {
  }
}
