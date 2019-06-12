//
//  Data+SHA256.swift
//  nteractClient
//
//  Created by Alastair Houghton on 09/10/2017.
//  Copyright © 2017 Alastair's Place. All rights reserved.
//

import Foundation

extension Data {
  func sha256() -> Data {
    var result = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    
    self.withUnsafeBytes { (input) -> Void in
      result.withUnsafeMutableBytes { (output) -> Void in
        CC_SHA256(input, CC_LONG(count), output)
      }
    }
    
    return result
  }
}
