//
//  Blake2bUtility.swift
//  Blake2swift
//
//  Created by pebble8888 on 2018/10/14.
//  Copyright © 2018年 pebble8888. All rights reserved.
//

import Foundation
import CommonCrypto

extension String {
	public func unhexlify() -> [UInt8] {
		var pos = startIndex
		return (0..<count/2).compactMap { _ in
			defer { pos = index(pos, offsetBy: 2) }
			return UInt8(self[pos...index(after: pos)], radix: 16)
		}
	}
}

extension Collection where Iterator.Element == UInt8 {
	public func hexDescription() -> String {
		return self.map({ String(format: "%02x", $0) }).joined()
	}
}
