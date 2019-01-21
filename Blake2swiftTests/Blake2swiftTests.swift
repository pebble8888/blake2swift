//
//  Blake2swiftTests.swift
//  Blake2swiftTests
//
//  Created by pebble8888 on 2018/10/14.
//  Copyright © 2018年 pebble8888. All rights reserved.
//

import XCTest
@testable import Blake2swift

class Blake2swiftTests: XCTestCase {

    override func setUp() {
    }

    override func tearDown() {
    }

	// no key blake2b hash for "abc"
	func test0() {
		let calc = Blake2b.hash(data: [0x61, 0x62, 0x63])
		print("\(calc.hexDescription())")
		let expected:[UInt8] = [
			0xBA, 0x80, 0xA5, 0x3F, 0x98, 0x1C, 0x4D, 0x0D, 0x6A, 0x27, 0x97, 0xB6, 0x9F, 0x12, 0xF6, 0xE9,
			0x4C, 0x21, 0x2F, 0x14, 0x68, 0x5A, 0xC4, 0xB7, 0x4B, 0x12, 0xBB, 0x6F, 0xDB, 0xFF, 0xA2, 0xD1,
			0x7D, 0x87, 0xC5, 0x39, 0x2A, 0xAB, 0x79, 0x2D, 0xC2, 0x52, 0xD5, 0xDE, 0x45, 0x33, 0xCC, 0x95,
			0x18, 0xD3, 0x8A, 0xA8, 0xDB, 0xF1, 0x92, 0x5A, 0xB9, 0x23, 0x86, 0xED, 0xD4, 0x00, 0x99, 0x23
		]
		XCTAssertEqual(calc.count, 64)
		for i in 0..<64 {
			XCTAssertEqual(calc[i], expected[i])
		}
	}
	
	// Deterministic sequences (Fibonacci generator).
	
	static func selftest_seq(_ len: UInt32, _ seed: UInt32) -> [UInt8]
    {
		var out = [UInt8](repeating: 0, count: Int(len))
		var t: UInt32
		var a: UInt32
		var b: UInt32
     	a = 0xDEAD4BAD &* seed              // prime
    	b = 1
		// fill the buf
    	for i in 0..<Int(len) {
        	t = a &+ b
        	a = b
        	b = t
        	out[i] = UInt8((t >> 24) & 0xFF)
    	}
		return out
	}
	
	// BLAKE2b self-test validation. Return true when OK.
	func blake2b_selftest() -> Bool
	{
    	// grand hash of hash results
		let blake2b_res: [UInt8] = [
        	0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD,
        	0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29, 0xDA, 0x56,
        	0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73,
        	0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC, 0xD4, 0x75
    	]
    	// parameter sets
		let b2b_md_len: [UInt32] = [ 20, 32, 48, 64 ] // outer 4 loop 
		let b2b_in_len: [UInt32] = [ 0, 3, 128, 129, 255, 1024 ] // inner 6 loop 
	
		var outlen: UInt32
		var inlen: UInt32
		var md: [UInt8] = [UInt8](repeating: 0, count: 64)
		var ctx = Blake2b.blake2b_ctx()
    	// 256-bit hash for testing
		if !Blake2b.blake2b_init(&ctx, 32, [], 0) {
        	return false
		}
		for i in 0..<4 {
        	outlen = b2b_md_len[i]
			for j in 0..<6 {
            	inlen = b2b_in_len[j]
	
				// unkeyed hash
				let in0 = Blake2swiftTests.selftest_seq(inlen, inlen)
				_ = Blake2b.blake2b(&md, UInt64(outlen), [], 0, in0, UInt64(inlen));
				// hash the hash
				Blake2b.blake2b_update(&ctx, md, UInt64(outlen));

				// keyed hash
				let key = Blake2swiftTests.selftest_seq(outlen, outlen)
				_ = Blake2b.blake2b(&md, UInt64(outlen), key, UInt64(outlen), in0, UInt64(inlen))
				Blake2b.blake2b_update(&ctx, md, UInt64(outlen));   // hash the hash
        	}
    	}
	
    	// compute and compare the hash of hashes
    	Blake2b.blake2b_final(&ctx, &md)
		for i in 0..<32 {
			if md[i] != blake2b_res[i] {
            	return false
			}
    	}
    	return true
	}
	
	func testSelfTest() {
    	let result = blake2b_selftest()
    	XCTAssertEqual(result, true)
	}
}
