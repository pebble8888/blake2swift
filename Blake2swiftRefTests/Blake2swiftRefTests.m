//
//  Blake2swiftRefTests.m
//  Blake2swiftRefTests
//
//  Created by pebble8888 on 2018/10/16.
//  Copyright © 2018年 pebble8888. All rights reserved.
//

#import <XCTest/XCTest.h>
@import Blake2swiftRef;

@interface Blake2swiftRefTests : XCTestCase

@end

@implementation Blake2swiftRefTests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

// no key blake2b hash for "abc"
- (void)testABC {
	uint8_t inbuf[3];
	inbuf[0] = 'a';
	inbuf[1] = 'b';
	inbuf[2] = 'c';
	uint8_t outbuf[64];
	int ret = blake2b(outbuf, 64, NULL, 0, inbuf, 3);
	XCTAssertEqual(ret, 0);
	
	uint8_t expected[64] = {
		0xBA, 0x80, 0xA5, 0x3F, 0x98, 0x1C, 0x4D, 0x0D, 0x6A, 0x27, 0x97, 0xB6, 0x9F, 0x12, 0xF6, 0xE9,
		0x4C, 0x21, 0x2F, 0x14, 0x68, 0x5A, 0xC4, 0xB7, 0x4B, 0x12, 0xBB, 0x6F, 0xDB, 0xFF, 0xA2, 0xD1,
		0x7D, 0x87, 0xC5, 0x39, 0x2A, 0xAB, 0x79, 0x2D, 0xC2, 0x52, 0xD5, 0xDE, 0x45, 0x33, 0xCC, 0x95,
		0x18, 0xD3, 0x8A, 0xA8, 0xDB, 0xF1, 0x92, 0x5A, 0xB9, 0x23, 0x86, 0xED, 0xD4, 0x00, 0x99, 0x23 };
    for (int i = 0; i < 64; ++i){
	    XCTAssertEqual(outbuf[i], expected[i]);
    }
}

// Deterministic sequences (Fibonacci generator).

static void selftest_seq(uint8_t *out, size_t len, uint32_t seed)
{
	size_t i;
	uint32_t t, a , b;
	a = 0xDEAD4BAD * seed;              // prime
	b = 1;
	for (i = 0; i < len; i++) {         // fill the buf
		t = a + b;
		a = b;
		b = t;
		out[i] = (t >> 24) & 0xFF;
	}
}

// BLAKE2b self-test validation. Return 0 when OK.
static int blake2b_selftest()
{
	// grand hash of hash results
	const uint8_t blake2b_res[32] = {
		0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD,
		0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29, 0xDA, 0x56,
		0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73,
		0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC, 0xD4, 0x75
	};
	// parameter sets
	const size_t b2b_md_len[4] = { 20, 32, 48, 64 };
	const size_t b2b_in_len[6] = { 0, 3, 128, 129, 255, 1024 };
	
	size_t i, j, outlen, inlen;
	uint8_t in[1024], md[64], key[64];
	blake2b_ctx ctx;
	
	// 256-bit hash for testing
	if (blake2b_init(&ctx, 32, NULL, 0))
		return -1;
	
	for (i = 0; i < 4; i++) {
		outlen = b2b_md_len[i];
		for (j = 0; j < 6; j++) {
			inlen = b2b_in_len[j];
			
			selftest_seq(in, inlen, (uint32_t)inlen);     // unkeyed hash
			blake2b(md, outlen, NULL, 0, in, inlen);
			blake2b_update(&ctx, md, outlen);   // hash the hash
			
			selftest_seq(key, outlen, (uint32_t)outlen);  // keyed hash
			blake2b(md, outlen, key, outlen, in, inlen);
			blake2b_update(&ctx, md, outlen);   // hash the hash
		}
	}
	
	// compute and compare the hash of hashes
	blake2b_final(&ctx, md);
	for (i = 0; i < 32; i++) {
		if (md[i] != blake2b_res[i])
			return -1;
	}
	return 0;
}


- (void)testSelfTest {
	int result = blake2b_selftest();
	XCTAssertEqual(result, 0);
}

@end
