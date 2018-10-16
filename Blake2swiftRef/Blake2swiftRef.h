//
//  Blake2swiftRef.h
//  Blake2swiftRef
//
//  Created by pebble8888 on 2018/10/16.
//  Copyright 2018 pebble8888. All rights reserved.
//

/*
#import <Cocoa/Cocoa.h>

//! Project version number for Blake2swiftRef.
FOUNDATION_EXPORT double Blake2swiftRefVersionNumber;

//! Project version string for Blake2swiftRef.
FOUNDATION_EXPORT const unsigned char Blake2swiftRefVersionString[];
 */

// In this header, you should import all the public headers of your framework using statements like #import <Blake2swiftRef/PublicHeader.h>

#include <stdint.h>
#include <stddef.h>

// state context
typedef struct {
	uint8_t b[128];                     // input buffer
	uint64_t h[8];                      // chained state
	uint64_t t[2];                      // total number of bytes
	size_t c;                           // pointer for b[]
	size_t outlen;                      // digest size
} blake2b_ctx;

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).
int blake2b_init(blake2b_ctx *ctx, size_t outlen,
				 const void *key, size_t keylen);    // secret key

// Add "inlen" bytes from "in" into the hash.
void blake2b_update(blake2b_ctx *ctx,   // context
					const void *in, size_t inlen);      // data to be hashed

// Generate the message digest (size given in init).
//      Result placed in "out".
void blake2b_final(blake2b_ctx *ctx, void *out);

// All-in-one convenience function.
int blake2b(void *out, size_t outlen,   // return buffer for digest
			const void *key, size_t keylen,     // optional secret key
			const void *in, size_t inlen);      // data to be hashed
