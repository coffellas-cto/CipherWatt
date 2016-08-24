//
//  CWHMAC.m
//
//  Copyright © 2016 A. Gordiyenko. All rights reserved.
//

/*
 The MIT License (MIT)
 
 Copyright (c) 2016 A. Gordiyenko
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */

#import "CWHMAC.h"
#import "CWCipherWattObject_Private.h"
#import "CWSecureRandomness.h"
#import <CommonCrypto/CommonHMAC.h>

@implementation CWHMAC

#pragma mark - Public Methods

- (NSData *)computeMACForData:(NSData *)data keyData:(NSData *)keyData error:(NSError **)error {
    if (error) {
        *error = nil;
    }
    
    size_t mac_size = [self MACSize];
    uint8_t *macOut = malloc(mac_size);
    if (macOut == NULL) {
        [self setError:error withCode:CWCipherWattErrorNoMemory];
        return nil;
    }
    
    memset(macOut, 0, mac_size);
    
    CCHmac(
           [self CCHmacAlgorithm],  /* kCCHmacSHA1, kCCHmacMD5 */
           keyData.bytes,
           keyData.length,
           data.bytes,
           data.length,
           macOut);
    
    NSData *retVal = [NSData dataWithBytesNoCopy:macOut length:mac_size freeWhenDone:YES];
    return retVal;
}

- (BOOL)verifyMACForData:(NSData *)data keyData:(NSData *)keyData MACToVerify:(NSData *)MACToVerify {
    /*
     Here "timing attack defence #2" from Dan Boneh Cryptography I course is used.
     Google "double hmac".
     First we compute normal MAC, but then we compare MACs of candidate and original MAC.
     So adversary doesn't know which strings are compared. The comparison of not equal MAC(MAC(msg))
     will drop at random points revealing nothing to adversary, so no timing attack is possible.
     Moreover we change key for second MAC iteration assuming our PRNG is good. If it's no good, well,
     the whole idea using CommonCrypto as a backbone is bad then :).
     */
    
    NSData *MAC = [self computeMACForData:data keyData:keyData error:nil];
    
    NSData *randomKey = [CWSecureRandomness secureRandomDataWithSize:keyData.length error:nil];
    if (randomKey == nil) {
        // Fallback to original key if something (very unlikely) goes wrong
        randomKey = keyData;
    }
    
    NSData *MACOfMAC = [self computeMACForData:MAC keyData:randomKey error:nil];
    NSData *MACOfCandidateMAC = [self computeMACForData:MACToVerify keyData:randomKey error:nil];
    
    return [MACOfMAC isEqualToData:MACOfCandidateMAC];
}

#pragma mark - Private Methods

- (size_t)MACSize {
    switch (self.algorithm) {
        case CWHMACAlgorithmSHA1:
            return CC_SHA1_DIGEST_LENGTH;
        case CWHMACAlgorithmSHA224:
            return CC_SHA224_DIGEST_LENGTH;
        case CWHMACAlgorithmSHA256:
            return CC_SHA256_DIGEST_LENGTH;
        case CWHMACAlgorithmSHA384:
            return CC_SHA384_DIGEST_LENGTH;
        case CWHMACAlgorithmSHA512:
            return CC_SHA512_DIGEST_LENGTH;
            
        default: // MD5
            return CC_MD5_DIGEST_LENGTH;
    }
}

- (CCHmacAlgorithm)CCHmacAlgorithm {
    switch (self.algorithm) {
        case CWHMACAlgorithmSHA1:
            return kCCHmacAlgSHA1;
        case CWHMACAlgorithmSHA224:
            return kCCHmacAlgSHA224;
        case CWHMACAlgorithmSHA256:
            return kCCHmacAlgSHA256;
        case CWHMACAlgorithmSHA384:
            return kCCHmacAlgSHA384;
        case CWHMACAlgorithmSHA512:
            return kCCHmacAlgSHA512;
            
        default: // MD5
            return kCCHmacAlgMD5;
    }
}

#pragma mark - Life Cycle

- (instancetype)initWithAlgorithm:(CWHMACAlgorithm)algorithm {
    self = [super init];
    if (self) {
        _algorithm = algorithm;
    }
    return self;
}

- (instancetype)init {
    return [self initWithAlgorithm:CWHMACAlgorithmSHA224];
}

@end
