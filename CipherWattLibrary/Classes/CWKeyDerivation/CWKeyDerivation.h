//
//  CWKeyDerivation.h
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

#import "CWCipherWattObject.h"

typedef NS_ENUM(NSUInteger, CWPBKDF2PseudoRandomAlgorithm) {
    CWPBKDF2PseudoRandomAlgorithmHMACSHA1,
    CWPBKDF2PseudoRandomAlgorithmHMACSHA224,
    CWPBKDF2PseudoRandomAlgorithmHMACSHA256,
    CWPBKDF2PseudoRandomAlgorithmHMACSHA384,
    CWPBKDF2PseudoRandomAlgorithmHMACSHA512
};

/** Default number of KDF rounds (20,000). */
FOUNDATION_EXTERN const NSUInteger kCWKeyDerivationDefaultNumberOfRounds;
/**
 Default salt length is 64 bits (or 8 bytes) as stated in https://tools.ietf.org/html/rfc2898#page-6
 
 "It should be at least eight octets (64 bits) long."
 */
FOUNDATION_EXTERN const NSUInteger kCWKeyDerivationDefaultSaltSize;

// TODO: Secure randomness is available only from  NS_AVAILABLE(10_10, 8_0). This means no salt/IV generation. Think what to do with it.

/**
 Class which is responsible for password-based key derivation. It uses PBKDF2 under the hood. PBKDF2 is a part of PKCS5 v2.0 (RFC 2898) standard.
 */
@interface CWKeyDerivation : CWCipherWattObject

/** The Pseudo Random Algorithm to use for the derivation iterations. Default is `CWPBKDF2PseudoRandomAlgorithmHMACSHA1`. */
@property (readwrite, assign, nonatomic) CWPBKDF2PseudoRandomAlgorithm PBKDF2PseudoRandomAlgorithm;

/**
 The salt data used as input to the derivation function. The standard recommends a salt length of at least 64 bits (8 bytes).
 
 @discussion
 
 If this property is empty a random salt `kCWKeyDerivationDefaultSaltSize` bytes long will be generated and stored into this property after derivation process. You then save this value along with encrypted data and use it later for decryption.
 */
@property (readwrite, strong, nonatomic) NSData *PBKDF2Salt;

/** The number of rounds of the Pseudo Random Algorithm to use. Default is `kCWKeyDerivationDefaultNumberOfRounds`. */
@property (readwrite, assign, nonatomic) NSUInteger PBKDF2NumberOfRounds;

/**
 Derive a key from a text password / passphrase.
 @discussion The key derivation process is performed using the combination of `PBKDF2PseudoRandomAlgorithm`, `PBKDF2Salt`, `PBKDF2NumberOfRounds`.
 
 Use exactly the same parameters if you want to have same key data as output.
 
 @attention If `PBKDF2Salt` property is empty a random salt will be generated and stored into this property after derivation process.
 
 @param password The text password used as input to the derivation function.
 @param keySize Expected key size in bytes. If 0 nil is returned.
 @param error Upon completion contains error object if any error occured. Can be nil.
 
 @return Data representation of derived key or nil if any error has occured or `keySize` parameter is 0.
 */
- (NSData *)deriveKeyDataFromPassword:(NSString *)password keySize:(NSUInteger)keySize error:(NSError **)error;

/**
 Copies all parameters from provided key derivation object.
 @param keyDerivation Key derivation object to copy parameters from. If `nil` returns immediately without copying.
 */
- (void)copyParametersFromKeyDerivation:(CWKeyDerivation *)keyDerivation;

@end
