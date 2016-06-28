//
//  CWKeyDerivation.m
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

#import "CWKeyDerivation.h"
#import "CWSecureRandomness.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import "NSError+CipherWatt.h"
#import "CWCipherWattObject_Private.h"

const NSUInteger kCWKeyDerivationDefaultNumberOfRounds = 20000;
const NSUInteger kCWKeyDerivationDefaultSaltSize = 8;

@implementation CWKeyDerivation

#pragma mark - Public Methods

// TODO: Test zero error

- (NSData *)deriveKeyDataFromPassword:(NSString *)password keySize:(NSUInteger)keySize error:(NSError **)error {
    if (error) {
        *error = nil;
    }
    
    if (password.length == 0) {
        return nil;
    }
    
    if (keySize == 0) {
        return nil;
    }
    
    if (self.PBKDF2NumberOfRounds == 0) {
        return nil;
    }
    
    if (self.PBKDF2Salt.length == 0) {
        self.PBKDF2Salt = [[CWSecureRandomness new] secureRandomDataWithSize:kCWKeyDerivationDefaultSaltSize];
        if (self.PBKDF2Salt == nil) {
            [self setError:error withCode:CWCipherWattErrorKeyDerivationSaltFailure];
            return nil;
        }
    }
    
    NSData *retVal = nil;
    uint8_t *derivedKey = malloc(keySize);
    if (derivedKey == NULL) {
        [self setError:error withCode:CWCipherWattErrorNoMemory];
        return nil;
    }
    
    int result = CCKeyDerivationPBKDF(kCCPBKDF2,
                                      [password cStringUsingEncoding:NSUTF8StringEncoding],
                                      [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                                      self.PBKDF2Salt.bytes,
                                      self.PBKDF2Salt.length,
                                      [self CCPseudoRandomAlgorithm],
                                      (uint)self.PBKDF2NumberOfRounds,
                                      derivedKey,
                                      keySize);
    
    if (result == kCCSuccess) {
        retVal = [NSData dataWithBytesNoCopy:derivedKey length:keySize freeWhenDone:YES];
    } else {
        [self setError:error withCryptorStatus:result];
        self.PBKDF2Salt = nil;
        free(derivedKey);
    }
    
    // TODO: Check CCCalibratePBKDF
    
    return retVal;
}

- (void)copyParametersFromKeyDerivation:(CWKeyDerivation *)keyDerivation {
    if (keyDerivation == nil) {
        return;
    }
    
    self.PBKDF2PseudoRandomAlgorithm = keyDerivation.PBKDF2PseudoRandomAlgorithm;
    self.PBKDF2Salt = keyDerivation.PBKDF2Salt;
    self.PBKDF2NumberOfRounds = keyDerivation.PBKDF2NumberOfRounds;
}

#pragma mark - Private Methods

- (CCPseudoRandomAlgorithm)CCPseudoRandomAlgorithm {
    switch (self.PBKDF2PseudoRandomAlgorithm) {
        case CWPBKDF2PseudoRandomAlgorithmHMACSHA224:
            return kCCPRFHmacAlgSHA224;
        case CWPBKDF2PseudoRandomAlgorithmHMACSHA256:
            return kCCPRFHmacAlgSHA256;
        case CWPBKDF2PseudoRandomAlgorithmHMACSHA384:
            return kCCPRFHmacAlgSHA384;
        case CWPBKDF2PseudoRandomAlgorithmHMACSHA512:
            return kCCPRFHmacAlgSHA512;
            
        default: // CWPBKDF2PseudoRandomAlgorithmHMACSHA1
            return kCCPRFHmacAlgSHA1;
    }
}

#pragma mark - Life Cycle

- (instancetype)init {
    self = [super init];
    if (self) {
        _PBKDF2NumberOfRounds = kCWKeyDerivationDefaultNumberOfRounds;
        _PBKDF2PseudoRandomAlgorithm = CWPBKDF2PseudoRandomAlgorithmHMACSHA1;
    }
    
    return self;
}

@end
