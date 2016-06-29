//
//  CWBlockCipher.m
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

#import "CWBlockCipher.h"
#import "CWKeyDerivation.h"
#import "CWSecureRandomness.h"
#import <CommonCrypto/CommonCryptor.h>
#import "NSError+CipherWatt.h"
#import "CWCipherWattObject_Private.h"

@implementation CWBlockCipher

@synthesize keyDerivation = _keyDerivation;

#pragma mark - Life Cycle

- (instancetype)initWithMode:(CWBlockOperationMode)mode {
    if ([self isMemberOfClass:[CWBlockCipher class]]) {
        [NSException raise:NSInternalInconsistencyException format:@"Can't create an instance of `%@` class. Use one of its subclasses.", NSStringFromClass([self class])];
        return nil;
    }
    
    self = [super init];
    if (self) {
        _mode = mode;
        _usePKCS7Padding = YES;
        _useKeyDerivation = YES;
    }
    return self;
}

- (instancetype)init {
    return [self initWithMode:CWBlockOperationModeCBC];
}

#pragma mark - Accessors

- (BOOL)isValidIV {
    if (self.mode != CWBlockOperationModeCBC) {
        return YES;
    }
    
    return self.IV.length == self.blockSizeInBytes;
}

- (CWKeyDerivation *)keyDerivation {
    if (_keyDerivation == nil) {
        _keyDerivation = [CWKeyDerivation new];
    }
    
    return _keyDerivation;
}

#pragma mark - Public Methods

#pragma mark - Encryption

- (NSData *)encryptData:(NSData *)dataToEncrypt error:(NSError **)error {
    if (self.rawKeyData) {
        return [self encryptData:dataToEncrypt withRawKeyData:self.rawKeyData error:error];
    } else if (self.password.length == 0) {
        [self setError:error withCode:CWCipherWattErrorNoKey];
        return nil;
    }
    
    return [self encryptData:dataToEncrypt withPassword:self.password error:error];
}

- (NSData *)encryptData:(NSData *)dataToEncrypt withPassword:(NSString *)password error:(NSError **)error {
    NSData *keyData = [self deriveKeyDataFromPassword:password error:error];
    if (!keyData) {
        return nil;
    }
    
    return [self encryptData:dataToEncrypt withRawKeyData:keyData error:error];
}

- (NSData *)encryptData:(NSData *)dataToEncrypt withRawKeyData:(NSData *)keyData error:(NSError **)error {
    if (error) {
        *error = nil;
    }
    
    if (self.mode == CWBlockOperationModeCBC && !self.IV) {
        self.IV = [CWSecureRandomness secureRandomDataWithSize:self.blockSizeInBytes];
        if (!self.IV.length) {
            [self setError:error withCode:CWCipherWattErrorIVGenerationFailed];
            return nil;
        }
    }
    
    return [self performOperation:kCCEncrypt onData:dataToEncrypt keyData:keyData error:error];
}

#pragma mark - Decryption

- (NSData *)decryptData:(NSData *)dataToDecrypt error:(NSError **)error {
    if (self.rawKeyData) {
        return [self decryptData:dataToDecrypt withRawKeyData:self.rawKeyData error:error];
    } else if (self.password.length == 0) {
        [self setError:error withCode:CWCipherWattErrorNoKey];
        return nil;
    }
    
    return [self decryptData:dataToDecrypt withPassword:self.password error:error];
}

- (NSData *)decryptData:(NSData *)dataToDecrypt withPassword:(NSString *)password error:(NSError **)error {
    NSData *keyData = [self deriveKeyDataFromPassword:password error:error];
    if (!keyData) {
        return nil;
    }
    
    return [self decryptData:dataToDecrypt withRawKeyData:keyData error:error];
}

- (NSData *)decryptData:(NSData *)dataToDecrypt withRawKeyData:(NSData *)keyData error:(NSError **)error {
    if (self.mode == CWBlockOperationModeCBC && !self.IV) {
        [self setError:error withCode:CWCipherWattErrorInvalidIV];
        return nil;
    }
    
    return [self performOperation:kCCDecrypt onData:dataToDecrypt keyData:keyData error:error];
}

#pragma mark - Private Methods

- (BOOL)operationPrologForOperation:(CCOperation)operation data:(NSData *)data keyData:(NSData *)keyData
                            cryptor:(CCCryptorRef *)cryptor error:(NSError **)error
{
    if (error) {
        *error = nil;
    }
    
    if (data == nil) {
        return NO;
    }
    
    if (self.keySizeInBytes == 0) {
        return NO;
    }
    
    if (self.IV && !self.validIV) {
        [self setError:error withCode:CWCipherWattErrorInvalidIV];
        return NO;
    }
    
    if (keyData.length == 0) {
        [self setError:error withCode:CWCipherWattErrorNoKey];
        return NO;
    }
    
    if (!self.usePKCS7Padding && data.length % self.blockSizeInBytes) {
        [self setError:error withCode:CWCipherWattErrorNoPaddingDataNotAligned];
        return NO;
    }
    
    // Initialize cryptor
    CCMode mode = [self CCMode];
    CCAlgorithm algo = [self CCAlgorithm];
    CCPadding padding = [self CCPadding];
    CCCryptorStatus status = CCCryptorCreateWithMode(operation,
                                                     mode,
                                                     algo,
                                                     padding,
                                                     self.IV.bytes,
                                                     keyData.bytes,
                                                     self.keySizeInBytes,
                                                     NULL, // Used for XTS mode only, not implemented
                                                     0, // Used for XTS mode only, not implemented
                                                     0, // Default number of rounds
                                                     0, // Deprecated. Not used
                                                     &(*cryptor));
    if (status != kCCSuccess) {
        [self setError:error withCryptorStatus:status];
        return NO;
    }
    
    return YES;
}

- (CCCryptorStatus)performUpdateAndFinalForCryptor:(CCCryptorRef)cryptor data:(NSData *)data
                                       resultBytes:(uint8_t *)resultBytes resultDataSize:(size_t)resultDataSize
                                 writtenBytesTotal:(size_t *)writtenBytesTotal error:(NSError **)error
{
    CCCryptorStatus status;
    size_t writtenBytes = 0;
    // Perform operation
    status = CCCryptorUpdate(cryptor, data.bytes, data.length, resultBytes, resultDataSize, &writtenBytes);
    if (status == kCCSuccess) {
        if (writtenBytesTotal) {
            *writtenBytesTotal += writtenBytes;
        }
        // Finalize
        status = CCCryptorFinal(cryptor, resultBytes + writtenBytes, resultDataSize - writtenBytes, &writtenBytes);
    }
    
    if (status == kCCSuccess) {
        if (writtenBytesTotal) {
            *writtenBytesTotal += writtenBytes;
        }
    } else {
        [self setError:error withCryptorStatus:status];
    }
    
    return status;
}

- (CCCryptorStatus)operationEpilogForCryptor:(CCCryptorRef)cryptor error:(NSError **)error {
    CCCryptorStatus status;
    status = CCCryptorRelease(cryptor);
    if (status != kCCSuccess) {
        [self setError:error withCryptorStatus:status];
    }
    
    return status;
}

- (NSData *)performOperation:(CCOperation)operation onData:(NSData *)data keyData:(NSData *)keyData error:(NSError **)error {
    CCCryptorRef cryptor;
    if (![self operationPrologForOperation:operation data:data keyData:keyData
                                   cryptor:&cryptor error:error])
    {
        return nil;
    }
    
    NSData *retVal = nil;
    
    // Prepare buffer for result
    size_t resultDataSize = CCCryptorGetOutputLength(cryptor, data.length, true);
    if (resultDataSize == 0) {
        [self setError:error withCode:CWCipherWattErrorZeroExpectedBuffer];
    } else {
        uint8_t *resultBytes = malloc(resultDataSize);
        if (resultBytes == NULL) {
            [self setError:error withCode:CWCipherWattErrorNoMemory];
            CCCryptorRelease(cryptor);
            return nil;
        }
        
        size_t writtenBytesTotal = 0;
        CCCryptorStatus status = [self performUpdateAndFinalForCryptor:cryptor data:data
                                                           resultBytes:resultBytes resultDataSize:resultDataSize
                                                     writtenBytesTotal:&writtenBytesTotal error:error];
        
        if (status == kCCSuccess) {
            retVal = [NSData dataWithBytesNoCopy:resultBytes length:writtenBytesTotal freeWhenDone:YES];
        } else {
            // `retVal` didn't take ownership of `resultBytes`, so free it explicitly.
            free(resultBytes);
        }
    }
    
    if ([self operationEpilogForCryptor:cryptor error:error] != kCCSuccess) {
        retVal = nil;
    }
    
    if (retVal) {
        self.rawKeyData = keyData;
    }
    
    return retVal;
}

#pragma mark -

- (CCMode)CCMode {
    switch (self.mode) {
        default:
            return kCCModeCBC;
    }
}

- (CCAlgorithm)CCAlgorithm {
    switch (self.algorithm) {
        default:
            return kCCAlgorithmAES;
    }
}

- (CCPadding)CCPadding {
    return self.usePKCS7Padding ? ccPKCS7Padding : ccNoPadding;
}

- (NSData *)deriveKeyDataFromPassword:(NSString *)password error:(NSError **)error {
    NSData *keyData = nil;
    if (self.useKeyDerivation) {
        keyData = [self.keyDerivation deriveKeyDataFromPassword:password keySize:self.keySizeInBytes error:error];
        if (keyData == nil) {
            return nil;
        }
    } else {
        keyData = [password dataUsingEncoding:NSUTF8StringEncoding];
    }
    
    return keyData;
}

@end
