//
//  CWAES.m
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

#import "CWAES.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation CWAES

#pragma mark - Overridden read-only Getters

- (CWBlockAlgorithm)algorithm {
    return CWBlockAlgorithmAES;
}

- (size_t)blockSizeInBytes {
    return kCCBlockSizeAES128;
}

- (size_t)keySizeInBytes {
    switch (self.AESKeySize) {
        case CWAESKeySize192:
            return kCCKeySizeAES192;
        case CWAESKeySize256:
            return kCCKeySizeAES256;
        default:
            return kCCKeySizeAES128;
    }
}

#pragma mark - Life Cycle

- (instancetype)initWithKeySize:(CWAESKeySize)keySize mode:(CWBlockOperationMode)mode {
    self = [super initWithMode:mode];
    if (self) {
        _AESKeySize = keySize;
    }
    
    return self;
}

- (instancetype)init {
    return [self initWithKeySize:CWAESKeySize128 mode:CWBlockOperationModeCBC];
}

- (instancetype)initWithMode:(CWBlockOperationMode)mode {
    return [self initWithKeySize:CWAESKeySize128 mode:mode];
}

#pragma mark - Class Methods

+ (NSUInteger)keySizeInBytesFromKeySize:(CWAESKeySize)keySize {
    switch (keySize) {
        case CWAESKeySize192:
            return kCCKeySizeAES192;
        case CWAESKeySize256:
            return kCCKeySizeAES256;
        default:
            return kCCKeySizeAES128;
    }
}

@end
