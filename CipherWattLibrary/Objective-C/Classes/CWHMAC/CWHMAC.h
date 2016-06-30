//
//  CWHMAC.h
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

typedef NS_ENUM(NSUInteger, CWHMACAlgorithm) {
    CWHMACAlgorithmMD5,
    CWHMACAlgorithmSHA1,
    CWHMACAlgorithmSHA224,
    CWHMACAlgorithmSHA256,
    CWHMACAlgorithmSHA384,
    CWHMACAlgorithmSHA512
};

/** Class used to compute hash-based message authentication code (HMAC). */
@interface CWHMAC : CWCipherWattObject

/** Hash algorithm to use. Default is `CWHMACAlgorithmSHA224`. */
@property (readwrite, assign, nonatomic) CWHMACAlgorithm algorithm;

/**
 Returns newly created HMAC object instantiated with specified algorithm. This is the designated initializer.
 @param algorithm Hash algorithm to use.
 @return Newly created HMAC object instantiated with specified algorithm.
 */
- (instancetype)initWithAlgorithm:(CWHMACAlgorithm)algorithm NS_DESIGNATED_INITIALIZER;

/**
 Computes hash-based message authentication code (HMAC).
 @param data Data to compute HMAC on.
 @param keyData Raw key data. If `nil` the key is treated the same as an array of zeroes.
 @param error Upon completion contains error object if any error occured. Can be `nil`.
 @return Data object containing computed HMAC.
 */
- (NSData *)computeMACForData:(NSData *)data keyData:(NSData *)keyData error:(NSError **)error;

@end
