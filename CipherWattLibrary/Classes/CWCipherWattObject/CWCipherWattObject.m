//
//  CWCipherWattObject.m
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
#import "NSError+CipherWatt.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation CWCipherWattObject

- (BOOL)setError:(NSError **)error withCode:(CWCipherWattError)errorCode {
    // clang static analyzer doesn't like this method to have void return value:
    // "Method accepting NSError** should have a non-void return value to indicate whether or not an error occurred".
    // Implemented just to mute warning.
    if (error) {
        *error = [NSError cw_errorForCode:errorCode];
        return YES;
    }
    
    return NO;
}

- (BOOL)setError:(NSError **)error withCryptorStatus:(CCCryptorStatus)cryptorStatus {
    if (error) {
        CWCipherWattError errorCode = CWCipherWattErrorUnknown;
        switch (cryptorStatus) {
            case kCCParamError:
                errorCode = CWCipherWattErrorCryptorParamError;
                break;
            case kCCBufferTooSmall:
                errorCode = CWCipherWattErrorCryptorBufferTooSmall;
                break;
            case kCCMemoryFailure:
                errorCode = CWCipherWattErrorCryptorMemoryFailure;
                break;
            case kCCAlignmentError:
                errorCode = CWCipherWattErrorCryptorAlignmentError;
                break;
            case kCCDecodeError:
                errorCode = CWCipherWattErrorCryptorDecodeError;
                break;
            case kCCUnimplemented:
                errorCode = CWCipherWattErrorCryptorUnimplemented;
                break;
                
            default:
                break;
        }
        
        *error = [NSError cw_errorForCode:errorCode commonString:@"CommonCrypto underlying error"];
        return YES;
    }
    
    return NO;
}

@end
