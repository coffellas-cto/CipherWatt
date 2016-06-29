//
//  NSError+CipherWatt.m
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

#import "NSError+CipherWatt.h"


@implementation NSError (CipherWatt)

+ (NSError *)cw_errorForCode:(CWCipherWattError)errorCode {
    return [self cw_errorForCode:errorCode commonString:nil];
}

+ (NSError *)cw_errorForCode:(CWCipherWattError)errorCode commonString:(NSString *)commonString {
    NSString *localizedDescription;
    switch (errorCode) {
        case CWCipherWattErrorInvalidIV:
            localizedDescription = @"IV is invalid";
            break;
        case CWCipherWattErrorNoMemory:
            localizedDescription = @"Failed to allocate memory";
            break;
        case CWCipherWattErrorIVGenerationFailed:
            localizedDescription = @"IV generation failed";
            break;
        case CWCipherWattErrorNoKey:
            localizedDescription = @"No key provided";
            break;
        case CWCipherWattErrorNoPaddingDataNotAligned:
            localizedDescription = @"Padding is not used but your data is not aligned to block size";
            break;
        case CWCipherWattErrorZeroExpectedBuffer:
            localizedDescription = @"Expected buffer size estimated to zero. Probably data is malformed";
            break;
        case CWCipherWattErrorIvalidExpectedBufferSize:
            localizedDescription = @"Expected buffer size is invalid";
            break;
            
        case CWCipherWattErrorCryptorParamError:
            localizedDescription = @"Illegal parameter value";
            break;
        case CWCipherWattErrorCryptorBufferTooSmall:
            localizedDescription = @"Insufficent buffer provided for specified operation";
            break;
        case CWCipherWattErrorCryptorMemoryFailure:
            localizedDescription = @"Memory allocation failure";
            break;
        case CWCipherWattErrorCryptorAlignmentError:
            localizedDescription = @"Input size was not aligned properly";
            break;
        case CWCipherWattErrorCryptorDecodeError:
            localizedDescription = @"Input data did not decode or decrypt properly";
            break;
        case CWCipherWattErrorCryptorUnimplemented:
            localizedDescription = @"Function not implemented for the current algorithm";
            break;
            
        case CWCipherWattErrorKeyDerivationSaltFailure:
            localizedDescription = @"Failed to generate salt";
            break;
            
        default:
            localizedDescription = @"Unknown error";
            break;
    }
    
    if (commonString.length) {
        localizedDescription = [NSString stringWithFormat:@"%@. %@", commonString, localizedDescription];
    }
    
    return [NSError errorWithDomain:kCWCipherWattErrorDomain code:errorCode userInfo:@{NSLocalizedDescriptionKey: localizedDescription}];
}

@end
