//
//  CWEasyAES.h
//  Crypto
//
//  Created by Alex on 6/30/16.
//  Copyright © 2016 Alex. All rights reserved.
//

#import <Foundation/Foundation.h>
// TODO: Documentation
@interface CWEasyAES : NSObject

@property (nonatomic, copy) NSString *clientID;
/** Default - YES. */
@property (nonatomic, assign) BOOL provideMessageIntegity;

- (instancetype)initWithClientID:(NSString *)clientID;

- (NSData *)easyEncryptData:(NSData *)dataToEncrypt password:(NSString *)password error:(NSError **)error;
- (NSData *)easyDecryptData:(NSData *)dataToDecrypt password:(NSString *)password error:(NSError **)error;

@end
