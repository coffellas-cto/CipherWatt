//
//  CWEasyAES.m
//  Crypto
//
//  Created by Alex on 6/30/16.
//  Copyright © 2016 Alex. All rights reserved.
//

#import "CWEasyAES.h"

@implementation CWEasyAES

- (NSData *)easyEncryptData:(NSData *)dataToEncrypt password:(NSString *)password error:(NSError **)error {
    /* Algorithm is as follows:
     1. Generate random SALT.
     2. Derive a MASTER KEY from password with PBKDF2 using SALT.
     3. Derive both CIPHER KEY and HMAC KEY from MASTER KEY using HKDF
        and `clientID` property (if `clientID` is empty - use predefined string).
     4. Generate random IV.
     5. Encrypt data with AES-256-CBC using CIPHER KEY and IV and obtain CIPHERTEXT.
     6. Compute MAC of resulting CIPHERTEXT using HMAC-SHA256 and HMAC KEY from step 3.
     7. Return SALT+MAC+IV+CIPHERTEXT.
     */
    
    return nil;
}

- (NSData *)easyDecryptData:(NSData *)dataToDecrypt password:(NSString *)password error:(NSError **)error {
    /* Algorithm is as follows:
     1. Take input as SALT+MAC+IV+CIPHERTEXT.
     2. Derive a MASTER KEY from password with PBKDF2 using SALT.
     3. Derive both CIPHER KEY and HMAC KEY from MASTER KEY using HKDF
        and `clientID` property (if `clientID` is empty - use predefined string).
     4. Compute MAC' of CIPHERTEXT using HMAC-SHA256 and HMAC KEY.
     5. Securely compare MAC and MAC' and return empty data and error if not equal, else continue.
     6. Decrypt data with AES-256-CBC using CIPHER KEY from step 3 and IV and obtain PLAINTEXT.
     7. Return PLAINTEXT.
     */
    return nil;
}

#pragma mark - Life Cycle

- (instancetype)init {
    return [self initWithClientID:nil];
}

- (instancetype)initWithClientID:(NSString *)clientID {
    self = [super init];
    if (self) {
        _clientID = clientID;
        _provideMessageIntegity = YES;
    }
    return self;
}

@end
