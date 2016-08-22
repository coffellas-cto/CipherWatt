//
//  CWAESTests.m
//
//  Created by A. Gordiyenko on 6/1/16.
//  Copyright © 2016 A. Gordiyenko. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "CWAES.h"
#import "CWKeyDerivation.h"
#import "CWSecureRandomness.h"
#import "NSError+CipherWatt.h"
#import "CWSecureRandomnessFailer.h"

@interface CWAESTests : XCTestCase

@property NSData *IV15Bytes;
@property NSData *IV16Bytes;
@property NSData *IV24Bytes;
@property NSData *IV32Bytes;

@property NSData *tinyPlainTextData;

@end

@implementation CWAESTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    self.tinyPlainTextData = [NSData dataWithBytes:"012345" length:6];
    self.IV15Bytes = [NSData dataWithBytes:"0123456789012345" length:15];
    self.IV16Bytes = [NSData dataWithBytes:"0123456789012345" length:16];
    self.IV24Bytes = [NSData dataWithBytes:"012345678901234567890123" length:24];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)validateCipherCBC:(CWAES *)cipher keySize:(CWAESKeySize)keySize {
    XCTAssertNotNil(cipher);
    XCTAssertEqual(cipher.algorithm, CWBlockAlgorithmAES);
    XCTAssertEqual(cipher.AESKeySize, keySize);
    XCTAssertEqual(cipher.mode, CWBlockOperationModeCBC);
}

- (void)testCreation {
    // CBC (Default), 128 (Default)
    [self validateCipherCBC:[[CWAES alloc] init] keySize:CWAESKeySize128];
    
    // CBC, 128 (Default)
    [self validateCipherCBC:[[CWAES alloc] initWithMode:CWBlockOperationModeCBC] keySize:CWAESKeySize128];
    
    // CBC, 128 (Explicit)
    [self validateCipherCBC:[[CWAES alloc] initWithKeySize:CWAESKeySize128 mode:CWBlockOperationModeCBC]
                    keySize:CWAESKeySize128];
    
    // CBC, 192
    [self validateCipherCBC:[[CWAES alloc] initWithKeySize:CWAESKeySize192 mode:CWBlockOperationModeCBC]
                    keySize:CWAESKeySize192];
    
    // CBC, 256
    [self validateCipherCBC:[[CWAES alloc] initWithKeySize:CWAESKeySize256 mode:CWBlockOperationModeCBC]
                    keySize:CWAESKeySize256];
}

- (NSData *)validateIV:(NSData *)IV mode:(CWBlockOperationMode)mode keySize:(CWAESKeySize)keySize error:(NSError **)error {
    *error = nil;
    CWAES *cipher = [[CWAES alloc] initWithKeySize:keySize mode:mode];
    cipher.IV = IV;
    cipher.rawKeyData = [NSData dataWithBytes:"01" length:2];
    return [cipher encryptData:[NSData dataWithBytes:"012345" length:6] error:error];
}

- (NSData *)validateIV_CBC:(NSData *)IV keySize:(CWAESKeySize)keySize error:(NSError **)error {
    return [self validateIV:IV mode:CWBlockOperationModeCBC keySize:keySize error:error];
}

- (void)testIV_CBCMode {
    // Invalid IV 15b
    NSError *error;
    NSData *cipherText = [self validateIV_CBC:self.IV15Bytes keySize:CWAESKeySize128 error:&error];
    XCTAssertEqual(error.code, CWCipherWattErrorInvalidIV);
    XCTAssertNil(cipherText);
    
    // Invalid IV 24b
    cipherText = [self validateIV_CBC:self.IV24Bytes keySize:CWAESKeySize192 error:&error];
    XCTAssertEqual(error.code, CWCipherWattErrorInvalidIV);
    XCTAssertNil(cipherText);
    
    // Valid IV CBC 128
    cipherText = [self validateIV_CBC:self.IV16Bytes keySize:CWAESKeySize128 error:&error];
    XCTAssertNil(error);
    XCTAssertNotNil(cipherText);
}

- (void)testEmptyKey {
    CWAES *cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize128 mode:CWBlockOperationModeCBC];
    cipher.IV = self.IV16Bytes;
    NSError *error;
    NSData *cipherText = [cipher encryptData:self.tinyPlainTextData error:&error];
    XCTAssertEqual(error.code, CWCipherWattErrorNoKey);
    XCTAssertNil(cipherText);
}

#pragma mark - Rigorous tests

- (NSData *)encryptData:(NSData *)data
           withPassword:(NSString *)password
                    key:(NSData *)key
                keySize:(CWAESKeySize)keySize
                     IV:(NSData *)IV
          keyDerivation:(CWKeyDerivation *)keyDerivation
                padding:(BOOL)padding
                  error:(NSError **)error
{
    CWAES *cipher = [[CWAES alloc] initWithKeySize:keySize mode:CWBlockOperationModeCBC];
    cipher.password = password;
    cipher.rawKeyData = key;
    cipher.IV = IV;
    cipher.usePKCS7Padding = padding;
    cipher.useKeyDerivation = keyDerivation != nil;
    cipher.keyDerivation.PBKDF2NumberOfRounds = keyDerivation.PBKDF2NumberOfRounds;
    cipher.keyDerivation.PBKDF2Salt = keyDerivation.PBKDF2Salt;
    cipher.keyDerivation.PBKDF2PseudoRandomAlgorithm = keyDerivation.PBKDF2PseudoRandomAlgorithm;
    
    return [cipher encryptData:data error:error];
}

typedef enum : int {
    TestPasswordPresent = 1 << 0,
    TestPasswordEmpty = 1 << 1,
    TestPasswordCount = 2
} TestPassword;

typedef enum : int {
    TestKeyPresent = 1 << 0,
    TestKeyEmpty = 1 << 1,
    TestKeyTooShort = 1 << 2,
    TestKeyCount = 3
} TestKey;

typedef enum : int {
    TestKeySize128 = 1 << 0,
    TestKeySize192 = 1 << 1,
    TestKeySize256 = 1 << 2,
    TestKeySizeCount = 3
} TestKeySize;

typedef enum : int {
    TestIVPresent = 1 << 0,
    TestIVEmpty = 1 << 1,
    TestIVCount = 2
} TestIV;

typedef enum : int {
    TestKeyDerivationYES = 1 << 0,
    TestKeyDerivationNO = 1 << 1,
    TestKeyDerivationCount = 2
} TestKeyDerivation;

typedef enum : int {
    TestKeyDerivationAlgoSHA1 = 1 << 0,
    TestKeyDerivationAlgoSHA224 = 1 << 1,
    TestKeyDerivationAlgoSHA256 = 1 << 2,
    TestKeyDerivationAlgoSHA384 = 1 << 3,
    TestKeyDerivationAlgoSHA512 = 1 << 4,
    TestKeyDerivationAlgoCount = 5
} TestKeyDerivationAlgo;

typedef enum : int {
    TestSaltPresent = 1 << 0,
    TestSaltEmpty = 1 << 1,
    TestSaltCount = 2
} TestSalt;

typedef enum : int {
    TestPaddingPresent = 1 << 0,
    TestPaddingEmpty = 1 << 1,
    TestPaddingCount = 2
} TestPadding;

- (void)encryptData:(NSData *)data
       testPassword:(TestPassword)testPassword
            testKey:(TestKey)testKey
        testKeySize:(TestKeySize)testKeySize
             testIV:(TestIV)testIV
  testKeyDerivation:(TestKeyDerivation)testKeyDerivation
testKeyDerivationAlgo:(TestKeyDerivationAlgo)testKeyDerivationAlgo
           testSalt:(TestSalt)testSalt
        testPadding:(TestPadding)testPadding
{
    NSString *(^parametersDescription)() = ^NSString *{
        NSString *password = [NSString stringWithFormat:@"Password: %@", @(testPassword & TestPasswordPresent)];
        NSString *key = nil;
        if (testKey & TestKeyPresent) {
            key = @"1";
        } else if (testKey & TestKeyTooShort) {
            key = @"short";
        } else {
            key = @"0";
        }
        key = [NSString stringWithFormat:@"Key: %@", key];
        NSString *keySize = nil;
        if (testKeySize & TestKeySize128) {
            keySize = @"128";
        } else if (testKeySize & TestKeySize192) {
            keySize = @"192";
        } else {
            keySize = @"256";
        }
        keySize = [NSString stringWithFormat:@"Key Size: %@", keySize];
        
        NSString *IV = [NSString stringWithFormat:@"IV: %@", @(testIV & TestIVPresent)];
        NSString *keyDerivation = [NSString stringWithFormat:@"Key Derivation: %@", @(testKeyDerivation & TestKeyDerivationYES)];
        NSString *algo = nil;
        if (testKeyDerivationAlgo & TestKeyDerivationAlgoSHA1) {
            algo = @"HMAC-SHA1";
        } else if (testKeyDerivationAlgo & TestKeyDerivationAlgoSHA224) {
            algo = @"HMAC-SHA224";
        } else if (testKeyDerivationAlgo & TestKeyDerivationAlgoSHA256) {
            algo = @"HMAC-SHA256";
        } else if (testKeyDerivationAlgo & TestKeyDerivationAlgoSHA384) {
            algo = @"HMAC-SHA384";
        } else {
            algo = @"HMAC-SHA512";
        }
        algo = [NSString stringWithFormat:@"Derivation Algorithm: %@", algo];
        NSString *salt = [NSString stringWithFormat:@"Salt: %@", @(testSalt & TestSaltPresent)];
        NSString *padding = [NSString stringWithFormat:@"Padding: %@", @(testPadding & TestPaddingPresent)];
        
        return [NSString stringWithFormat:@"\n%@\n%@\n%@\n%@\n%@\n%@\n%@\n%@\n", password, key, keySize, IV, keyDerivation, algo, salt, padding];
    };
    
    CWKeyDerivation *keyDerivation = nil;
    NSData *IV = nil;
    CWAESKeySize keySize = 0;
    NSUInteger expectedDataSize = 0;
    NSData *key = nil;
    BOOL expectError = NO;
    
    if (testKeyDerivation & TestKeyDerivationYES) {
        keyDerivation = [CWKeyDerivation new];
        keyDerivation.PBKDF2NumberOfRounds = 5; // No need for security here, just check the algorithm so it is fast enough for numerous tests
        keyDerivation.PBKDF2Salt = testSalt & TestSaltPresent ? [CWSecureRandomness secureRandomDataWithSize:64 error:nil] : nil;
        CWPBKDF2PseudoRandomAlgorithm algo;
        if (testKeyDerivationAlgo & TestKeyDerivationAlgoSHA1) {
            algo = CWPBKDF2PseudoRandomAlgorithmHMACSHA1;
        } else if (testKeyDerivationAlgo & TestKeyDerivationAlgoSHA224) {
            algo = CWPBKDF2PseudoRandomAlgorithmHMACSHA224;
        } else if (testKeyDerivationAlgo & TestKeyDerivationAlgoSHA256) {
            algo = CWPBKDF2PseudoRandomAlgorithmHMACSHA256;
        } else if (testKeyDerivationAlgo & TestKeyDerivationAlgoSHA384) {
            algo = CWPBKDF2PseudoRandomAlgorithmHMACSHA384;
        } else {
            algo = CWPBKDF2PseudoRandomAlgorithmHMACSHA512;
        }
        
        keyDerivation.PBKDF2PseudoRandomAlgorithm = algo;
    }
    
    if (testIV & TestIVPresent) {
        IV = [CWSecureRandomness secureRandomDataWithSize:16  error:nil];
    }
    
    if (testKeySize & TestKeySize128) {
        keySize = CWAESKeySize128;
    } else if (testKeySize & TestKeySize192) {
        keySize = CWAESKeySize192;
    } else {
        keySize = CWAESKeySize256;
    }
    
    NSUInteger blockSize = 16;
    NSUInteger keySizeInBytes = [CWAES keySizeInBytesFromKeySize:keySize];
    
    if (testKey & TestKeyPresent) {
        key = [CWSecureRandomness secureRandomDataWithSize:keySizeInBytes error:nil];
    } else if (testKey & TestKeyTooShort) {
        key = [CWSecureRandomness secureRandomDataWithSize:keySizeInBytes / 2 error:nil];
    }
    
    if ((testKey & TestKeyEmpty) && (testPassword & TestPasswordEmpty)) {
        expectError = YES;
    } else if ((testPadding & TestPaddingEmpty) && (data.length % blockSize)) {
        expectError = YES;
    } else if (((testKey & TestKeyPresent) || (testKey & TestKeyTooShort) || (testPassword & TestPasswordPresent))) {
        NSUInteger originalDataSize = data.length;
        if (testPadding & TestPaddingPresent) {
            expectedDataSize = originalDataSize + blockSize - originalDataSize % blockSize;
        } else {
            expectedDataSize = originalDataSize;
        }
    }
    
    NSError *error = nil;
    
    NSData *finalData = [self encryptData:data
                             withPassword:testPassword & TestPasswordPresent ? @"test_password" : nil
                                      key:key
                                  keySize:keySize
                                       IV:IV
                            keyDerivation:keyDerivation
                                  padding:testPadding & TestPaddingPresent
                                    error:&error];
    if (expectedDataSize == finalData.length) {
        XCTAssertTrue(YES);
    } else {
        XCTFail(@"Failure: %@", parametersDescription());
    }
    
    XCTAssertEqual(expectError, error != nil, @"Failure: %@", parametersDescription());
}

- (void)encrypt:(BOOL)encrypt data:(NSData *)data {
    TestPassword testPassword;
    TestKey testKey;
    TestKeySize testKeySize;
    TestIV testIV;
    TestKeyDerivation testKeyDerivation;
    TestKeyDerivationAlgo testKeyDerivationAlgo;
    TestSalt testSalt;
    TestPadding testPadding;
    
    for (int i = 0; i < TestPasswordCount; i++) {
        testPassword = 1 << i;
        
        for (int j = 0; j < TestKeyCount; j++) {
            testKey = 1 << j;
            
            for (int k = 0; k < TestKeySizeCount; k++) {
                testKeySize = 1 << k;
                
                for (int l = 0; l < TestIVCount; l++) {
                    testIV = 1 << l;
                    
                    for (int m = 0; m < TestKeyDerivationCount; m++) {
                        testKeyDerivation = 1 << m;
                        
                        for (int n = 0; n < TestKeyDerivationAlgoCount; n++) {
                            testKeyDerivationAlgo = 1 << n;
                            
                            for (int o = 0; o < TestSaltCount; o++) {
                                testSalt = 1 << o;
                                
                                for (int p = 0; p < TestPaddingCount; p++) {
                                    testPadding = 1 << p;
                                    @autoreleasepool {
                                        [self encryptData:data
                                             testPassword:testPassword
                                                  testKey:testKey
                                              testKeySize:testKeySize
                                                   testIV:testIV
                                        testKeyDerivation:testKeyDerivation
                                    testKeyDerivationAlgo:testKeyDerivationAlgo
                                                 testSalt:testSalt
                                              testPadding:testPadding];
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

- (void)testEncryptionRigorous {
    NSData *dataToEncrypt = [@"My dear friend, this is just a test for many possible permutaions of encryption parameters" dataUsingEncoding:NSUTF8StringEncoding];
    [self encrypt:YES data:dataToEncrypt];
    
    dataToEncrypt = [@"This data length is multiple of 16 bytes aka AES block size_____" dataUsingEncoding:NSUTF8StringEncoding];
    [self encrypt:YES data:dataToEncrypt];
}

- (void)encryptThenDecryptWithPlainText:(NSString *)testPlainText
                                keySize:(CWAESKeySize)keySize
                          keyDerivation:(CWKeyDerivation *)keyDerivation
                               password:(NSString *)password
                                     IV:(NSData *)IV
                             usePadding:(BOOL)usePadding
                                 rawKey:(NSData *)rawKey
{
    NSData *plainTextData = [testPlainText dataUsingEncoding:NSUTF8StringEncoding];
    CWAES *cipherEnc = [[CWAES alloc] initWithKeySize:keySize mode:CWBlockOperationModeCBC];
    cipherEnc.usePKCS7Padding = usePadding;
    if (password && keyDerivation) {
        [cipherEnc.keyDerivation copyParametersFromKeyDerivation:keyDerivation];
    }
    if (IV) {
        cipherEnc.IV = IV;
    }
    NSError *error = nil;
    NSData *cipherText = nil;
    if (rawKey) {
        cipherText = [cipherEnc encryptData:plainTextData withRawKeyData:rawKey error:&error];
    } else if (password) {
        cipherText = [cipherEnc encryptData:plainTextData withPassword:password error:&error];
    }
    XCTAssertNil(error);
    XCTAssertNotNil(cipherText);
    if (!IV) {
        IV = cipherEnc.IV;
    }
    XCTAssertNotNil(IV);
    
    CWAES *cipherDec = [[CWAES alloc] initWithKeySize:keySize mode:CWBlockOperationModeCBC];
    cipherDec.usePKCS7Padding = usePadding;
    if (password && keyDerivation) {
        [cipherDec.keyDerivation copyParametersFromKeyDerivation:keyDerivation];
    }
    cipherDec.IV = IV;
    NSData *decryptedPlainTextData = nil;
    if (rawKey) {
        decryptedPlainTextData = [cipherDec decryptData:cipherText withRawKeyData:rawKey error:&error];
    } else if (password) {
        if (!keyDerivation) {
            [cipherDec.keyDerivation copyParametersFromKeyDerivation:cipherEnc.keyDerivation];
        }
        decryptedPlainTextData = [cipherDec decryptData:cipherText withPassword:password error:&error];
    }
    XCTAssertEqualObjects(cipherEnc.IV, cipherDec.IV);
    XCTAssertNil(error);
    XCTAssertNotNil(decryptedPlainTextData);
    NSString *decryptedPlainText = [[NSString alloc] initWithData:decryptedPlainTextData encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(decryptedPlainText, testPlainText);
}

- (void)testEncryptThenDecrypt {
    NSString *testPlainText = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    
    [self encryptThenDecryptWithPlainText:testPlainText
                                  keySize:CWAESKeySize128
                            keyDerivation:nil
                                 password:nil
                                       IV:nil
                               usePadding:YES
                                   rawKey:[CWSecureRandomness secureRandomDataWithSize:[CWAES keySizeInBytesFromKeySize:CWAESKeySize128] error:nil]];
    
    testPlainText = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.___";
    [self encryptThenDecryptWithPlainText:testPlainText
                                  keySize:CWAESKeySize128
                            keyDerivation:nil
                                 password:nil
                                       IV:nil
                               usePadding:NO
                                   rawKey:[CWSecureRandomness secureRandomDataWithSize:[CWAES keySizeInBytesFromKeySize:CWAESKeySize128] error:nil]];
    
    testPlainText = @"Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?";
    
    [self encryptThenDecryptWithPlainText:testPlainText
                                  keySize:CWAESKeySize192
                            keyDerivation:nil
                                 password:nil
                                       IV:nil
                               usePadding:YES
                                   rawKey:[CWSecureRandomness secureRandomDataWithSize:[CWAES keySizeInBytesFromKeySize:CWAESKeySize192] error:nil]];
    
    [self encryptThenDecryptWithPlainText:testPlainText
                                  keySize:CWAESKeySize192
                            keyDerivation:nil
                                 password:@"1n237-23vn5-2"
                                       IV:nil
                               usePadding:YES
                                   rawKey:nil];
    
    CWKeyDerivation *keyDerivation = [CWKeyDerivation new];
    keyDerivation.PBKDF2Salt = [@"saltysalt:)" dataUsingEncoding:NSUTF8StringEncoding];
    
    [self encryptThenDecryptWithPlainText:testPlainText
                                  keySize:CWAESKeySize256
                            keyDerivation:keyDerivation
                                 password:@"c8c9s0s0sjsjs8"
                                       IV:nil
                               usePadding:YES
                                   rawKey:nil];
    
    testPlainText = @"At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi, id est laborum et dolorum fuga. Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus, omnis voluptas assumenda est, omnis dolor repellendus. Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet ut et voluptates repudiandae sint et molestiae non recusandae. Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat.";
    
    
    keyDerivation = [CWKeyDerivation new];
    keyDerivation.PBKDF2Salt = [CWSecureRandomness secureRandomDataWithSize:300 error:nil];
    
    [self encryptThenDecryptWithPlainText:testPlainText
                                  keySize:CWAESKeySize256
                            keyDerivation:keyDerivation
                                 password:@"atur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi "
                                       IV:[CWSecureRandomness secureRandomDataWithSize:16 error:nil]
                               usePadding:YES
                                   rawKey:nil];
}

- (void)testDecriptionPreparedCipherTexts {
    NSSet *keyLengthsSet = [NSSet setWithObjects:@128, @192, @256, nil];
    NSDictionary *mdsToAlgo = @{@"sha1": @(CWPBKDF2PseudoRandomAlgorithmHMACSHA1),
                                @"sha224": @(CWPBKDF2PseudoRandomAlgorithmHMACSHA224),
                                @"sha256": @(CWPBKDF2PseudoRandomAlgorithmHMACSHA256),
                                @"sha384": @(CWPBKDF2PseudoRandomAlgorithmHMACSHA384),
                                @"sha512": @(CWPBKDF2PseudoRandomAlgorithmHMACSHA512)};
    
    for (int i = 0; i < 200; i++) {
        // The contents of these `plist` files were generated by OpenSSL then serialized into `plist` format.
        // Plaintexts contain random quotes from Byron's Childe Harold.
        NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:[NSString stringWithFormat:@"aes-cbc-%03d", i] ofType:@"plist"];
        XCTAssertNotNil(path);
        NSDictionary *dic = [NSDictionary dictionaryWithContentsOfFile:path];
        XCTAssertNotNil(dic);
        
        NSDictionary *AESDic = dic[@"aes"];
        XCTAssertNotNil(AESDic);
        NSNumber *keyLengthNumber = AESDic[@"keyLength"];
        XCTAssertTrue([keyLengthsSet containsObject:keyLengthNumber]);
        CWAESKeySize keySize = CWAESKeySize128;
        switch (keyLengthNumber.unsignedIntegerValue) {
            case 192:
                keySize = CWAESKeySize192;
                break;
            case 256:
                keySize = CWAESKeySize256;
                break;
            default:
                break;
        }
        
        NSData *IV = AESDic[@"iv"];
        XCTAssertNotNil(IV);
        
        NSNumber *usePaddingNumber = AESDic[@"usePadding"];
        XCTAssertNotNil(usePaddingNumber);
        
        CWAES *cipher = [[CWAES alloc] initWithKeySize:keySize mode:CWBlockOperationModeCBC];
        cipher.IV = IV;
        cipher.usePKCS7Padding = usePaddingNumber.boolValue;
        
        NSDictionary *PBKDFDic = dic[@"pbkdf2"];
        BOOL usePassword = NO;
        if (PBKDFDic) {
            usePassword = YES;
            NSString *md = PBKDFDic[@"md"];
            XCTAssertNotNil(md);
            NSNumber *algoNumber = mdsToAlgo[md];
            XCTAssertNotNil(algoNumber);
            cipher.keyDerivation.PBKDF2PseudoRandomAlgorithm = algoNumber.unsignedIntegerValue;
            NSNumber *iterationsCount = PBKDFDic[@"ic"];
            XCTAssertNotNil(iterationsCount);
            cipher.keyDerivation.PBKDF2NumberOfRounds = iterationsCount.unsignedIntegerValue;
            NSData *salt = PBKDFDic[@"salt"];
            XCTAssertNotNil(salt);
            cipher.keyDerivation.PBKDF2Salt = salt;
            NSString *password = PBKDFDic[@"password"];
            XCTAssertNotNil(password);
            cipher.password = password;
        }
        
        if (!usePassword) {
            NSData *key = AESDic[@"key"];
            XCTAssertNotNil(key);
            cipher.rawKeyData = key;
        }
        
        NSString *plainText = AESDic[@"plainText"];
        XCTAssertNotNil(plainText);
        
        NSData *cipherTextData = AESDic[@"cipherText"];
        XCTAssertNotNil(cipherTextData);
        
        NSError *error;
        NSData *recoveredData = [cipher decryptData:cipherTextData error:&error];
        XCTAssertNil(error);
        XCTAssertNotNil(recoveredData);
        NSString *recoveredPlainText = [[NSString alloc] initWithData:recoveredData encoding:NSUTF8StringEncoding]; // NSUTF8StringEncoding because I know it for sure.
        XCTAssertEqualObjects(recoveredPlainText, plainText, @"recoveredPlainText:\n%@\nplainText:\n%@", recoveredPlainText, plainText);
    }
}

- (void)testFailedKeyDerivation {
    CWAES *cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize128 mode:CWBlockOperationModeCBC];
    CWSecureRandomnessFailer *failer = [CWSecureRandomnessFailer new];
    [failer replaceImplementations];
    NSError *error = nil;
    NSData *result = [cipher encryptData:[@"testy" dataUsingEncoding:NSASCIIStringEncoding] withPassword:@"pass" error:&error];
    XCTAssertNil(result);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorKeyDerivationSaltFailure);
    [failer restoreImplementations];
}

- (void)testFailedIVGeneration {
    CWAES *cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize192 mode:CWBlockOperationModeCBC];
    CWSecureRandomnessFailer *failer = [CWSecureRandomnessFailer new];
    [failer replaceImplementations];
    NSError *error = nil;
    NSData *result = [cipher encryptData:[@"testy3" dataUsingEncoding:NSASCIIStringEncoding] withRawKeyData:[@"sometestdatadoesntmatter" dataUsingEncoding:NSASCIIStringEncoding] error:&error];
    XCTAssertNil(result);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorIVGenerationFailed);
    
    // Using buffer
    
    NSData *dataToEncrypt = [@"somethingwhatever" dataUsingEncoding:NSASCIIStringEncoding];
    size_t bufferSize = dataToEncrypt.length / 16 * 16 + 16;
    uint8_t *buffer = malloc(bufferSize);
    size_t written = 0;
    cipher.rawKeyData = [@"blahdoesntmatterinthistest" dataUsingEncoding:NSASCIIStringEncoding];
    BOOL bResult = [cipher encryptData:dataToEncrypt buffer:buffer bufferSize:bufferSize bytesWritten:NULL error:&error];
    XCTAssertFalse(bResult);
    XCTAssertEqual(error.code, CWCipherWattErrorIVGenerationFailed);
    XCTAssertEqual(written, 0);
    
    free(buffer);
    
    [failer restoreImplementations];
}

- (NSData *)firstChildeCipherText {
    NSDictionary *dic = [NSDictionary dictionaryWithContentsOfFile:[[NSBundle bundleForClass:[self class]] pathForResource:@"aes-cbc-001" ofType:@"plist"]];
    NSData *cipherTextData = nil;
    @try { cipherTextData = [dic valueForKeyPath:@"aes.cipherText"]; } @catch (NSException *exception) {} @finally {}
    XCTAssertNotNil(cipherTextData);
    return cipherTextData;
}

- (void)testDecryptionWithNoKey {
    CWAES *cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize192 mode:CWBlockOperationModeCBC];
    
    NSData *cipherTextData = [self firstChildeCipherText];
    
    NSError *error = nil;
    NSData *result = [cipher decryptData:cipherTextData error:&error];
    XCTAssertNil(result);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorNoKey);
}

- (void)testNoErrorEncryption {
    NSError *error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
    CWAES *cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize192 mode:CWBlockOperationModeCBC];
    NSData *result = [cipher encryptData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] withPassword:@"ggsvfasfkas" error:&error];
    XCTAssertNotNil(result);
    XCTAssertNil(error);
    
    error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
    cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize192 mode:CWBlockOperationModeCBC];
    result = [cipher encryptData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] withRawKeyData:[CWSecureRandomness secureRandomDataWithSize:12 error:nil] error:&error];
    XCTAssertNotNil(result);
    XCTAssertNil(error);
    
    error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
    cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize192 mode:CWBlockOperationModeCBC];
    cipher.rawKeyData = [CWSecureRandomness secureRandomDataWithSize:12 error:nil];
    result = [cipher encryptData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] error:&error];
    XCTAssertNotNil(result);
    XCTAssertNil(error);
    
    error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
    cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize192 mode:CWBlockOperationModeCBC];
    cipher.password = @"nvpqjpqjf";
    result = [cipher encryptData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] error:&error];
    XCTAssertNotNil(result);
    XCTAssertNil(error);
}

- (void)testZeroData {
    NSError *error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
    CWAES *cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize192 mode:CWBlockOperationModeCBC];
    NSData *result = [cipher encryptData:nil withPassword:@"ggsvfasfkas" error:&error];
    XCTAssertNil(result);
    XCTAssertNil(error);
}

- (void)testFailingDecryptionWithFailingKeyDerivation {
    CWAES *cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize192 mode:CWBlockOperationModeCBC];
    NSData *cipherTextData = [self firstChildeCipherText];
    
    NSError *error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
    CWSecureRandomnessFailer *failer = [CWSecureRandomnessFailer new];
    [failer replaceImplementations];
    NSData *result = [cipher decryptData:cipherTextData withPassword:@"supapupapass" error:&error];
    [failer restoreImplementations];
    XCTAssertNil(result);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorKeyDerivationSaltFailure);
}

- (void)testDecryptionWithoutIV {
    CWAES *cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize128 mode:CWBlockOperationModeCBC];
    NSData *cipherTextData = [self firstChildeCipherText];
    
    NSError *error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
    NSData *result = [cipher decryptData:cipherTextData withRawKeyData:[CWSecureRandomness secureRandomDataWithSize:16 error:nil] error:&error];
    XCTAssertNil(result);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorInvalidIV);
    
    // Same with buffer
    
    error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
    uint8_t *buffer = malloc(cipherTextData.length);
    size_t written = 0;
    cipher.rawKeyData = [@"whatever" dataUsingEncoding:NSASCIIStringEncoding];
    BOOL bResult = [cipher decryptData:cipherTextData buffer:buffer bufferSize:cipherTextData.length bytesWritten:&written error:&error];
    XCTAssertFalse(bResult);
    XCTAssertEqual(written, 0);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorInvalidIV);
    free(buffer);
}

- (void)testSP800AESCBC {
    NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"sp800-38a-aes-cbc" ofType:@"plist"];
    XCTAssertNotNil(path);

    NSArray *tests = [NSArray arrayWithContentsOfFile:path];
    XCTAssertNotNil(tests);
    
    for (NSDictionary *testDic in tests) {
        NSUInteger keySizeValue = [testDic[@"keysize"] unsignedIntegerValue];
        CWAESKeySize keySize;
        switch (keySizeValue) {
            case 128:
                keySize = CWAESKeySize128;
                break;
            case 192:
                keySize = CWAESKeySize192;
                break;
            case 256:
                keySize = CWAESKeySize256;
                break;
                
            default:
                XCTFail(@"Unknown key size");
                break;
        }
        
        // Test Encryption
        NSData *IV = testDic[@"iv"];
        XCTAssertNotNil(IV);
        XCTAssertEqual(IV.length, 16);
        
        NSData *key = testDic[@"key"];
        XCTAssertNotNil(key);
        
        NSData *plaintext = testDic[@"plaintext"];
        XCTAssertNotNil(plaintext);
        
        NSData *ciphertext = testDic[@"ciphertext"];
        XCTAssertNotNil(ciphertext);
        
        CWAES *cipher = [[CWAES alloc] initWithKeySize:keySize mode:CWBlockOperationModeCBC];
        cipher.rawKeyData = key;
        cipher.IV = IV;
        cipher.usePKCS7Padding = NO;
        
        // 1. Encryption
        NSError *error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
        NSData *resultData = [cipher encryptData:plaintext error:&error];
        XCTAssertNil(error);
        XCTAssertEqualObjects(resultData, ciphertext);
        
        size_t bufferLength = ciphertext.length;
        uint8_t *buffer = malloc(bufferLength);
        error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
        size_t bytesWritten = 0;
        BOOL bRes = [cipher encryptData:plaintext buffer:buffer bufferSize:bufferLength bytesWritten:&bytesWritten error:&error];
        XCTAssertTrue(bRes);
        XCTAssertNil(error);
        XCTAssertEqual(bytesWritten, bufferLength);
        resultData = [NSData dataWithBytesNoCopy:buffer length:bufferLength freeWhenDone:YES];
        XCTAssertEqualObjects(resultData, ciphertext);
        
        
        // 2. Decryption
        error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
        resultData = [cipher decryptData:ciphertext error:&error];
        XCTAssertNil(error);
        XCTAssertEqualObjects(resultData, plaintext);
        
        bufferLength = plaintext.length;
        buffer = malloc(bufferLength);
        error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
        bytesWritten = 0;
        bRes = [cipher decryptData:ciphertext buffer:buffer bufferSize:bufferLength bytesWritten:&bytesWritten error:&error];
        XCTAssertTrue(bRes);
        XCTAssertNil(error);
        XCTAssertEqual(bytesWritten, bufferLength);
        resultData = [NSData dataWithBytesNoCopy:buffer length:bufferLength freeWhenDone:YES];
        XCTAssertEqualObjects(resultData, plaintext);
    }
}

- (void)testEncryptDecryptZeroBuffer {
    CWAES *cipher = [[CWAES alloc] initWithKeySize:CWAESKeySize128 mode:CWBlockOperationModeCBC];
    NSError *error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
    size_t written = 0;
    BOOL result = [cipher encryptData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] buffer:NULL bufferSize:120 bytesWritten:&written error:&error];
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorZeroBufferProvided);
    XCTAssertFalse(result);
    XCTAssertEqual(written, 0);
    
    uint8_t *buffer = malloc(1);
    result = [cipher encryptData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] buffer:buffer bufferSize:0 bytesWritten:&written error:&error];
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorZeroBufferProvided);
    XCTAssertFalse(result);
    XCTAssertEqual(written, 0);
    
    
    [cipher decryptData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] buffer:NULL bufferSize:120 bytesWritten:&written error:&error];
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorZeroBufferProvided);
    XCTAssertFalse(result);
    XCTAssertEqual(written, 0);
    
    result = [cipher decryptData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] buffer:buffer bufferSize:0 bytesWritten:&written error:&error];
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorZeroBufferProvided);
    XCTAssertFalse(result);
    XCTAssertEqual(written, 0);
    
    free(buffer);
}

@end
