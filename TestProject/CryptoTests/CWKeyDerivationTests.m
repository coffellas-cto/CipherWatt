//
//  CWKeyDerivationTests.m
//
//  Created by A. Gordiyenko on 6/3/16.
//  Copyright © 2016 A. Gordiyenko. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "CWKeyDerivation.h"
#import "CWSecureRandomnessFailer.h"
#import "NSError+CipherWatt.h"

@interface CWKeyDerivationTests : XCTestCase

@end

@implementation CWKeyDerivationTests

- (void)testCreation {
    CWKeyDerivation *keyDerivation = [CWKeyDerivation new];
    XCTAssertNotNil(keyDerivation);
    XCTAssertNil(keyDerivation.PBKDF2Salt);
    XCTAssertEqual(keyDerivation.PBKDF2NumberOfRounds, kCWKeyDerivationDefaultNumberOfRounds);
    XCTAssertEqual(keyDerivation.PBKDF2PseudoRandomAlgorithm, CWPBKDF2PseudoRandomAlgorithmHMACSHA1);
}

- (void)testInvalidDerivation {
    CWKeyDerivation *keyDerivation = [CWKeyDerivation new];
    NSData *data = [keyDerivation deriveKeyDataFromPassword:nil keySize:32 error:nil];
    XCTAssertEqual(keyDerivation.PBKDF2NumberOfRounds, kCWKeyDerivationDefaultNumberOfRounds);
    XCTAssertEqual(keyDerivation.PBKDF2PseudoRandomAlgorithm, CWPBKDF2PseudoRandomAlgorithmHMACSHA1);
    XCTAssertNil(keyDerivation.PBKDF2Salt);
    XCTAssertNil(data);
    
    data = [keyDerivation deriveKeyDataFromPassword:@"" keySize:32 error:nil];
    XCTAssertEqual(keyDerivation.PBKDF2NumberOfRounds, kCWKeyDerivationDefaultNumberOfRounds);
    XCTAssertEqual(keyDerivation.PBKDF2PseudoRandomAlgorithm, CWPBKDF2PseudoRandomAlgorithmHMACSHA1);
    XCTAssertNil(keyDerivation.PBKDF2Salt);
    XCTAssertNil(data);
    
    data = [keyDerivation deriveKeyDataFromPassword:@"cutepass" keySize:0 error:nil];
    XCTAssertEqual(keyDerivation.PBKDF2NumberOfRounds, kCWKeyDerivationDefaultNumberOfRounds);
    XCTAssertEqual(keyDerivation.PBKDF2PseudoRandomAlgorithm, CWPBKDF2PseudoRandomAlgorithmHMACSHA1);
    XCTAssertNil(keyDerivation.PBKDF2Salt);
    XCTAssertNil(data);
    
    keyDerivation.PBKDF2NumberOfRounds = 0;
    data = [keyDerivation deriveKeyDataFromPassword:@"cutepass" keySize:32 error:nil];
    XCTAssertEqual(keyDerivation.PBKDF2NumberOfRounds, 0);
    XCTAssertEqual(keyDerivation.PBKDF2PseudoRandomAlgorithm, CWPBKDF2PseudoRandomAlgorithmHMACSHA1);
    XCTAssertNil(keyDerivation.PBKDF2Salt);
    XCTAssertNil(data);
}

- (void)testDerivationRandomnessFailure {
    CWKeyDerivation *derivation = [CWKeyDerivation new];
    CWSecureRandomnessFailer *failer = [CWSecureRandomnessFailer new];
    [failer replaceImplementations];
    NSError *error = nil;
    NSData *key = [derivation deriveKeyDataFromPassword:@"somepass" keySize:16 error:&error];
    XCTAssertNil(key);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, CWCipherWattErrorKeyDerivationSaltFailure);
    
    [failer restoreImplementations];
}

- (void)testDerivationDefault {
    CWKeyDerivation *keyDerivation = [CWKeyDerivation new];
    NSData *data = [keyDerivation deriveKeyDataFromPassword:@"somePassword" keySize:32 error:nil];
    XCTAssertEqual(keyDerivation.PBKDF2Salt.length, kCWKeyDerivationDefaultSaltSize);
    XCTAssertNotNil(data);
    XCTAssertEqual(data.length, 32);
    XCTAssertEqual(keyDerivation.PBKDF2NumberOfRounds, kCWKeyDerivationDefaultNumberOfRounds);
    XCTAssertEqual(keyDerivation.PBKDF2PseudoRandomAlgorithm, CWPBKDF2PseudoRandomAlgorithmHMACSHA1);
}

- (void)performDerivationWithAlgorithm:(CWPBKDF2PseudoRandomAlgorithm)algorithm expectedKeySize:(NSUInteger)expectedKeySize {
    CWKeyDerivation *keyDerivation = [CWKeyDerivation new];
    keyDerivation.PBKDF2PseudoRandomAlgorithm = algorithm;
    NSData *data = [keyDerivation deriveKeyDataFromPassword:@"shv03ff2hf2h235975237" keySize:expectedKeySize error:nil];
    XCTAssertEqual(keyDerivation.PBKDF2Salt.length, kCWKeyDerivationDefaultSaltSize);
    XCTAssertNotNil(data);
    XCTAssertEqual(data.length, expectedKeySize);
    XCTAssertEqual(keyDerivation.PBKDF2NumberOfRounds, kCWKeyDerivationDefaultNumberOfRounds);
    XCTAssertEqual(keyDerivation.PBKDF2PseudoRandomAlgorithm, algorithm);
}

- (void)testAllKDFAlgorithms {
    [self performDerivationWithAlgorithm:CWPBKDF2PseudoRandomAlgorithmHMACSHA1 expectedKeySize:20];
    [self performDerivationWithAlgorithm:CWPBKDF2PseudoRandomAlgorithmHMACSHA224 expectedKeySize:28];
    [self performDerivationWithAlgorithm:CWPBKDF2PseudoRandomAlgorithmHMACSHA256 expectedKeySize:32];
    [self performDerivationWithAlgorithm:CWPBKDF2PseudoRandomAlgorithmHMACSHA384 expectedKeySize:48];
    [self performDerivationWithAlgorithm:CWPBKDF2PseudoRandomAlgorithmHMACSHA512 expectedKeySize:64];
}

#define PBKDF2_USE_LONG_TEST 0

- (void)testStandardTests {
    // As suggested here: https://tools.ietf.org/html/rfc6070
    
    CWKeyDerivation *keyDerivation = [CWKeyDerivation new];
    
    NSString *password = nil;
    NSString *salt = nil;
    NSUInteger numberOfRounds = 0;
    NSUInteger keyLength = 0;
    
    NSUInteger expectedSaltLength = 0;
    NSData *expectedKeyData = nil;
    
#if PBKDF2_USE_LONG_TEST
    int loop_count = 5;
#else
    int loop_count = 4;
#endif /* PBKDF2_USE_LONG_TEST */
    
    for (int i = 0; i < loop_count; i++) {
        switch (i) {
            case 0:
            {
                /*
                 Input:
                 P = "password" (8 octets)
                 S = "salt" (4 octets)
                 c = 1
                 dkLen = 20
                 
                 Output:
                 DK = 0c 60 c8 0f 96 1f 0e 71
                 f3 a9 b5 24 af 60 12 06
                 2f e0 37 a6             (20 octets)
                 */
                password = @"password";
                salt = @"salt";
                numberOfRounds = 1;
                keyLength = 20;
                expectedSaltLength = 4;
                char bytes[] = {0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6};
                expectedKeyData = [NSData dataWithBytes:bytes length:keyLength];
            }
                break;
            case 1:
            {
                /*
                 Input:
                 P = "password" (8 octets)
                 S = "salt" (4 octets)
                 c = 2
                 dkLen = 20
                 
                 Output:
                 DK = ea 6c 01 4d c7 2d 6f 8c
                 cd 1e d9 2a ce 1d 41 f0
                 d8 de 89 57             (20 octets)
                 */
                password = @"password";
                salt = @"salt";
                numberOfRounds = 2;
                keyLength = 20;
                expectedSaltLength = 4;
                char bytes[] = {0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57};
                expectedKeyData = [NSData dataWithBytes:bytes length:keyLength];
            }
                break;
            case 2:
            {
                /*
                 Input:
                 P = "password" (8 octets)
                 S = "salt" (4 octets)
                 c = 4096
                 dkLen = 20
                 
                 Output:
                 DK = 4b 00 79 01 b7 65 48 9a
                 be ad 49 d9 26 f7 21 d0
                 65 a4 29 c1             (20 octets)
                 */
                password = @"password";
                salt = @"salt";
                numberOfRounds = 4096;
                keyLength = 20;
                expectedSaltLength = 4;
                char bytes[] = {0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1};
                expectedKeyData = [NSData dataWithBytes:bytes length:keyLength];
            }
                break;
            case 3:
            {
                /*
                 Input:
                 P = "passwordPASSWORDpassword" (24 octets)
                 S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
                 c = 4096
                 dkLen = 25
                 
                 Output:
                 DK = 3d 2e ec 4f e4 1c 84 9b
                 80 c8 d8 36 62 c0 e4 4a
                 8b 29 1a 96 4c f2 f0 70
                 38                      (25 octets)
                 */
                password = @"passwordPASSWORDpassword";
                salt = @"saltSALTsaltSALTsaltSALTsaltSALTsalt";
                numberOfRounds = 4096;
                keyLength = 25;
                expectedSaltLength = 36;
                char bytes[] = {0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38};
                expectedKeyData = [NSData dataWithBytes:bytes length:keyLength];
            }
                break;
                
            default:
            {
                // This one is extremely slow due to 16777216 number of rounds.
                
                /*
                 Input:
                 P = "password" (8 octets)
                 S = "salt" (4 octets)
                 c = 16777216
                 dkLen = 20
                 
                 Output:
                 DK = ee fe 3d 61 cd 4d a4 e4
                 e9 94 5b 3d 6b a2 15 8c
                 26 34 e9 84             (20 octets)
                 */
                password = @"password";
                salt = @"salt";
                numberOfRounds = 16777216;
                keyLength = 20;
                expectedSaltLength = 4;
                char bytes[] = {0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4, 0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c, 0x26, 0x34, 0xe9, 0x84};
                expectedKeyData = [NSData dataWithBytes:bytes length:keyLength];
            }
                break;
        }
        
        keyDerivation.PBKDF2NumberOfRounds = numberOfRounds;
        keyDerivation.PBKDF2Salt = [NSData dataWithBytes:[salt cStringUsingEncoding:NSASCIIStringEncoding] length:expectedSaltLength];
        NSError *error = nil;
        NSData *keyData = [keyDerivation deriveKeyDataFromPassword:password keySize:keyLength error:&error];
        XCTAssertNotNil(keyData);
        XCTAssertNil(error);
        XCTAssertEqual(keyDerivation.PBKDF2Salt.length, expectedSaltLength);
        XCTAssertEqualObjects(keyData, expectedKeyData);
    }
    
}

- (void)testCopyParameters {
    CWKeyDerivation *derivation1 = [CWKeyDerivation new];
    derivation1.PBKDF2Salt = [@"doesntmatter" dataUsingEncoding:NSASCIIStringEncoding];
    derivation1.PBKDF2NumberOfRounds = 20;
    derivation1.PBKDF2PseudoRandomAlgorithm = CWPBKDF2PseudoRandomAlgorithmHMACSHA1;
    
    CWKeyDerivation *derivation2 = [CWKeyDerivation new];
    derivation2.PBKDF2Salt = [@"anothermeaninglesssalt" dataUsingEncoding:NSASCIIStringEncoding];
    derivation2.PBKDF2NumberOfRounds = 200;
    derivation2.PBKDF2PseudoRandomAlgorithm = CWPBKDF2PseudoRandomAlgorithmHMACSHA512;
    
    [derivation1 copyParametersFromKeyDerivation:derivation2];
    
    XCTAssertEqual(derivation1.PBKDF2Salt, derivation2.PBKDF2Salt);
    XCTAssertEqual(derivation1.PBKDF2PseudoRandomAlgorithm, derivation2.PBKDF2PseudoRandomAlgorithm);
    XCTAssertEqual(derivation1.PBKDF2NumberOfRounds, derivation2.PBKDF2NumberOfRounds);
    
    [derivation1 copyParametersFromKeyDerivation:nil];
    
    XCTAssertEqual(derivation1.PBKDF2Salt, derivation2.PBKDF2Salt);
    XCTAssertEqual(derivation1.PBKDF2PseudoRandomAlgorithm, derivation2.PBKDF2PseudoRandomAlgorithm);
    XCTAssertEqual(derivation1.PBKDF2NumberOfRounds, derivation2.PBKDF2NumberOfRounds);
}

@end
