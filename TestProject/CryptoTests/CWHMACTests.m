//
//  CWHMACTests.m
//  Crypto
//
//  Created by Alex on 6/28/16.
//  Copyright © 2016 Alex. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "CWHMAC.h"

@interface CWHMACTests : XCTestCase

@end

@implementation CWHMACTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testCreation {
    CWHMAC *mac = [CWHMAC new];
    XCTAssertNotNil(mac);
    XCTAssertEqual(mac.algorithm, CWHMACAlgorithmSHA224);
}

- (void)testZeroKey {
    CWHMAC *mac = [CWHMAC new];
    NSData *result1 = [mac computeMACForData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] keyData:nil error:nil];
    XCTAssertNotNil(result1);
    char zero_key[24] = {0};
    NSData *zeroKeyData = [NSData dataWithBytes:zero_key length:24];
    NSData *result2 = [mac computeMACForData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] keyData:zeroKeyData error:nil];
    XCTAssertEqualObjects(result1, result2);
}

- (void)testZeroData {
    CWHMAC *mac = [CWHMAC new];
    NSData *result1 = [mac computeMACForData:nil keyData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] error:nil];
    XCTAssertNotNil(result1);
}

- (void)testHMACVectors {
    // Test vectors taken from https://tools.ietf.org/html/rfc4231
    
    NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"HMACVectors" ofType:@"plist"];
    XCTAssertNotNil(path);
    NSArray *testVector = [NSArray arrayWithContentsOfFile:path];
    XCTAssertNotNil(testVector);
    
    for (int i = 0; i < testVector.count; i++) {
        NSDictionary *testDic = testVector[i];
        
        NSData *key = testDic[@"Key"];
        NSData *data = testDic[@"Data"];
        NSData *SHA224Data = testDic[@"HMAC-SHA-224"];
        NSData *SHA256Data = testDic[@"HMAC-SHA-256"];
        NSData *SHA384Data = testDic[@"HMAC-SHA-384"];
        NSData *SHA512Data = testDic[@"HMAC-SHA-512"];
        XCTAssertNotNil(key);
        XCTAssertNotNil(data);
        XCTAssertNotNil(SHA224Data);
        XCTAssertNotNil(SHA256Data);
        XCTAssertNotNil(SHA384Data);
        XCTAssertNotNil(SHA512Data);
        
        CWHMAC *mac = [CWHMAC new];
        CWHMACAlgorithm algo = CWHMACAlgorithmMD5;
        NSData *dataToCheck = nil;
        for (int j = 0; j < 4; j++) {
            switch (j) {
                case 0:
                    algo = CWHMACAlgorithmSHA224;
                    dataToCheck = SHA224Data;
                    break;
                case 1:
                    algo = CWHMACAlgorithmSHA256;
                    dataToCheck = SHA256Data;
                    break;
                case 2:
                    algo = CWHMACAlgorithmSHA384;
                    dataToCheck = SHA384Data;
                    break;
                case 3:
                    algo = CWHMACAlgorithmSHA512;
                    dataToCheck = SHA512Data;
                    break;
                    
                default:
                    break;
            }
            
            mac.algorithm = algo;
            NSError *error = [NSError errorWithDomain:@"" code:-1000 userInfo:nil];
            NSData *computedHMAC = [mac computeMACForData:data keyData:key error:&error];
            if (i == 4) {
                // Test with a truncation of output to 128 bits.
                computedHMAC = [computedHMAC subdataWithRange:NSMakeRange(0, 16)];
            }
            
            XCTAssertNil(error);
            XCTAssertEqualObjects(computedHMAC, dataToCheck);
        }
    }
}

- (void)testMD5 {
    CWHMAC *mac = [[CWHMAC alloc] initWithAlgorithm:CWHMACAlgorithmMD5];
    NSData *result = [mac computeMACForData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] keyData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] error:nil];
    XCTAssertNotNil(result);
}

- (void)testSHA1 {
    CWHMAC *mac = [[CWHMAC alloc] initWithAlgorithm:CWHMACAlgorithmSHA1];
    NSData *result = [mac computeMACForData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] keyData:[@"somedata" dataUsingEncoding:NSASCIIStringEncoding] error:nil];
    XCTAssertNotNil(result);
}

@end
