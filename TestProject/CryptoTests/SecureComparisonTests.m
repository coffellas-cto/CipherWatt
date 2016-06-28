//
//  SecureComparisonTests.m
//  Crypto
//
//  Created by Alex on 6/28/16.
//  Copyright © 2016 Alex. All rights reserved.
//

#import <XCTest/XCTest.h>
#include <time.h>
#import "NSData+CipherWatt.h"

@implementation NSData(CipherWattNotSecureRandomness)

+ (NSData *)cw_notSecureRandomDataWithLength:(NSUInteger)length {
    NSMutableData *data=[NSMutableData dataWithLength:length];
    [[NSInputStream inputStreamWithFileAtPath:@"/dev/urandom"] read:(uint8_t *)data.mutableBytes maxLength:length];
    return data.copy;
}

@end

@interface SecureComparisonTests : XCTestCase

@end

@implementation SecureComparisonTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testDifferentLengths {
    XCTAssertFalse([[@"foo" dataUsingEncoding:NSUTF8StringEncoding] cw_isSecurelyEqualToData:[@"fooo" dataUsingEncoding:NSUTF8StringEncoding]]);
    XCTAssertFalse([[@"fooo" dataUsingEncoding:NSUTF8StringEncoding] cw_isSecurelyEqualToData:[@"foo" dataUsingEncoding:NSUTF8StringEncoding]]);
}

- (void)testSame {
    XCTAssertTrue([[@"0123456789" dataUsingEncoding:NSUTF8StringEncoding] cw_isSecurelyEqualToData:[@"0123456789" dataUsingEncoding:NSUTF8StringEncoding]]);
}

- (void)testDifferent {
    XCTAssertFalse([[@"9876543210" dataUsingEncoding:NSUTF8StringEncoding] cw_isSecurelyEqualToData:[@"0123456789" dataUsingEncoding:NSUTF8StringEncoding]]);
}

- (void)testGeneral {
    // This test was held for total 500,000 iterations.
    
    // 1) Arbitrary result for one iteration of simple `isEqualToData:` was:
    // - same data: 0.2337549924850464
    // - diff data: 0.3525829315185547
    // Same data comparison was ~34% faster than different data comparison.
    // The value of `comparisonsAverageDifference` for one 500k iterations test was 0.000360.
    
    // 2) Arbitrary result for `one iteration of cw_notSecureRandomDataWithLength:` was:
    // - same data: 4.474257171154022
    // - diff data: 4.675835132598877
    // The fluctuation is about 0.04%.
    // The value of `comparisonsAverageDifference` for one 500k iterations test was: 0.000084,
    // which is less than that of `isEqualToData:` test by one decimal order.
    // And the difference changes from test to test:
    // Sometimes comparing different data is a bit faster, sometimes vice versa.
    
    // We assume the test has succeeded when same data comparison is not faster than different
    // data comparison with probability more than 0,95.
    // From test to test the fluctuation will differ and must be as close to 0 as possible.
    
    NSUInteger roundsCount = 50;
    NSUInteger comparisonsCount = 1000;
    double comparisonsTotalDifference = 0;
    
    double elapsedTimeForSameDataTotal = 0;
    double elapsedTimeForDifferentDataTotal = 0;
    
    for (NSUInteger r = 0; r < roundsCount; r++) {
        NSTimeInterval elapsedTimeForSameData = 0;
        NSTimeInterval elapsedTimeForDifferentData = 0;
        
        for (NSUInteger i = 0; i < comparisonsCount; i++) {
            NSData *data1 = [NSData cw_notSecureRandomDataWithLength:1200];
            NSData *data2 = data1.copy;
            clock_t t1 = clock();
            [data1 cw_isSecurelyEqualToData:data2];
            elapsedTimeForSameData += (clock() - t1) / (double)CLOCKS_PER_SEC;
        }
        
        for (NSUInteger i = 0; i < comparisonsCount; i++) {
            NSData *data1 = [NSData cw_notSecureRandomDataWithLength:1200];
            NSData *data2 = [NSData cw_notSecureRandomDataWithLength:1200];
            clock_t t1 = clock();
            [data1 cw_isSecurelyEqualToData:data2];
            elapsedTimeForDifferentData += (clock() - t1) / (double)CLOCKS_PER_SEC;
        }
        
        elapsedTimeForSameDataTotal += elapsedTimeForSameData;
        elapsedTimeForDifferentDataTotal += elapsedTimeForDifferentData;
        comparisonsTotalDifference += elapsedTimeForDifferentData - elapsedTimeForSameData;
    }
    
    NSLog(@"\ncomparisonsTotalDifference: %f", comparisonsTotalDifference);
    double comparisonsAverageDifference = (elapsedTimeForDifferentDataTotal - elapsedTimeForSameDataTotal) / (double)roundsCount;
    NSLog(@"\ncomparisonsAverageDifference: %f", comparisonsAverageDifference);
}


@end
