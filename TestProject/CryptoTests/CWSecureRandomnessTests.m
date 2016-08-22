//
//  CWSecureRandomnessTests.m
//
//  Created by A. Gordiyenko on 6/20/16.
//  Copyright © 2016 A. Gordiyenko. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "CWSecureRandomness.h"
#import "CWSecureRandomnessFailer.h"

@interface CWSecureRandomnessTests : XCTestCase

@end

@implementation CWSecureRandomnessTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSecureRandom {
    NSData *randomData = [CWSecureRandomness secureRandomDataWithSize:8 error:nil];
    XCTAssertEqual(randomData.length, 8);
    
    randomData = [CWSecureRandomness secureRandomDataWithSize:0 error:nil];
    XCTAssertNil(randomData);
}

- (void)testSecureRandomFailure {
    CWSecureRandomnessFailer *failer = [CWSecureRandomnessFailer new];
    [failer replaceImplementations];
    
    NSData *randomData = [CWSecureRandomness secureRandomDataWithSize:8 error:nil];
    XCTAssertNil(randomData);
    
    [failer restoreImplementations];
    
    randomData = [CWSecureRandomness secureRandomDataWithSize:8 error:nil];
    XCTAssertEqual(randomData.length, 8);
}

@end
