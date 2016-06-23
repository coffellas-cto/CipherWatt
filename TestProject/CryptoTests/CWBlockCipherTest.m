//
//  CWBlockCipherTest.m
//  Crypto
//
//  Created by Alex on 6/23/16.
//  Copyright © 2016 Alex. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "CWBlockCipher.h"

@interface CWBlockCipherTest : XCTestCase

@end

@implementation CWBlockCipherTest

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testInstantiating {
    CWBlockCipher *cipher = nil;
    XCTAssertThrowsSpecificNamed(cipher = [[CWBlockCipher alloc] initWithMode:CWBlockOperationModeCBC], NSException, NSInternalInconsistencyException);
    XCTAssertNil(cipher);
    
    XCTAssertThrowsSpecificNamed(cipher = [CWBlockCipher new], NSException, NSInternalInconsistencyException);
    XCTAssertNil(cipher);
}

@end
