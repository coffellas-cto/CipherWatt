//
//  CWSecureRandomnessFailer.m
//
//  Created by A. Gordiyenko on 6/20/16.
//  Copyright © 2016 A. Gordiyenko. All rights reserved.
//

#import "CWSecureRandomnessFailer.h"
#import "CWSecureRandomness.h"
#import "CWImplementationReplacer.h"

@implementation CWSecureRandomness (CWSecureRandomnessTests)

- (NSData *)secureRandomDataWithSizeFail:(NSUInteger)size error:(NSError **)error {
    return nil;
}

@end

@interface CWSecureRandomnessFailer ()

@property CWImplementationReplacer *replacer;

@end

@implementation CWSecureRandomnessFailer

- (void)replaceImplementations {
    self.replacer = [[CWImplementationReplacer alloc] initWithClass:[CWSecureRandomness class]];
    [self.replacer replaceImplemenetationForSelector:@selector(secureRandomDataWithSize:error:) withImplementationOfSelector:@selector(secureRandomDataWithSizeFail:error:)];
}

- (void)restoreImplementations {
    [self.replacer restoreImplementations];
    self.replacer = nil;
}

@end
