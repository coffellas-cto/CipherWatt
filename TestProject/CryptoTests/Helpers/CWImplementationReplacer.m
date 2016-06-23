//
//  CWImplementationReplacer.m
//
//  Created by A. Gordiyenko on 6/20/16.
//  Copyright © 2016 A. Gordiyenko. All rights reserved.
//

#import "CWImplementationReplacer.h"
#import <objc/objc-runtime.h>

@interface CWImplementationReplacer () {
    IMP _originalImplementation;
    Method _originalMethod;
    Class _class;
}

@end

@implementation CWImplementationReplacer

- (void)replaceImplemenetationForSelector:(SEL)originalSel withImplementationOfSelector:(SEL)newSel {
    _originalMethod = class_getInstanceMethod(_class, originalSel);
    Method replacedMethod = class_getInstanceMethod(_class, newSel);
    IMP replacedImplementation = method_getImplementation(replacedMethod);
    _originalImplementation = method_setImplementation(_originalMethod, replacedImplementation);
}

- (void)restoreImplementations {
    method_setImplementation(_originalMethod, _originalImplementation);
}

- (instancetype)initWithClass:(Class)class {
    self = [super init];
    if (self) {
        _class = class;
    }
    return self;
}

@end
