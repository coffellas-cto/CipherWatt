//
//  CWImplementationReplacer.h
//
//  Created by A. Gordiyenko on 6/20/16.
//  Copyright © 2016 A. Gordiyenko. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CWImplementationReplacer : NSObject

- (void)replaceImplemenetationForSelector:(SEL)originalSel withImplementationOfSelector:(SEL)newSel;
- (void)restoreImplementations;
- (instancetype)initWithClass:(Class)class;

@end
