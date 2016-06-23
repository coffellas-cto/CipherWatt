//
//  CWSecureRandomnessFailer.h
//
//  Created by A. Gordiyenko on 6/20/16.
//  Copyright © 2016 A. Gordiyenko. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CWSecureRandomnessFailer : NSObject

- (void)replaceImplementations;
- (void)restoreImplementations;

@end
