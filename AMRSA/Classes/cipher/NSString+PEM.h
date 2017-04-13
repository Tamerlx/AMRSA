//
//  NSString+Tabs.h
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/11.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (PEM)

- (NSString *)removeTabs;
- (NSString *)pemKeyDump:(NSString *)aKey start:(NSString *)start end:(NSString *)end;

@end
