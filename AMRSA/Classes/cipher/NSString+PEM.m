//
//  NSString+Tabs.m
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/11.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import "NSString+PEM.h"

@implementation NSString (PEM)

- (NSString *)removeTabs
{
    NSString *clear = [self copy];
    clear = [clear stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    clear = [clear stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    clear = [clear stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    clear = [clear stringByReplacingOccurrencesOfString:@" "  withString:@""];
    return clear;
}

- (NSString *)pemKeyDump:(NSString *)aKey start:(NSString *)start end:(NSString *)end
{
    NSString *pemKey = [aKey copy];
    NSRange spos_rsa = [pemKey rangeOfString:start];
    NSRange epos_rsa = [pemKey rangeOfString:end];
    if(spos_rsa.location != NSNotFound && epos_rsa.location != NSNotFound){
        NSUInteger s = spos_rsa.location + spos_rsa.length;
        NSUInteger e = epos_rsa.location;
        NSRange range = NSMakeRange(s, e-s);
        pemKey = [pemKey substringWithRange:range];
        return [pemKey removeTabs];
    }
    return nil;
}

@end
