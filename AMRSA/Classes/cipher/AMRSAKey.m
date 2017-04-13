//
//  AMRSAKey.m
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/8.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import "AMRSAKey.h"


@interface AMRSAKey ()

@end
@implementation AMRSAKey

- (instancetype)initWithSecKeyRef:(SecKeyRef)keyRef text:(NSString *)text tag:(nullable NSString *)keyTag formatter:(AMRSAKeyFormat)format type:(AMRSAKeyType)type
{
    if (self = [super init]) {
        _keyRef = keyRef;
        _keyText = text;
        _keyTag = keyTag;
        _format = format;
        _type = type;
    }
    return self;
}

@end
