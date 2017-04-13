//
//  AMRSAKeyFactory.m
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/11.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import "AMRSAKeyFactory.h"
#import "AMSecKeyRefConvertor.h"
#import "NSString+PEM.h"

@implementation AMRSAKeyFactory

- (AMRSAKey *)keyByKeyRef:(SecKeyRef)keyRef tag:(nullable NSString *)tag format:(AMRSAKeyFormat)format type:(AMRSAKeyType)type
{
    AMRSAKey *key = [[AMRSAKey alloc] initWithSecKeyRef:keyRef text:@"" tag:tag formatter:format type:type];
    return key;
}

- (AMRSAKey *)keyByData:(NSData *)data tag:(nullable NSString *)tag format:(AMRSAKeyFormat)format type:(AMRSAKeyType)type
{
    SecKeyRef keyRef = [AMSecKeyRefConvertor keyRefFromData:data tag:tag type:type];
    AMRSAKey *key = [[AMRSAKey alloc] initWithSecKeyRef:keyRef text:[NSString string] tag:tag formatter:format type:type];
    return key;
}

- (AMRSAKey *)keyByText:(NSString *)text tag:(nullable NSString *)tag format:(AMRSAKeyFormat)format type:(AMRSAKeyType)type
{
    if (format == AMRSAKeyFormatPEM) {
        
    }
    SecKeyRef keyRef = [AMSecKeyRefConvertor keyRefFromString:text tag:tag type:type];
    AMRSAKey *key = [[AMRSAKey alloc] initWithSecKeyRef:keyRef text:text tag:tag formatter:format type:type];
    return key;
}

+ (NSString *)pemPublicKeyDump:(NSString *)aKey
{
    NSString *ret = nil;
    ret = [aKey pemKeyDump:aKey start:kRSAPublicKeyBegin end:kRSAPublicKeyEnd];
    if (ret.length >0) {
        return aKey;
    }
    ret = [aKey pemKeyDump:aKey start:kPublicKeyBegin end:kPublicKeyEnd];
    return ret.length >0 ? ret : aKey;
}

+ (NSString *)pemPrivateKeyDump:(NSString *)aKey
{
    NSString *ret = nil;
    ret = [aKey pemKeyDump:aKey start:kRSAPrivateKeyBegin end:kRSAPrivateKeyEnd];
    if (ret.length >0) {
        return aKey;
    }
    ret = [aKey pemKeyDump:aKey start:kPrivateKeyBegin end:kPrivateKeyEnd];
    return ret.length >0 ? ret : aKey;
}


@end
