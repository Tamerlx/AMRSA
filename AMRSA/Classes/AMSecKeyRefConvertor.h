//
//  AMSecKeyRef.h
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/11.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import "AMRSAKey.h"

extern NSString * const kRSAPublicKeyBegin;
extern NSString * const kRSAPublicKeyEnd;
extern NSString * const kRSAPrivateKeyBegin;
extern NSString * const kRSAPrivateKeyEnd;
extern NSString * const kPublicKeyBegin;
extern NSString * const kPublicKeyEnd;
extern NSString * const kPrivateKeyBegin;
extern NSString * const kPrivateKeyEnd;

@interface AMSecKeyRefConvertor : NSObject

+ (SecKeyRef)keyRefFromString:(NSString *)keyStr tag:(NSString *)keyTag type:(AMRSAKeyType)type;
+ (SecKeyRef)keyRefFromData:(NSData *)d_key tag:(NSString *)keyTag type:(AMRSAKeyType)type;

@end
