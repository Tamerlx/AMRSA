//
//  AMRSASecurity.h
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/12.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import <Foundation/Foundation.h>

@class AMRSAKey;
typedef void(^AMRSASecurityCallback)(BOOL success, id ret, NSError *error);

NS_ASSUME_NONNULL_BEGIN
@interface AMRSASecurity : NSObject

// encrypt (base64 encode string)
+ (NSString *)encrypt:(NSString *)cleartext pubKey:(AMRSAKey *)pubKey;
+ (NSData *)encryptData:(NSData *)cleardata pubKey:(AMRSAKey *)pubKey;
+ (void)encrypt:(id)clear pubKey:(AMRSAKey *)pubKey completed:(AMRSASecurityCallback)completed;

// decrypt
+ (NSString *)decrypt:(NSString *)ciphertext priKey:(AMRSAKey *)priKey;
+ (NSData *)decryptData:(NSData *)cipherData priKey:(AMRSAKey *)priKey;
+ (void)decrypt:(id)cipher priKey:(AMRSAKey *)priKey completed:(AMRSASecurityCallback)completed;

// sign
+ (NSString *)sign:(NSString *)raw_text priKey:(AMRSAKey *)priKey;
+ (NSData *)signData:(NSData *)raw_data priKey:(AMRSAKey *)priKey;
+ (void)sign:(id)raw priKey:(AMRSAKey *)priKey completed:(AMRSASecurityCallback)completed;

// verify (cooked_text need base64 encode string)
+ (BOOL)verify:(NSString *)cooked_text  rawText:(NSString *)raw_text pubKey:(AMRSAKey *)pubKey;
+ (BOOL)verifyData:(NSData *)cooked_data rawData:(NSData *)raw_data pubKey:(AMRSAKey *)pubKey;
+ (void)verify:(id)cooked raw:(id)raw pubKey:(AMRSAKey *)pubKey completed:(void(^)(BOOL verified, NSError *error))completed;

@end
NS_ASSUME_NONNULL_END
