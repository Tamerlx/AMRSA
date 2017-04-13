//
//  AMSecKeyRef.m
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/11.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import "AMSecKeyRefConvertor.h"
#import "NSString+PEM.h"

NSString * const kRSAPublicKeyBegin = @"-----BEGIN RSA PUBLIC KEY-----";
NSString * const kRSAPublicKeyEnd = @"-----END RSA PUBLIC KEY-----";
NSString * const kRSAPrivateKeyBegin = @"-----BEGIN RSA PRIVATE KEY-----";
NSString * const kRSAPrivateKeyEnd = @"-----END RSA PRIVATE KEY-----";
NSString * const kPublicKeyBegin = @"-----BEGIN RSA PUBLIC KEY-----";
NSString * const kPublicKeyEnd = @"-----END RSA PUBLIC KEY-----";
NSString * const kPrivateKeyBegin = @"-----BEGIN RSA PRIVATE KEY-----";
NSString * const kPrivateKeyEnd = @"-----END RSA PRIVATE KEY-----";

@implementation AMSecKeyRefConvertor

+ (SecKeyRef)keyRefFromString:(NSString *)keyStr tag:(NSString *)keyTag type:(AMRSAKeyType)type
{
    // This will be base64 encoded, decode it.
    NSData *d_key = [[NSData alloc] initWithBase64EncodedString:keyStr options:0];
    if(d_key == nil) return NULL;
    return [self keyRefFromData:d_key tag:keyTag type:type];
}

+ (SecKeyRef)keyRefFromData:(NSData *)d_key tag:(NSString *)keyTag type:(AMRSAKeyType)type
{
    NSData *d_tag = [NSData dataWithBytes:[keyTag UTF8String] length:[keyTag length]];
    // 1. create config dictionary
    NSMutableDictionary *keyConfig = [[NSMutableDictionary alloc] init];
    [keyConfig setObject:(id) kSecClassKey forKey:(id)kSecClass];
    [keyConfig setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [keyConfig setObject:d_tag forKey:(id)kSecAttrApplicationTag];
    // 2. Delete any old lingering key with the same tag
    OSStatus remove_Status = [self removeKeyRefBy:keyConfig];
    if (remove_Status != errSecSuccess){
        //TODO:- 处理异常
        return NULL;
    }
    
    // 3. modify config dictionary
    id keyClass = (type == AMRSAKeyTypePrivate) ? (id)kSecAttrKeyClassPublic:  (id)kSecAttrKeyClassPrivate;
    [keyConfig setObject:keyClass forKey:(id)kSecAttrKeyClass];
    [keyConfig setObject:d_key forKey:(id)kSecValueData];
    [keyConfig setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnPersistentRef];
    // 4. Add persistent version of the key to system keychain
    OSStatus add_Status = [self addKeyRefBy:keyConfig];
    if (add_Status != errSecSuccess) {
        //TODO:- 处理异常
        return NULL;
    }
    
    // 5. modify config dictionary
    [keyConfig removeObjectForKey:(id)kSecValueData];
    [keyConfig removeObjectForKey:(id)kSecReturnPersistentRef];
    [keyConfig setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
    // 6. copy key by matching keychains
    SecKeyRef keyRef = nil;
    OSStatus matching_Status = [self getKeyRef:keyRef by:keyConfig];
    if(matching_Status != errSecSuccess){
        //TODO:- 处理异常
        return NULL;
    }
    return keyRef;
}

+ (OSStatus)getKeyRef:(SecKeyRef)keyRef by:(NSDictionary *)attrDict
{
    return SecItemCopyMatching((CFDictionaryRef)attrDict, (CFTypeRef *)&keyRef);
}

+ (OSStatus)addKeyRefBy:(NSDictionary *)attrDict
{
    CFTypeRef persistKey = nil;
    OSStatus secStatus = SecItemAdd((CFDictionaryRef)attrDict, &persistKey);
    if (persistKey != nil) CFRelease(persistKey);
    return secStatus;
}

+ (OSStatus)removeKeyRefBy:(NSDictionary *)attrDict
{
    // Delete any old lingering key with the same tag
    return SecItemDelete((CFDictionaryRef)attrDict);
}


@end
