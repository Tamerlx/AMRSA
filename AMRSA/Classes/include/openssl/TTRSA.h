//
//  RSA.h
//  OpensslTest
//
//  Created by 刘ToTo on 16/10/12.
//  Copyright © 2016年 com.365ime. All rights reserved.
//

#import <Foundation/Foundation.h>


typedef enum : NSUInteger {
    TTRSAKeyTypePublic = 1,
    TTRSAKeyTypePrivate = 2,
} TTRSAKeyType;

@interface TTRSA : NSObject

- (instancetype)initWithBits:(int)bits privateTag:(NSString*)privateTag publicTag:(NSString *)publicTag NS_DESIGNATED_INITIALIZER;

// sign
- (NSData*)signPKCS1PlainData:(NSData *)plainData;
- (NSData*)signPKCS1SHA1PlainData:(NSData *)plainData;
- (NSData*)signPKCS1SHA256PlainData:(NSData *)plainData;
// verify
- (BOOL)verifyPKCS1SignedData:(NSData *)signedData plainData:(NSData *)plainData;
- (BOOL)verifyPKCS1SHA1SignedData:(NSData *)signedData plainData:(NSData *)plainData;
- (BOOL)verifyPKCS1SHA256SignedData:(NSData *)signedData plainData:(NSData *)plainData;

// encrypt
-(NSString*)encryptPKCS1PlainText:(NSString*)plainText;
// decrypt
- (NSString*)decryptPKCS1CipherText:(NSString*)cipherText;

// reload
- (void)refreshRsaKeyPair;

@property (nonatomic, copy, readonly) NSString *pem_publicKey;
@property (nonatomic, copy, readonly) NSString *pem_privateKey;

#pragma mark - convenient
// sign
+ (NSData*)signPKCS1PrivateTag:(NSString*)privateTag privateKey:(NSString*)privateKey plainData:(NSData *)plainData;
// verify
+ (BOOL)verifyPKCS1PublicTag:(NSString*)publicTag publicKey:(NSString*)publicKey plainData:(NSData *)plainData signedData:(NSData *)signedData;
// encrypt
+ (NSString *)encryptPKCS1PublicTag:(NSString*)publicTag publicKey:(NSString*)publicKey plainText:(NSString *)plainText;
// decrypt
+ (NSString *)decryptPKCS1PrivateTag:(NSString*)privateTag privateKey:(NSString*)privateKey cipherText:(NSString *)cipherText;

@end
