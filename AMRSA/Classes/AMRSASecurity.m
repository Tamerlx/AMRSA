//
//  AMRSASecurity.m
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/12.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import "AMRSASecurity.h"
#import "AMRSAKey.h"
#import "AMError.h"

@implementation AMRSASecurity

+ (NSString *)encrypt:(NSString *)cleartext pubKey:(AMRSAKey *)pubKey
{
    NSData *cipher = [self encryptData:[cleartext dataUsingEncoding:NSUTF8StringEncoding] pubKey:pubKey];
    return  [cipher base64EncodedStringWithOptions:0];
}

+ (NSData *)encryptData:(NSData *)cleardata pubKey:(AMRSAKey *)pubKey
{
    __block NSData *cipher_data = nil;
    [self encryptData:cleardata pubKey:pubKey completed:^(BOOL success, id ret, NSError *error) {
        cipher_data = ret;
    }];
    return cipher_data;
}

+ (void)encrypt:(id)clear pubKey:(AMRSAKey *)pubKey completed:(AMRSASecurityCallback)completed
{
    if ([clear isKindOfClass:[NSString class]]) {
        [self encryptData:[clear dataUsingEncoding:NSUTF8StringEncoding] pubKey:pubKey completed:^(BOOL success, id ret, NSError *error) {
            if (completed) {
                if (success) {
                    completed(success,[ret base64EncodedStringWithOptions:0], error);
                }else{
                    completed(success,ret, error);
                }
            }
        }];
    }else if ([clear isKindOfClass:[NSData class]]){
        [self encryptData:clear pubKey:pubKey completed:completed];
    }else{
        completed(NO, nil,[NSError errorWithDomain:am_err_domain(@"encrypt:pubKey:completed:") code:errSecParam userInfo:@{@"errorMessage":@"parameter is invalid",@"errorCode":@(errSecParam)}]);
    }
}

+ (void)encryptData:(NSData *)cleardata pubKey:(AMRSAKey *)pubKey completed:(AMRSASecurityCallback)completed
{
    BOOL success = YES;
    NSError *error =  nil;
    size_t cipherBufferSize = SecKeyGetBlockSize(pubKey.keyRef);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    size_t blockSize = cipherBufferSize - 11;       // 分段加密
    size_t blockCount = (size_t)ceil([cleardata length] / (double)blockSize);
    NSMutableData *encryptedData = [[NSMutableData alloc] init] ;
    for (int i=0; i<blockCount; i++) {
        int bufferSize = (int)MIN(blockSize,[cleardata length] - i * blockSize);
        NSData *buffer = [cleardata subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        OSStatus status = SecKeyEncrypt(pubKey.keyRef, kSecPaddingPKCS1, (const uint8_t *)[buffer bytes], [buffer length], cipherBuffer, &cipherBufferSize);
        if (status != errSecSuccess) {
            success = NO;
            encryptedData = nil;
            error = [NSError errorWithDomain:am_err_domain(@"SecKeyEncrypt") code:errSecSuccess userInfo:@{@"errorMessage":@"SecKeyEncrypt failure",@"errorCode":@(status)}];
            break;
        }
        NSData *encryptedBytes = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
        [encryptedData appendData:encryptedBytes];
    }
    if (cipherBuffer){
        free(cipherBuffer);
    }
    if (completed) {
        completed(success, encryptedData, error);
    }
}

// decrypt
+ (NSString *)decrypt:(NSString *)ciphertext priKey:(AMRSAKey *)priKey
{
    NSData* cipherData = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *clearData = [self decryptData:cipherData priKey:priKey];
    return [NSString stringWithUTF8String:[clearData bytes]];
}

+ (NSData *)decryptData:(NSData *)cipherData priKey:(AMRSAKey *)priKey
{
    __block NSData *clear_data = nil;
    [self decryptData:cipherData priKey:priKey completed:^(BOOL success, id ret, NSError *error) {
        clear_data = ret;
    }];
    return clear_data;
}

+ (void)decrypt:(id)cipher priKey:(AMRSAKey *)priKey completed:(AMRSASecurityCallback)completed
{
    if ([cipher isKindOfClass:[NSString class]]) {
        NSData* cipherData = [[NSData alloc] initWithBase64EncodedString:cipher options:NSDataBase64DecodingIgnoreUnknownCharacters];
        [self decryptData:cipherData priKey:priKey completed:^(BOOL success, id ret, NSError *error) {
            if (completed) {
                if (success) {
                    completed(success,[NSString stringWithUTF8String:[ret bytes]], error);
                }else{
                    completed(success,ret, error);
                }
            }
        }];
    }else if ([cipher isKindOfClass:[NSData class]]){
        [self decryptData:cipher priKey:priKey completed:completed];
    }else{
        completed(NO, nil,[NSError errorWithDomain:am_err_domain(@"decrypt:priKey:completed:") code:errSecParam userInfo:@{@"errorMessage":@"parameter is invalid",@"errorCode":@(errSecParam)}]);
    }
}

+ (void)decryptData:(NSData *)cipherData priKey:(AMRSAKey *)priKey completed:(AMRSASecurityCallback)completed
{
    BOOL success = YES;
    NSError *error =  nil;
    NSData *decryptedData = nil;
    size_t cipherLen = [cipherData length];
    void *cipher = malloc(cipherLen);
    [cipherData getBytes:cipher length:cipherLen];
    size_t plainLen = SecKeyGetBlockSize(priKey.keyRef) - 12;
    void *plain = malloc(plainLen);
    // decrypt
    OSStatus status = SecKeyDecrypt(priKey.keyRef,
                                    kSecPaddingPKCS1,
                                    cipher,
                                    cipherLen,
                                    plain,
                                    &plainLen);
    if (status != errSecSuccess) {
        success = NO;
        decryptedData = nil;
        error = [NSError errorWithDomain:am_err_domain(@"SecKeyDecrypt") code:errSecSuccess userInfo:@{@"errorMessage":@"SecKeyDecrypt failure",@"errorCode":@(status)}];
    }else{
        decryptedData = [[NSData alloc] initWithBytes:(const void *)plain length:plainLen];
    }
    
    if (cipher) {
        free(cipher);
    }
    
    if (completed) {
        completed(success, decryptedData, error);
    }
}

//MARK:- sign
+ (NSString *)sign:(NSString *)raw_text priKey:(AMRSAKey *)priKey
{
    NSData *cooked_data = [self signData:[raw_text dataUsingEncoding:NSUTF8StringEncoding] priKey:priKey];
    return [cooked_data base64EncodedStringWithOptions:0];
}

+ (NSData *)signData:(NSData *)raw_data priKey:(AMRSAKey *)priKey
{
    __block NSData *signed_data = nil;
    [self signData:raw_data priKey:priKey completed:^(BOOL success, id ret, NSError *error) {
        signed_data = ret;
    }];
    return nil;
}

+ (void)sign:(id)raw priKey:(AMRSAKey *)priKey completed:(AMRSASecurityCallback)completed
{
    if ([raw isKindOfClass:[NSString class]]) {
        [self signData:[raw dataUsingEncoding:NSUTF8StringEncoding] priKey:priKey completed:^(BOOL success, id ret, NSError *error) {
            if (completed) {
                if (success) {
                    completed(success,[ret base64EncodedStringWithOptions:0], error);
                }else{
                    completed(success,ret, error);
                }
            }
        }];
    }else if ([raw isKindOfClass:[NSData class]]){
        [self signData:raw priKey:priKey completed:completed];
    }else{
        completed(NO, nil,[NSError errorWithDomain:am_err_domain(@"sign:priKey:completed:") code:errSecParam userInfo:@{@"errorMessage":@"parameter is invalid",@"errorCode":@(errSecParam)}]);
    }
}

+ (void)signData:(NSData *)raw_data priKey:(AMRSAKey *)priKey completed:(AMRSASecurityCallback)completed
{
    BOOL success = YES;
    NSError *error =  nil;
    NSData *signed_data = nil;
    
    // get will be signed data by privateKey size
    size_t signedHashBytesSize = SecKeyGetBlockSize(priKey.keyRef);
    // allocate memry
    uint8_t *signedHashBytes = malloc(signedHashBytesSize);
    // initializ signedHashBytes memry
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    // sign
    OSStatus status = SecKeyRawSign(priKey.keyRef,
                                    kSecPaddingPKCS1,
                                    [raw_data bytes],
                                    CC_SHA1_DIGEST_LENGTH,
                                    signedHashBytes,
                                    &signedHashBytesSize);
    if (status != errSecSuccess) {
        success = NO;
        signed_data = nil;
        error = [NSError errorWithDomain:am_err_domain(@"SecKeyRawSign") code:errSecSuccess userInfo:@{@"errorMessage":@"SecKeyRawSign failure",@"errorCode":@(status)}];
    }else{
        signed_data = [NSData dataWithBytes:signedHashBytes length:(NSUInteger)signedHashBytesSize];
    }
    
    // release unuseable C object
    if (signedHashBytes){
        free(signedHashBytes);
    }
    
    if (completed) {
        completed(success, signed_data, error);
    }
}

//MARK:- verify
// verify (base64 encode string)
+ (BOOL)verify:(NSString *)cooked_text  rawText:(NSString *)raw_text pubKey:(AMRSAKey *)pubKey
{
    __block BOOL a_verified = NO;
    NSData* cooked_data = [[NSData alloc] initWithBase64EncodedString:cooked_text options:NSDataBase64DecodingIgnoreUnknownCharacters];
    [self verifyData:cooked_data rawData:[raw_text dataUsingEncoding:NSUTF8StringEncoding] pubKey:pubKey completed:^(BOOL verified, NSError *error) {
        a_verified = verified;
    }];
    return a_verified;
}

+ (BOOL)verifyData:(NSData *)cooked_data rawData:(NSData *)raw_data pubKey:(AMRSAKey *)pubKey
{
    __block BOOL a_verified = NO;
    [self verifyData:cooked_data rawData:raw_data pubKey:pubKey completed:^(BOOL verified, NSError *error) {
        a_verified = verified;
    }];
    return a_verified;
}

+ (void)verify:(id)cooked raw:(id)raw pubKey:(AMRSAKey *)pubKey completed:(void(^)(BOOL verified, NSError *error))completed
{
    if ([cooked isKindOfClass:[NSString class]] && [raw isKindOfClass:[NSString class]]) {
        NSData* cooked_data = [[NSData alloc] initWithBase64EncodedString:cooked options:NSDataBase64DecodingIgnoreUnknownCharacters];
        [self verifyData:cooked_data rawData:[raw dataUsingEncoding:NSUTF8StringEncoding] pubKey:pubKey completed:^(BOOL verified, NSError *error) {
            if (completed) {
                completed(verified, error);
            }
        }];
    }else if ([cooked isKindOfClass:[NSData class]] && [raw isKindOfClass:[NSData class]]){
        [self verifyData:cooked rawData:raw pubKey:pubKey completed:completed];
    }else{
        completed(NO,[NSError errorWithDomain:am_err_domain(@"verify:raw:pubKey:completed:") code:errSecParam userInfo:@{@"errorMessage":@"parameter is invalid",@"errorCode":@(errSecParam)}]);
    }
}

+ (void)verifyData:(NSData *)cooked_data rawData:(NSData *)raw_data pubKey:(AMRSAKey *)pubKey completed:(void(^)(BOOL verified, NSError *error))completed
{
    BOOL verified = YES;
    NSError *error =  nil;
    
    // get signed data bytes Size by public key
    size_t signedHashBytesSize = SecKeyGetBlockSize(pubKey.keyRef);
    // signed data to bytes
    const void* signedHashBytes = [cooked_data bytes];
    
    // verify
    OSStatus status = SecKeyRawVerify(pubKey.keyRef,
                                      kSecPaddingPKCS1,
                                      [raw_data bytes],
                                      CC_SHA1_DIGEST_LENGTH,
                                      signedHashBytes,
                                      signedHashBytesSize);
    if (status != errSecSuccess) {
        verified = NO;
        error = [NSError errorWithDomain:am_err_domain(@"SecKeyRawVerify") code:errSecSuccess userInfo:@{@"errorMessage":@"SecKeyRawVerify failure",@"errorCode":@(status)}];
    }
    if (completed) {
        completed(verified, error);
    }
}

@end
