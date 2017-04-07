//
//  RSA.m
//  OpensslTest
//
//  Created by 刘ToTo on 16/10/12.
//  Copyright © 2016年 com.365ime. All rights reserved.
//

#import "TTRSA.h"
#include "openssl/pem.h"
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#import <CommonCrypto/CommonCrypto.h>


#define kPublicKeyBegin @"-----BEGIN RSA PUBLIC KEY-----"
#define kPublicKeyEnd @"-----END RSA PUBLIC KEY-----"
#define kPrivateKeyBegin @"-----BEGIN RSA PRIVATE KEY-----"
#define kPrivateKeyEnd @"-----END RSA PRIVATE KEY-----"

@interface TTRSA (){
    RSA *_keyPair;
    int _bits;
    NSString *_publicTag;
    NSString *_privateTag;
}

@end
@implementation TTRSA{
    unsigned char *pri_key;
    unsigned char *pub_key;
    SecKeyRef publicSeckeyRef;
    SecKeyRef privateSecKeyRef;
}

#pragma mark - initialization
- (instancetype)initWithBits:(int)bits privateTag:(NSString*)privateTag publicTag:(NSString *)publicTag{
    if (self = [super init]) {
        _bits = bits;
        _publicTag = publicTag;
        _privateTag = privateTag;
        [self generateRsaKeypair:_bits];
    }
    return self;
}

- (instancetype)init{
    return [self initWithBits:2048 privateTag:@"TTRSA_PRIVATE_TAG" publicTag:@"TTRSA_PUBLIC_TAG"];
}

- (void)refreshRsaKeyPair{
    [self generateRsaKeypair:_bits];
}

#pragma mark - generate
- (void)generateRsaKeypair:(int)bits{
    
    int ret;
    unsigned int e = RSA_F4;
    BIGNUM *bne;
    bne = BN_new();
    ret = BN_set_word(bne, e);
    _keyPair = RSA_new();
    
    // generate key pair
    int result = RSA_generate_key_ex(_keyPair, bits,bne, NULL);
    if (result !=1) {
        char buffer[500];
        ERR_error_string(ERR_get_error(), buffer);
        NSLog(@"%@",[NSString stringWithUTF8String:buffer]);
    }
    
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());
    
    PEM_write_bio_RSAPrivateKey(pri, _keyPair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, _keyPair);
    
    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);
    
    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);
    
    BIO_read(pri, pri_key, (int) pri_len);
    BIO_read(pub, pub_key, (int) pub_len);
    
    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    
    
    _pem_publicKey = [[NSString alloc] initWithCString:(const char*)pub_key encoding:NSUTF8StringEncoding];
    _pem_privateKey = [[NSString alloc] initWithCString:(const char*)pri_key encoding:NSUTF8StringEncoding];
    
}

#pragma mark - create key
- (SecKeyRef)createRsaKey:(NSString *)keyStr rsaKeyType:(TTRSAKeyType)keyType{
    
    NSString *s_key = [NSString string];
    NSArray  *a_key = [keyStr componentsSeparatedByString:@"\n"];
    BOOL     f_key  = FALSE;
    
    for (NSString *a_line in a_key) {
        if ([a_line isEqualToString:[self symbol4Begin:keyType]]) {
            f_key = TRUE;
        }
        else if ([a_line isEqualToString:[self symbol4End:keyType]]) {
            f_key = FALSE;
        }else if (f_key) {
            s_key = [s_key stringByAppendingString:a_line];
        }
    }
    if (s_key.length == 0) return NULL;
    
    return createRsaKey(s_key,[self tagString4SecKey:keyType],[self secAttrKeyClass:keyType]);
//    
//    NSString *s_key = [NSString string];
//    NSArray  *a_key = [keyStr componentsSeparatedByString:@"\n"];
//    BOOL     f_key  = FALSE;
//    
//    for (NSString *a_line in a_key) {
//        if ([a_line isEqualToString:[self symbol4Begin:keyType]]) {
//            f_key = TRUE;
//        }
//        else if ([a_line isEqualToString:[self symbol4End:keyType]]) {
//            f_key = FALSE;
//        }else if (f_key) {
//            s_key = [s_key stringByAppendingString:a_line];
//        }
//    }
//    if (s_key.length == 0) return NULL;
//    
//    // This will be base64 encoded, decode it.
//    NSData *d_key = [[NSData alloc] initWithBase64EncodedString:s_key options:0];
//    if(d_key == nil) return NULL;
//    
//    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
//    
//    // Delete any old lingering key with the same tag
//    NSMutableDictionary *keyConfig = [[NSMutableDictionary alloc] init];
//    [keyConfig setObject:(id) kSecClassKey forKey:(id)kSecClass];
//    [keyConfig setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
//    [keyConfig setObject:d_tag forKey:(id)kSecAttrApplicationTag];
//    SecItemDelete((CFDictionaryRef)keyConfig);
//    
//    CFTypeRef persistKey = nil;
//    
//    // Add persistent version of the key to system keychain
//    [keyConfig setObject:d_key forKey:(id)kSecValueData];
//    [keyConfig setObject:[self secAttrKeyClass:keyType] forKey:(id)
//     kSecAttrKeyClass];
//    [keyConfig setObject:[NSNumber numberWithBool:YES] forKey:(id)
//     kSecReturnPersistentRef];
//    
//    OSStatus secStatus = SecItemAdd((CFDictionaryRef)keyConfig, &persistKey);
//    if (persistKey != nil) CFRelease(persistKey);
//    
//    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem)) {
//        //        [privateKey release];
//        return NULL;
//    }
//    
//    // Now fetch the SecKeyRef version of the key
//    SecKeyRef keyRef = nil;
//    
//    [keyConfig removeObjectForKey:(id)kSecValueData];
//    [keyConfig removeObjectForKey:(id)kSecReturnPersistentRef];
//    [keyConfig setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
//    secStatus = SecItemCopyMatching((CFDictionaryRef)keyConfig,
//                                    (CFTypeRef *)&keyRef);
//    
//    if(secStatus != noErr)
//        return NULL;
//    return keyRef;
}

#pragma mark - sign
- (NSData*)signPKCS1PlainData:(NSData *)plainData{
    
    [self loadPrivateKey];
    
    // set plain data size by CC_SHA1_DIGEST_LENGTH
    size_t plainhashBytesSize = CC_SHA1_DIGEST_LENGTH;
    
    return secKeySignByPrivateKey(privateSecKeyRef, plainData, plainhashBytesSize,kSecPaddingPKCS1);
}

- (NSData*)signPKCS1SHA1PlainData:(NSData *)plainData{
    
    [self loadPrivateKey];
    
    // set plain data size by CC_SHA1_DIGEST_LENGTH
    size_t plainhashBytesSize = CC_SHA1_DIGEST_LENGTH;
    // create plainSha1Bytes
    uint8_t *plainSha1Bytes = malloc(CC_SHA1_DIGEST_LENGTH);
    // plainData to plain sha1 Bytes
    unsigned char *status =CC_SHA1([plainData bytes], (CC_LONG)[plainData length], plainSha1Bytes);
    NSAssert(status != NULL,@"plain data fail encrypt by sha1! Method: -[TTRSA signPKCS1SHA1ByPrivateKey]");
    //  plain sha1 Bytes to plain sha1 data
    NSData *plainSha1Data = [NSData dataWithBytes:plainSha1Bytes
                                           length:(NSUInteger)plainhashBytesSize];
    // sign
    return secKeySignByPrivateKey(privateSecKeyRef, plainSha1Data, plainhashBytesSize, kSecPaddingPKCS1SHA1);
}

- (NSData*)signPKCS1SHA256PlainData:(NSData *)plainData{
    
    [self loadPrivateKey];
    
    // set plain data size by CC_SHA256_DIGEST_LENGTH
    size_t plainhashBytesSize = CC_SHA256_DIGEST_LENGTH;
    // create plainSha256Bytes
    uint8_t *plainSha256Bytes = malloc(CC_SHA256_DIGEST_LENGTH);
    // plainData to plain sha256 Bytes
    unsigned char *status =CC_SHA256([plainData bytes], (CC_LONG)[plainData length], plainSha256Bytes);
    NSAssert(status != NULL,@"plain data fail encrypt by sha1! Method: -[TTRSA signPKCS1SHA1ByPrivateKey]");
    //  plain sha256 Bytes to plain sha256 data
    NSData *plainSha1Data = [NSData dataWithBytes:plainSha256Bytes
                                           length:(NSUInteger)plainhashBytesSize];
    // sign
    return secKeySignByPrivateKey(privateSecKeyRef, plainSha1Data, plainhashBytesSize, kSecPaddingPKCS1SHA256);
}

//- (NSData *)secKeySignByPrivateKey:(SecKeyRef)privateKey plainData:(NSData *)plainData plainHashBytesSize:(size_t)plainBytesSize secPadding:(SecPadding)secPadding{
//    
//    // get will be signed data by privateKey size
//    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
//    // allocate memry
//    uint8_t *signedHashBytes = malloc(signedHashBytesSize);
//    // initializ signedHashBytes memry
//    memset(signedHashBytes, 0x0, signedHashBytesSize);
//    
//    // sign
//    OSStatus status = SecKeyRawSign(privateKey,
//                                    secPadding,
//                                    [plainData bytes],
//                                    plainBytesSize,
//                                    signedHashBytes,
//                                    &signedHashBytesSize);
//    if (status!=0) {
//        char buffer[512];
//        ERR_error_string(ERR_get_error(), buffer);
//    }
//    
//    // convert signedBytes to NSData
//    NSData *signedData = [NSData dataWithBytes:signedHashBytes
//                                        length:(NSUInteger)signedHashBytesSize];
//    // release unuseable C object
//    if (signedHashBytes)
//        free(signedHashBytes);
//    
//    return signedData;
//}

#pragma mark - verify
- (BOOL)verifyPKCS1SignedData:(NSData *)signedData plainData:(NSData *)plainData{
    
    [self loadPublicKey];
    
    size_t plainBytesSize = CC_SHA1_DIGEST_LENGTH;
    
    // verify
    return secKeyVerifyByPublicKey(publicSeckeyRef, signedData, plainData, plainBytesSize, kSecPaddingPKCS1);
}

- (BOOL)verifyPKCS1SHA1SignedData:(NSData *)signedData plainData:(NSData *)plainData{
    
    [self loadPublicKey];
    
    // get plainSha1BytesSize
    size_t plainSha1BytesSize = CC_SHA1_DIGEST_LENGTH;
    // create plainSha1Bytes
    uint8_t* plainSha1Bytes = malloc(plainSha1BytesSize);
    //  plainBytes to plainSha1Bytes
    unsigned char *status = CC_SHA1([plainData bytes], (CC_LONG)[plainData length], plainSha1Bytes);
    NSAssert(status != NULL,@"plain data fail encrypt by sha1! Method: -[TTRSA verifyPKCS1SHA1ByPublicKey:]");
    
    // get plainSha1Data from plainSha1Bytes
    NSData *plainSha1Data = [NSData dataWithBytes:plainSha1Bytes
                                           length:(NSUInteger)plainSha1BytesSize];;
    
    // verify
    return secKeyVerifyByPublicKey(publicSeckeyRef, signedData, plainSha1Data, plainSha1BytesSize, kSecPaddingPKCS1SHA1);
}

- (BOOL)verifyPKCS1SHA256SignedData:(NSData *)signedData plainData:(NSData *)plainData{
    
    [self loadPublicKey];
    
    // get plainSha1BytesSize
    size_t plainSha256BytesSize = CC_SHA256_DIGEST_LENGTH;
    // create plainSha1Bytes
    uint8_t* plainSha256Bytes = malloc(plainSha256BytesSize);
    //  plainBytes to plainSha1Bytes
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], plainSha256Bytes)) {
        return nil;
    }
    // get plainSha1Data from plainSha1Bytes
    NSData *plainSha256Data = [NSData dataWithBytes:plainSha256Bytes
                                             length:(NSUInteger)plainSha256BytesSize];;
    
    // verify
    return secKeyVerifyByPublicKey(publicSeckeyRef, signedData, plainSha256Data, plainSha256BytesSize, kSecPaddingPKCS1SHA256);
}

//- (BOOL)secKeyVerifyByPublicKey:(SecKeyRef)publicKey signedData:(NSData *)signedData plainData:(NSData *)plainData plainHashBytesSize:(size_t)plainBytesSize secPadding:(SecPadding)secPadding{
//    
//    // get signed data bytes Size by public key
//    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
//    // signed data to bytes
//    const void* signedHashBytes = [signedData bytes];
//    
//    // verify
//    OSStatus status = SecKeyRawVerify(publicKey,
//                                      secPadding,
//                                      [plainData bytes],
//                                      plainBytesSize,
//                                      signedHashBytes,
//                                      signedHashBytesSize);
//    if (status != 0) {
//        char buffer[512];
//        ERR_error_string(ERR_get_error(), buffer);
//    }
//    
//    return (status == 0);
//}

#pragma mark - encrypt
- (NSString*)encryptPKCS1PlainText:(NSString*)plainText{
    
    [self loadPublicKey];
    
    NSData* plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData* encryptedData = secEncryptByPublicKey(publicSeckeyRef,plainData, kSecPaddingPKCS1);
    
    NSString* base64EncryptedString = [encryptedData base64EncodedStringWithOptions:0];
    
    return base64EncryptedString;
}

//// 加密的大小受限于SecKeyEncrypt函数，SecKeyEncrypt要求明文和密钥的长度一致，如果要加密更长的内容，需要把内容按密钥长度分成多份，然后多次调用SecKeyEncrypt来实现
//- (NSData*)secEncryptByPublicKey:(SecKeyRef)publicKey plainData:(NSData*)plainData secPadding:(SecPadding)secPadding{
//    
//    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
//    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
//    size_t blockSize = cipherBufferSize - 11;       // 分段加密
//    size_t blockCount = (size_t)ceil([plainData length] / (double)blockSize);
//    NSMutableData *encryptedData = [[NSMutableData alloc] init] ;
//    for (int i=0; i<blockCount; i++) {
//        int bufferSize = (int)MIN(blockSize,[plainData length] - i * blockSize);
//        NSData *buffer = [plainData subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
//        OSStatus status = SecKeyEncrypt(publicKey, secPadding, (const uint8_t *)[buffer bytes], [buffer length], cipherBuffer, &cipherBufferSize);
//        if (status == noErr){
//            NSData *encryptedBytes = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
//            [encryptedData appendData:encryptedBytes];
//        }else{
//            if (cipherBuffer) {
//                free(cipherBuffer);
//            }
//            char buffer[512];
//            ERR_error_string_n(ERR_get_error(), buffer, 512);
//            return nil;
//        }
//    }
//    
//    if (cipherBuffer){
//        free(cipherBuffer);
//    }
//    
//    return encryptedData;
//}

#pragma mark - Decrypt
- (NSString*)decryptPKCS1CipherText:(NSString*)cipherText{
    
    [self loadPrivateKey];
    
    NSData* cipherData = [[NSData alloc] initWithBase64EncodedString:cipherText options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    NSData* decryptData = secDecryptByPrivateKey(privateSecKeyRef, cipherData,kSecPaddingPKCS1);
    
    NSString* result = [[NSString alloc] initWithData: decryptData encoding:NSUTF8StringEncoding];
    return result;
}

//- (NSData*)secDecryptByPrivateKey:(SecKeyRef)privateKey cipherData:(NSData*)cipherData secPadding:(SecPadding)secPadding{
//    
//    size_t cipherLen = [cipherData length];
//    void *cipher = malloc(cipherLen);
//    [cipherData getBytes:cipher length:cipherLen];
//    size_t plainLen = SecKeyGetBlockSize(privateKey) - 12;
//    void *plain = malloc(plainLen);
//    
//    // decrypt
//    OSStatus status = SecKeyDecrypt(privateKey, secPadding, cipher, cipherLen, plain, &plainLen);
//    
//    if (status != noErr) {
//        char buffer[512];
//        ERR_error_string(ERR_get_error(), buffer);
//        
//        return nil;
//    }
//    
//    NSData *decryptedData = [[NSData alloc] initWithBytes:(const void *)plain length:plainLen];
//    
//    return decryptedData;
//}

#pragma mark - converter
- (NSString *)tagString4SecKey:(TTRSAKeyType)type{
    return type == TTRSAKeyTypePublic ? _publicTag : _privateTag;
}

- (NSString *)symbol4Begin:(TTRSAKeyType)type{
    return type == TTRSAKeyTypePublic ? kPublicKeyBegin : kPrivateKeyBegin;
}

- (NSString *)symbol4End:(TTRSAKeyType)type{
    return type == TTRSAKeyTypePublic ? kPublicKeyEnd : kPrivateKeyEnd;
}

- (id)secAttrKeyClass:(TTRSAKeyType)type{
    return type == TTRSAKeyTypePublic ? (id)kSecAttrKeyClassPublic:(id)kSecAttrKeyClassPrivate;
}

#pragma mark - loader
- (void)loadPublicKey{
    if (!publicSeckeyRef) {
        publicSeckeyRef = [self createRsaKey:_pem_publicKey rsaKeyType:TTRSAKeyTypePublic];
    }
}

- (void)loadPrivateKey{
    if (!privateSecKeyRef) {
        privateSecKeyRef = [self createRsaKey:_pem_privateKey rsaKeyType:TTRSAKeyTypePrivate];
    }
}

#pragma mark - convenient
// sign
+ (NSData*)signPKCS1PrivateTag:(NSString*)privateTag privateKey:(NSString*)privateKey plainData:(NSData *)plainData{
    NSString *s_key = [NSString string];
    NSArray  *a_key = [privateKey componentsSeparatedByString:@"\n"];
    BOOL     f_key  = FALSE;
    
    for (NSString *a_line in a_key) {
        if ([a_line isEqualToString:kPrivateKeyBegin]) {
            f_key = TRUE;
        }
        else if ([a_line isEqualToString:kPrivateKeyEnd]) {
            f_key = FALSE;
        }else if (f_key) {
            s_key = [s_key stringByAppendingString:a_line];
        }
    }
    if (s_key.length == 0) return NULL;
    
    SecKeyRef privateSecKeyRef = createRsaKey(s_key,privateTag,(id)kSecAttrKeyClassPrivate);

    // set plain data size by CC_SHA1_DIGEST_LENGTH
    size_t plainhashBytesSize = CC_SHA1_DIGEST_LENGTH;
    
    return secKeySignByPrivateKey(privateSecKeyRef, plainData, plainhashBytesSize,kSecPaddingPKCS1);
}
// verify
+ (BOOL)verifyPKCS1PublicTag:(NSString*)publicTag publicKey:(NSString*)publicKey plainData:(NSData *)plainData signedData:(NSData *)signedData{
    NSString *s_key = [NSString string];
    NSArray  *a_key = [publicKey componentsSeparatedByString:@"\n"];
    BOOL     f_key  = FALSE;
    
    for (NSString *a_line in a_key) {
        if ([a_line isEqualToString:kPublicKeyBegin]) {
            f_key = TRUE;
        }
        else if ([a_line isEqualToString:kPublicKeyEnd]) {
            f_key = FALSE;
        }else if (f_key) {
            s_key = [s_key stringByAppendingString:a_line];
        }
    }
    if (s_key.length == 0) return NULL;
    
    SecKeyRef publicSecKeyRef = createRsaKey(s_key,publicTag,(id)kSecAttrKeyClassPublic);
    
    // set plain data size by CC_SHA1_DIGEST_LENGTH
    size_t plainBytesSize = CC_SHA1_DIGEST_LENGTH;
    
    // verify
    return secKeyVerifyByPublicKey(publicSecKeyRef, signedData, plainData, plainBytesSize, kSecPaddingPKCS1);
}
// encrypt
+ (NSString *)encryptPKCS1PublicTag:(NSString*)publicTag publicKey:(NSString*)publicKey plainText:(NSString *)plainText{
    
    NSString *s_key = [NSString string];
    NSArray  *a_key = [publicKey componentsSeparatedByString:@"\n"];
    BOOL     f_key  = FALSE;
    
    for (NSString *a_line in a_key) {
        if ([a_line isEqualToString:kPublicKeyBegin]) {
            f_key = TRUE;
        }
        else if ([a_line isEqualToString:kPublicKeyEnd]) {
            f_key = FALSE;
        }else if (f_key) {
            s_key = [s_key stringByAppendingString:a_line];
        }
    }
    if (s_key.length == 0) return NULL;
    
    SecKeyRef publicSecKeyRef = createRsaKey(s_key,publicTag,(id)kSecAttrKeyClassPublic);
    
    NSData* plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData* encryptedData = secEncryptByPublicKey(publicSecKeyRef,plainData, kSecPaddingPKCS1);
    
    NSString* base64EncryptedString = [encryptedData base64EncodedStringWithOptions:0];
    
    return base64EncryptedString;
}
// decrypt
+ (NSString *)decryptPKCS1PrivateTag:(NSString*)privateTag privateKey:(NSString*)privateKey cipherText:(NSString *)cipherText
{
    NSString *s_key = [NSString string];
    NSArray  *a_key = [privateKey componentsSeparatedByString:@"\n"];
    BOOL     f_key  = FALSE;
    
    for (NSString *a_line in a_key) {
        if ([a_line isEqualToString:kPrivateKeyBegin]) {
            f_key = TRUE;
        }
        else if ([a_line isEqualToString:kPrivateKeyEnd]) {
            f_key = FALSE;
        }else if (f_key) {
            s_key = [s_key stringByAppendingString:a_line];
        }
    }
    if (s_key.length == 0) return NULL;
    
    SecKeyRef privateSecKeyRef = createRsaKey(s_key,privateTag,(id)kSecAttrKeyClassPrivate);
    
    NSData* cipherData = [[NSData alloc] initWithBase64EncodedString:cipherText options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    NSData* decryptData = secDecryptByPrivateKey(privateSecKeyRef, cipherData,kSecPaddingPKCS1);
    
    NSString* result = [[NSString alloc] initWithData: decryptData encoding:NSUTF8StringEncoding];
    return result;
}

#pragma mark - function
SecKeyRef createRsaKey(NSString *keyStr, NSString * keyTag, id secAttrKeyClass){
    
    // This will be base64 encoded, decode it.
    NSData *d_key = [[NSData alloc] initWithBase64EncodedString:keyStr options:0];
    if(d_key == nil) return NULL;
    
    NSData *d_tag = [NSData dataWithBytes:[keyTag UTF8String] length:[keyTag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *keyConfig = [[NSMutableDictionary alloc] init];
    [keyConfig setObject:(id) kSecClassKey forKey:(id)kSecClass];
    [keyConfig setObject:(id) kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [keyConfig setObject:d_tag forKey:(id)kSecAttrApplicationTag];
    SecItemDelete((CFDictionaryRef)keyConfig);
    
    CFTypeRef persistKey = nil;
    
    // Add persistent version of the key to system keychain
    [keyConfig setObject:d_key forKey:(id)kSecValueData];
    [keyConfig setObject:secAttrKeyClass forKey:(id)
     kSecAttrKeyClass];
    [keyConfig setObject:[NSNumber numberWithBool:YES] forKey:(id)
     kSecReturnPersistentRef];
    
    OSStatus secStatus = SecItemAdd((CFDictionaryRef)keyConfig, &persistKey);
    if (persistKey != nil) CFRelease(persistKey);
    
    if ((secStatus != noErr) && (secStatus != errSecDuplicateItem)) {
        //        [privateKey release];
        return NULL;
    }
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    
    [keyConfig removeObjectForKey:(id)kSecValueData];
    [keyConfig removeObjectForKey:(id)kSecReturnPersistentRef];
    [keyConfig setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
    secStatus = SecItemCopyMatching((CFDictionaryRef)keyConfig,
                                    (CFTypeRef *)&keyRef);
    
    if(secStatus != noErr)
        return NULL;
    return keyRef;
}

NSData * secKeySignByPrivateKey(SecKeyRef privateKey, NSData *plainData, size_t plainBytesSize, SecPadding secPadding){
    
    // get will be signed data by privateKey size
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    // allocate memry
    uint8_t *signedHashBytes = malloc(signedHashBytesSize);
    // initializ signedHashBytes memry
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    // sign
    OSStatus status = SecKeyRawSign(privateKey,
                                    secPadding,
                                    [plainData bytes],
                                    plainBytesSize,
                                    signedHashBytes,
                                    &signedHashBytesSize);
    if (status!=0) {
        char buffer[512];
        ERR_error_string(ERR_get_error(), buffer);
    }
    
    // convert signedBytes to NSData
    NSData *signedData = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    // release unuseable C object
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedData;
}

BOOL secKeyVerifyByPublicKey(SecKeyRef publicKey, NSData *signedData, NSData *plainData, size_t plainBytesSize, SecPadding secPadding){
    
    // get signed data bytes Size by public key
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    // signed data to bytes
    const void* signedHashBytes = [signedData bytes];
    
    // verify
    OSStatus status = SecKeyRawVerify(publicKey,
                                      secPadding,
                                      [plainData bytes],
                                      plainBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    if (status != 0) {
        char buffer[512];
        ERR_error_string(ERR_get_error(), buffer);
    }
    
    return (status == 0);
}

// 加密的大小受限于SecKeyEncrypt函数，SecKeyEncrypt要求明文和密钥的长度一致，如果要加密更长的内容，需要把内容按密钥长度分成多份，然后多次调用SecKeyEncrypt来实现
NSData * secEncryptByPublicKey(SecKeyRef publicKey, NSData * plainData, SecPadding secPadding){
    
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    size_t blockSize = cipherBufferSize - 11;       // 分段加密
    size_t blockCount = (size_t)ceil([plainData length] / (double)blockSize);
    NSMutableData *encryptedData = [[NSMutableData alloc] init] ;
    for (int i=0; i<blockCount; i++) {
        int bufferSize = (int)MIN(blockSize,[plainData length] - i * blockSize);
        NSData *buffer = [plainData subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        OSStatus status = SecKeyEncrypt(publicKey, secPadding, (const uint8_t *)[buffer bytes], [buffer length], cipherBuffer, &cipherBufferSize);
        if (status == noErr){
            NSData *encryptedBytes = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
            [encryptedData appendData:encryptedBytes];
        }else{
            if (cipherBuffer) {
                free(cipherBuffer);
            }
            char buffer[512];
            ERR_error_string_n(ERR_get_error(), buffer, 512);
            return nil;
        }
    }
    
    if (cipherBuffer){
        free(cipherBuffer);
    }
    
    return encryptedData;
}

NSData * secDecryptByPrivateKey(SecKeyRef privateKey, NSData *cipherData,SecPadding secPadding){
    
    size_t cipherLen = [cipherData length];
    void *cipher = malloc(cipherLen);
    [cipherData getBytes:cipher length:cipherLen];
    size_t plainLen = SecKeyGetBlockSize(privateKey) - 12;
    void *plain = malloc(plainLen);
    
    // decrypt
    OSStatus status = SecKeyDecrypt(privateKey, secPadding, cipher, cipherLen, plain, &plainLen);
    
    if (status != noErr) {
        char buffer[512];
        ERR_error_string(ERR_get_error(), buffer);
        
        return nil;
    }
    
    NSData *decryptedData = [[NSData alloc] initWithBytes:(const void *)plain length:plainLen];
    
    return decryptedData;
}

@end



