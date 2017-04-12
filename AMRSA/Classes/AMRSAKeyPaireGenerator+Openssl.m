//
//  AMRSAKeyPaireGenerator+Openssl.m
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/10.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import "AMRSAKeyPaireGenerator+Openssl.h"
#import "AMRSAKeyPaire.h"
#import "AMError.h"
#include "openssl/pem.h"
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>


@implementation AMRSAKeyPaireGenerator (Openssl)

- (AMRSAKeyPaire *)syncGeneratePEM:(int)bits privTag:(NSString *)privTag pubTag:(NSString *)pubTag
{
    __block AMRSAKeyPaire *s_keyPaire = nil;
    [self syncGeneratePEM:bits privTag:privTag pubTag:pubTag callback:^(BOOL success, AMRSAKeyPaire * _Nullable keyPaire, NSError * _Nullable error) {
        s_keyPaire = keyPaire;
    }];
    return s_keyPaire;
}

- (void)syncGeneratePEM:(int)bits privTag:(NSString *)privTag pubTag:(NSString *)pubTag callback:(AMRSAKeyPaireGeneratorCallback)callback
{
    NSParameterAssert(callback);
    [self generateRSA:bits privTag:privTag pubTag:pubTag completed:^(BOOL success, RSA *rsa_key, NSError *error) {
        if (success) {
            [self generateKeyPaire:rsa_key completed:^(BOOL success, NSString *pubKey, NSString *priKey, NSError *error) {
                if (success) {
                    AMRSAKey *am_pub_key = [self.productor keyByText:pubKey tag:pubTag format:AMRSAKeyFormatPEM type:AMRSAKeyTypePublic];
                    AMRSAKey *am_pri_key = [self.productor keyByText:priKey tag:privTag format:AMRSAKeyFormatPEM type:AMRSAKeyTypePrivate];
                    AMRSAKeyPaire *keyPaire = [AMRSAKeyPaire keyPaireWithPublicKey:am_pub_key privateKey:am_pri_key];
                    callback(YES, keyPaire, nil);
                }else{
                    callback(NO, nil, error);
                }
            }];
        }else{
            callback(NO, nil, error);
        }
    }];
}

- (void)generateRSA:(int)bits privTag:(NSString *)privTag pubTag:(NSString *)pubTag completed:(void(^)(BOOL success, RSA *rsa_key, NSError *error))completed
{
    unsigned int e = RSA_F4;
    BIGNUM *bne = BN_new();
    int ret_bn = BN_set_word(bne, e);
    if (ret_bn != ERR_LIB_NONE) {
        char buffer[500];
        ERR_error_string(ERR_get_error(), buffer);
        NSString *errorMessage = [NSString stringWithUTF8String:buffer];
        completed(NO, NULL ,[NSError errorWithDomain:am_err_domain(@"BN_set_word") code:ret_bn userInfo:@{@"errorMessage":errorMessage,@"errorCode":@(ret_bn)}]);
        return;
    }
    RSA *rsa_key = RSA_new();
    
    // generate key pair
    int ret_generate = RSA_generate_key_ex(rsa_key, bits,bne, NULL);
    if (ret_generate != ERR_LIB_NONE) {
        char buffer[500];
        ERR_error_string(ERR_get_error(), buffer);
        NSString *errorMessage = [NSString stringWithUTF8String:buffer];
        completed(NO, NULL ,[NSError errorWithDomain:am_err_domain(@"RSA_generate_key_ex") code:ret_bn userInfo:@{@"errorMessage":errorMessage,@"errorCode":@(ret_bn)}]);
        return;
    }
    // success
    completed(YES, rsa_key, nil);
}

- (void)generateKeyPaire:(RSA *)rsa_key completed:(void(^)(BOOL success, NSString *pubKey, NSString *priKey, NSError *error))completed
{
    __block NSString *pub_key = nil;
    __block NSString *pri_key = nil;
    __block BOOL g_success = YES;
    __block NSError *g_error = nil;
    // pub key
    [self readPEMKey:rsa_key isPub:YES completed:^(BOOL success, NSString *key, NSError *error) {
        if (success) {
            pub_key = key;
        }else{
            g_success = success;
            g_error = error;
        }
    }];
    if (!g_success) completed(g_success, nil, nil, g_error);
    
    // private key
    [self readPEMKey:rsa_key isPub:YES completed:^(BOOL success, NSString *key, NSError *error) {
        if (success) {
            pri_key = key;
        }else{
            g_success = success;
            g_error = error;
        }
    }];
    completed(g_success, pub_key, pri_key, g_error);
}

- (void)readPEMKey:(RSA *)rsa_key isPub:(BOOL)isPub completed:(void(^)(BOOL success, NSString *key, NSError *error))completed
{
    // create private and public key structure object
    BIO *bio = BIO_new(BIO_s_mem());
    // write data to private and public key structure object by RSA key paire
    int ret_pem_write;
    NSString *method;
    if (isPub) {
        ret_pem_write = PEM_write_bio_RSAPublicKey(bio, rsa_key);
        method = @"PEM_write_bio_RSAPublicKey";
    }else{
        ret_pem_write = PEM_write_bio_RSAPrivateKey(bio, rsa_key, NULL, NULL, 0, NULL, NULL);
        method = @"PEM_write_bio_RSAPrivateKey";
    }
    // error
    if (ret_pem_write != ERR_LIB_NONE) {
        char buffer[500];
        ERR_error_string(ERR_get_error(), buffer);
        NSString *errorMessage = [NSString stringWithUTF8String:buffer];
        completed(NO, NULL ,[NSError errorWithDomain:am_err_domain(method) code:ret_pem_write userInfo:@{@"errorMessage":errorMessage,@"errorCode":@(ret_pem_write)}]);
        return;
    }
    
    // measure size of private and public key structure object
    size_t bio_len = BIO_pending(bio);
    unsigned char *c_key = malloc(bio_len + 1);
    int ret_read = BIO_read(bio, c_key, (int) bio_len);
    // error
    if (ret_pem_write != ERR_LIB_NONE) {
        char buffer[500];
        ERR_error_string(ERR_get_error(), buffer);
        NSString *errorMessage = [NSString stringWithUTF8String:buffer];
        completed(NO, NULL ,[NSError errorWithDomain:am_err_domain(method) code:ret_read userInfo:@{@"errorMessage":errorMessage,@"errorCode":@(ret_read)}]);
        return;
    }
    
    // sign end of key
    c_key[bio_len] = '\0';
    NSString *pem_Key = [[NSString alloc] initWithCString:(const char*)c_key encoding:NSUTF8StringEncoding];
    completed(YES, pem_Key, nil);
}


- (void)asyncGeneratePEM:(int)bits privTag:(NSString *)privTag pubTag:(NSString *)pubTag callback:(AMRSAKeyPaireGeneratorCallback)callback
{
    __weak __typeof__(self) weakSelf = self;
    [_generateQueue addOperationWithBlock:^{
        __strong __typeof__(weakSelf) sself =  weakSelf;
        [sself syncGeneratePEM:bits privTag:privTag pubTag:pubTag callback:^(BOOL success, AMRSAKeyPaire * _Nullable keyPaire, NSError * _Nullable error) {
            [[NSOperationQueue mainQueue] addOperationWithBlock:^{
                callback(success, keyPaire, error);
            }];
        }];
    }];
}

@end
