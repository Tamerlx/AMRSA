//
//  AMRSAKeyPaireGenerator.m
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/10.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import "AMRSAKeyPaireGenerator.h"
#import "AMRSAKeyFactory.h"
#import "AMRSAKeyPaire.h"
#import "AMError.h"

@interface AMRSAKeyPaireGenerator ()

@end
@implementation AMRSAKeyPaireGenerator

+ (instancetype)defaultGenerator
{
    static AMRSAKeyPaireGenerator *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance =  [[self alloc] init];
    });
    return instance;
}

- (instancetype)initWithQueue:(NSOperationQueue *)queue productor:(nonnull id<AMRSAKeyProductor>)productor
{
    if (self = [super init]) {
        _generateQueue = queue;
        _productor = productor;
    }
    return self;
}

- (instancetype)init
{
    NSOperationQueue *generateQueue = [[NSOperationQueue alloc] init];
    generateQueue.maxConcurrentOperationCount = 6;
    generateQueue.name = @"com.amrsa.keypaire.generatequeue";
    return [self initWithQueue:generateQueue productor:[AMRSAKeyFactory new]];
}

- (AMRSAKeyPaire * __nullable)syncGenerate:(int)bits privTag:(NSString * __nullable)privTag pubTag:(NSString * __nullable)pubTag
{
    __block AMRSAKeyPaire *s_keyPaire = nil;
    [self syncGenerate:bits privTag:privTag pubTag:pubTag callback:^(BOOL success, AMRSAKeyPaire * _Nullable keyPaire, NSError * _Nullable error) {
        s_keyPaire = keyPaire;
    }];
    return s_keyPaire;
}

- (void)syncGenerate:(int)bits privTag:(NSString * __nullable)privTag pubTag:(NSString * __nullable)pubTag callback:(AMRSAKeyPaireGeneratorCallback)callback
{
    NSDictionary *pubAttr = nil;
    NSDictionary *priAttr = nil;
    if (privTag && privTag.length>0) {
        priAttr = @{(id)kSecAttrApplicationTag:privTag};
    }
    
    if (pubTag && pubTag.length >0) {
        pubAttr = @{(id)kSecAttrApplicationTag:pubTag};
    }
    
    NSMutableDictionary *parameters = [NSMutableDictionary dictionaryWithDictionary:@{(id)kSecAttrKeyType:(id)kSecAttrKeyTypeRSA,
                                                                                      (id)kSecAttrKeySizeInBits:@(bits)}];
    if (pubAttr) {
        [parameters setObject:pubAttr forKey:(id)kSecPublicKeyAttrs];
    }
    if (priAttr) {
        [parameters setObject:priAttr forKey:(id)kSecPrivateKeyAttrs];
    }
    
    SecKeyRef pub_key = NULL;
    SecKeyRef pri_key = NULL;
    OSStatus ret;
    ret = SecKeyGeneratePair((CFDictionaryRef)parameters, &pub_key, &pri_key);
    if (ret != errSecSuccess) {
        callback(NO, nil ,[NSError errorWithDomain:am_err_domain(@"BN_set_word") code:errSecSuccess userInfo:@{@"errorMessage":@"",@"errorCode":@(ret)}]);
        return;
    }
    
    AMRSAKey *am_pub_key = [self.productor keyByKeyRef:pub_key tag:pubTag format:AMRSAKeyFormatCER type:AMRSAKeyTypePublic];
    AMRSAKey *am_pri_key = [self.productor keyByKeyRef:pri_key tag:privTag format:AMRSAKeyFormatCER type:AMRSAKeyTypePrivate];
    AMRSAKeyPaire *keyPaire = [AMRSAKeyPaire keyPaireWithPublicKey:am_pub_key privateKey:am_pri_key];
    callback(YES, keyPaire, nil);
    return ;
}

- (void)asyncGenerate:(int)bits privTag:(NSString * __nullable)privTag pubTag:(NSString * __nullable)pubTag callback:(AMRSAKeyPaireGeneratorCallback)callback
{
    __weak __typeof__(self) weakSelf = self;
    [_generateQueue addOperationWithBlock:^{
        __strong __typeof__(weakSelf) sself =  weakSelf;
        [sself syncGenerate:bits privTag:privTag pubTag:pubTag callback:^(BOOL success, AMRSAKeyPaire * _Nullable keyPaire, NSError * _Nullable error) {
            [[NSOperationQueue mainQueue] addOperationWithBlock:^{
                callback(success, keyPaire, error);
            }];
        }];
    }];
}

@end
