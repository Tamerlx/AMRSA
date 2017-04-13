//
//  AMRSAKeyPaire.m
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/8.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import "AMRSAKeyPaire.h"
@implementation AMRSAKeyPaire

+ (instancetype)keyPaireWithPublicKey:(AMRSAKey *)publicKey privateKey:(AMRSAKey *)privateKey
{
    return [[self alloc] initWithPublicKey:publicKey privateKey:privateKey];
}

- (instancetype)initWithPublicKey:(AMRSAKey *)publicKey privateKey:(AMRSAKey *)privateKey
{
    if (self = [super init]) {
        _publicKey = publicKey;
        _privateKey = privateKey;
    }
    return self;
}

- (instancetype)init
{
    return [self initWithPublicKey:nil privateKey:nil];
}


@end
