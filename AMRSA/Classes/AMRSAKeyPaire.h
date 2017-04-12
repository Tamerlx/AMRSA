//
//  AMRSAKeyPaire.h
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/8.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
@class AMRSAKey;
@interface AMRSAKeyPaire : NSObject

+ (instancetype)keyPaireWithPublicKey:(AMRSAKey * __nullable)publicKey privateKey:(AMRSAKey * __nullable)privateKey;
- (instancetype)initWithPublicKey:(AMRSAKey * __nullable)publicKey privateKey:(AMRSAKey * __nullable)privateKey NS_DESIGNATED_INITIALIZER;

@property (nullable, nonatomic, strong) AMRSAKey *publicKey;
@property (nullable, nonatomic, strong) AMRSAKey *privateKey;

@end
NS_ASSUME_NONNULL_END
