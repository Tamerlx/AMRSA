//
//  AMRSAKeyPaireGenerator.h
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/10.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AMRSAKey.h"

@class AMRSAKeyPaire;

NS_ASSUME_NONNULL_BEGIN
typedef void(^AMRSAKeyPaireGeneratorCallback)(BOOL success, AMRSAKeyPaire * _Nullable keyPaire, NSError *_Nullable error);

@interface AMRSAKeyPaireGenerator : NSObject{
    @private
    NSOperationQueue *_generateQueue;
}

+ (instancetype)defaultGenerator;

- (instancetype)initWithQueue:(NSOperationQueue *)queue productor:(id<AMRSAKeyProductor>)productor NS_DESIGNATED_INITIALIZER;

@property (nonatomic, strong) id<AMRSAKeyProductor> productor;
@property (nonatomic, assign) BOOL isExcuting;

- (AMRSAKeyPaire * __nullable)syncGenerate:(int)bits privTag:(NSString * __nullable)privTag pubTag:(NSString * __nullable)pubTag;
- (void)asyncGenerate:(int)bits privTag:(NSString * __nullable)privTag pubTag:(NSString * __nullable)pubTag callback:(AMRSAKeyPaireGeneratorCallback)callback;

@end

NS_ASSUME_NONNULL_END
