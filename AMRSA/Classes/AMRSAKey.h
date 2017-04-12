//
//  AMRSAKey.h
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/8.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

typedef enum : NSUInteger {
    AMRSAKeyFormatCER = 1 << 0,
    AMRSAKeyFormatPEM = 1 << 1,
} AMRSAKeyFormat;

typedef enum : NSUInteger {
    AMRSAKeyTypePublic = 1 << 0,
    AMRSAKeyTypePrivate = 1 << 1,
} AMRSAKeyType;

NS_ASSUME_NONNULL_BEGIN
@class AMRSAKey;
@protocol AMRSAKeyProductor <NSObject>

- (AMRSAKey *)keyByKeyRef:(SecKeyRef)keyRef tag:(nullable NSString *)tag format:(AMRSAKeyFormat)format type:(AMRSAKeyType)type;
- (AMRSAKey *)keyByData:(NSString *)data tag:(nullable NSString *)tag format:(AMRSAKeyFormat)format type:(AMRSAKeyType)type;
- (AMRSAKey *)keyByText:(NSString *)text tag:(nullable NSString *)tag format:(AMRSAKeyFormat)format type:(AMRSAKeyType)type;

@end

@interface AMRSAKey : NSObject{
    @private
    SecKeyRef _keyRef;
}

//MARK: - initialization
- (instancetype)initWithSecKeyRef:(SecKeyRef)keyRef text:(NSString *)text tag:(nullable NSString *)keyTag formatter:(AMRSAKeyFormat)format type:(AMRSAKeyType)type;
//MARK: - basic property
@property (nonatomic, readonly) SecKeyRef keyRef;
@property (nonatomic, copy, readonly) NSString *keyText;
@property (nullable, nonatomic, copy, readonly) NSString *keyTag;
@property (nonatomic, assign, readonly) AMRSAKeyFormat format;
@property (nonatomic, assign, readonly) AMRSAKeyType type;
@property (nullable, nonatomic, strong) NSDate *createDate;
@property (nullable, nonatomic, strong) NSDate *expire;

@end
NS_ASSUME_NONNULL_END
