//
//  AMRSAKeyPaireGenerator+Openssl.h
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/10.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import "AMRSAKeyPaireGenerator.h"

NS_ASSUME_NONNULL_BEGIN
@interface AMRSAKeyPaireGenerator (Openssl)

- (AMRSAKeyPaire * __nullable)syncGeneratePEM:(int)bits privTag:(NSString * __nullable)privTag pubTag:(NSString * __nullable)pubTag;
- (void)asyncGeneratePEM:(int)bits privTag:(NSString * __nullable)privTag pubTag:(NSString * __nullable)pubTag callback:(AMRSAKeyPaireGeneratorCallback)callback;

@end
NS_ASSUME_NONNULL_END
