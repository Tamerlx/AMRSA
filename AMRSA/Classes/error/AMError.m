//
//  AMError.m
//  AMRSATest
//
//  Created by vip-刘旭 on 2017/4/12.
//  Copyright © 2017年 vip-刘旭. All rights reserved.
//

#import "AMError.h"


NSString * am_err_domain(NSString *path)
{
    return [NSString stringWithFormat:@"com.AMRSA.%@",path];
}

@implementation AMError

@end
