//
//  AMViewController.m
//  AMRSA
//
//  Created by liuxu5 on 04/05/2017.
//  Copyright (c) 2017 liuxu5. All rights reserved.
//

#import "AMViewController.h"
#import "AMRSAKeyPaire.h"
#import "AMRSAKey.h"
#import "AMRSAKeyPaireGenerator+Openssl.h"
#import "AMRSASecurity.h"

@interface AMViewController ()

@end

@implementation AMViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    NSString *rawText = @"这是我的测试数据#@¥#@%……&123abc";
    // generate key paire
    [[AMRSAKeyPaireGenerator defaultGenerator] asyncGenerate:2048 privTag:@"com.amer.private.as" pubTag:@"com.amer.public.as" callback:^(BOOL success, AMRSAKeyPaire * _Nullable keyPaire, NSError * _Nullable error)
     {
         if (success) {
             // encrypt by public key
             [AMRSASecurity encrypt:rawText pubKey:keyPaire.publicKey completed:^(BOOL success, id ret, NSError *error)
              {
                  NSLog(@"ciphertext: %@ \n",ret);
                  // decrypt by private key
                  [AMRSASecurity decrypt:ret priKey:keyPaire.privateKey completed:^(BOOL success, id ret, NSError *error) {
                      NSLog(@"cleartext: %@ \n",ret);
                  }];
              }];
             
             // sign by private key
             [AMRSASecurity sign:rawText priKey:keyPaire.privateKey completed:^(BOOL success, id ret, NSError *error)
              {
                  if (success) {
                      // verify by public key
                      [AMRSASecurity verify:ret raw:rawText  pubKey:keyPaire.publicKey  completed:^(BOOL verified, NSError * _Nonnull error)
                       {
                           NSLog(@"isVerified: %d \n",verified);
                       }];
                  }
              }];
         }
     }];
    
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
