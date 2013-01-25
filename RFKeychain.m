//
//  RFKeychain.m
//  EISENHOWERCommon
//
//  Created by Tim Brückmann on 25.01.13.
//  Copyright (c) 2013 Rheinfabrik. All rights reserved.
//

#import "RFKeychain.h"
#import <Security/Security.h>

@implementation RFKeychain

+ (BOOL)setPassword:(NSString *)password
            account:(NSString *)account
            service:(NSString *)service
{
    const char *serviceChars = [service UTF8String];
    const char *accountChars = [account UTF8String];
    const char *passwordChars = [password UTF8String];
    
    SecKeychainItemRef existingItemRef;
    OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                     (UInt32)strlen(serviceChars),
                                                     serviceChars,
                                                     (UInt32)strlen(accountChars),
                                                     accountChars,
                                                     NULL,
                                                     NULL,
                                                     &existingItemRef);
    
    if (status != errKCItemNotFound) {
        status = SecKeychainItemModifyAttributesAndData(existingItemRef,
                                                        NULL,
                                                        (UInt32)strlen(passwordChars),
                                                        passwordChars);
        CFRelease(existingItemRef);
    } else {
        status = SecKeychainAddGenericPassword(NULL,
                                               (UInt32)strlen(serviceChars),
                                               serviceChars,
                                               (UInt32)strlen(accountChars),
                                               accountChars,
                                               (UInt32)strlen(passwordChars),
                                               passwordChars,
                                               NULL);
    }
    
    return status == noErr;
}

+ (NSString *)passwordForAccount:(NSString *)account
                         service:(NSString *)service
{
    const char *accountChars = [account UTF8String];
    const char *serviceChars = [service UTF8String];
    
    UInt32 passwordLength;
    char *password;
    
    OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                     (UInt32)strlen(serviceChars),
                                                     serviceChars,
                                                     (UInt32)strlen(accountChars),
                                                     accountChars,
                                                     &passwordLength,
                                                     (void **)&password,
                                                     NULL);
    
    if (status != noErr) {
        return nil;
    }
    
    NSData *passwordData = [NSData dataWithBytes:password length:passwordLength];
    NSString *passwordString = [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding];
    SecKeychainItemFreeContent(NULL, password);
 
    return passwordString;
}

+ (BOOL)deletePasswordForAccount:(NSString *)account
                         service:(NSString *)service
{   
    NSDictionary *query = (@{
                           (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
                           (__bridge id)kSecAttrService : service,
                           (__bridge id)kSecAttrAccount : account
                           });
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    
    return (
            status == noErr
            || status == errKCItemNotFound
            );
}

@end
