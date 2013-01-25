#import "Kiwi.h"
#import "RFKeychain.h"
#import <Security/Security.h>

SPEC_BEGIN(RFKeychainSpec)

describe(@"RFKeychain", ^{
    
    __block NSString *service;
    __block NSString *account;
    __block NSString *password;
    
    void (^insertPassword)(void) = ^{
        OSStatus status = SecKeychainAddGenericPassword(NULL,
                                                        (UInt32)strlen([service UTF8String]),
                                                        [service UTF8String],
                                                        (UInt32)strlen([account UTF8String]),
                                                        [account UTF8String],
                                                        (UInt32)strlen([password UTF8String]),
                                                        [password UTF8String],
                                                        NULL);
        [[theValue(status) should] equal:theValue(noErr)];
    };
    
    beforeEach(^{
        service = @"RFKeychain";
        account = @"dwight@eisenhower.me";
        password = @"foobar";
        
        // delete all existing entries for our service
        NSDictionary *query = (@{
                               (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
                               (__bridge id)kSecAttrService : service,
                               (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitAll
                               });
        SecItemDelete((__bridge CFDictionaryRef)query);
    });
    
    context(@"when setting a password", ^{
        
        NSString *(^savedPassword)(void) = ^{
            CFTypeRef result;
            NSDictionary *query = (@{
                                   (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
                                   (__bridge id)kSecAttrService : service,
                                   (__bridge id)kSecAttrAccount : account,
                                   (__bridge id)kSecReturnData : (__bridge id)kCFBooleanTrue
                                   });
            SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
            NSData *resultData = (__bridge_transfer NSData *)result;
            NSString *resultString = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
            return resultString;
        };
        
        context(@"for a new account", ^{
            
            it(@"should create the account for the service with the given password", ^{
                BOOL success = [RFKeychain setPassword:password account:account service:service];
                [[theValue(success) should] beYes];
                
                [[savedPassword() should] equal:password];
            });
            
        });
        
        context(@"for an existing account", ^{
            
            beforeEach(^{
                insertPassword();
            });
            
            it(@"should update the existing password", ^{
                NSString *newPassword = @"haxx0r";
                BOOL success = [RFKeychain setPassword:newPassword account:account service:service];
                [[theValue(success) should] beYes];
                
                [[savedPassword() should] equal:newPassword];
            });
            
        });
        
    });
    
    context(@"when getting a password", ^{
        
        context(@"and a password for the given account and service exists", ^{
            
            beforeEach(^{
                insertPassword();
            });
            
            it(@"should return the password", ^{
                [[[RFKeychain passwordForAccount:account service:service] should] equal:password];
            });
            
        });
        
        context(@"and no password for the givven account and service exists", ^{
            
            it(@"should return nil", ^{
                [[RFKeychain passwordForAccount:account service:service] shouldBeNil];
            });
            
        });
        
    });
    
    context(@"when deleting a password", ^{
        
        context(@"and a password for the given account and service exists", ^{
            
            beforeEach(^{
                insertPassword();
            });
            
            it(@"should return YES", ^{
                [[theValue([RFKeychain deletePasswordForAccount:account service:service]) should] beYes];
            });
            
            it(@"should delete the password", ^{
                [[theValue([RFKeychain deletePasswordForAccount:account service:service]) should] beYes];
                
                OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                                 (UInt32)strlen([service UTF8String]),
                                                                 [service UTF8String],
                                                                 (UInt32)strlen([account UTF8String]),
                                                                 [account UTF8String],
                                                                 NULL,
                                                                 NULL,
                                                                 NULL);
                [[theValue(status) should] equal:theValue(errKCItemNotFound)];
            });
            
        });
        
        context(@"and no password for the givven account and service exists", ^{
            
            it(@"should return YES", ^{
                [[theValue([RFKeychain deletePasswordForAccount:account service:service]) should] beYes];
            });
            
        });
        
    });
    
});

SPEC_END