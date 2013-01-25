# RFKeychain

RFKeychain is an Objective-C keychain wrapper for iOS and Mac OS X. It's not as complete as [SSKeyChain](https://github.com/soffes/sskeychain) and is only tested on iOS 6 and Mac OS X 10.8.

However, it's completely unit tested using [Kiwi](https://github.com/allending/Kiwi). Therefore, it should be stable and a good example for people getting started with unit testing on iOS.

## Installation

### CocoaPods

pod 'RFKeychain', '~> 0.1'

### Manual

- Copy `RFKeychain.[h|m]` into your project
- Add `Security.framework` to your target

## Usage

The following methods are currently implemented

```objective-c
+ (BOOL)setPassword:(NSString *)password
            account:(NSString *)account
            service:(NSString *)service;
+ (NSString *)passwordForAccount:(NSString *)account
                         service:(NSString *)service;
+ (BOOL)deletePasswordForAccount:(NSString *)account
                         service:(NSString *)service;
```

If you want to know more about the methods, you can find their behaviour in the RFKeychainSpec.

## Tests

To run the tests, you first need to install Kiwi by running `pod install` (Assuming you have CocoaPods installed, otherwise you need to do that first, obviously).

## Status

RFKeychain is pretty trivial right now, I'll add features and better error handling as I need them myself. Feel free to help out but please always add tests.