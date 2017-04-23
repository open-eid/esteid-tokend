#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <CryptoTokenKit/TKSmartCardToken.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark EstEID implementation of TKToken classes

static const TKTokenOperationConstraint EstEIDConstraintPIN = @"PIN";

@interface EstEIDTokenDriver : TKSmartCardTokenDriver<TKSmartCardTokenDriverDelegate>
@end

@interface EstEIDToken : TKSmartCardToken<TKTokenDelegate>
@end

@interface EstEIDTokenSession : TKSmartCardTokenSession<TKTokenSessionDelegate>
@end

@interface EstEIDAuthOperation : TKTokenSmartCardPINAuthOperation
@end

NS_ASSUME_NONNULL_END
