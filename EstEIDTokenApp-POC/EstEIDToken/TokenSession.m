#import "Token.h"

@implementation EstEIDAuthOperation

- (BOOL)finishWithError:(NSError **)error {
    NSLog(@"EstEIDAuthOperation finishWithError");

    if (![self.smartCard inSessionWithError:error executeBlock:^BOOL(NSError **error) {
        UInt16 sw = 0;
        [self.smartCard sendIns:0x20 p1:0x00 p2:0x01 data:[self.PIN dataUsingEncoding:NSUTF8StringEncoding] le:nil sw:&sw error:error];
        if ((sw & 0xff00) == 0x6300) {
            int triesLeft = sw & 0x3f;
            NSLog(@"Failed to verify PIN sw:0x%04x retries: %d", sw, triesLeft);
            if (error != nil) {
                *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:
                          @{NSLocalizedDescriptionKey: [NSString localizedStringWithFormat: NSLocalizedString(@"VERIFY_TRY_LEFT", nil), triesLeft]}];
            }
            return NO;
        } else if (sw != 0x9000) {
            NSLog(@"Failed to verify PIN sw: 0x%04x", sw);
            if (error != nil) {
                *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:
                          @{NSLocalizedDescriptionKey: [NSString localizedStringWithFormat: NSLocalizedString(@"VERIFY_TRY_LEFT", nil), 0]}];
            }
            return NO;
        }
        return YES;
    }]) {
        NSLog(@"EstEIDAuthOperation finishWithError failed authenticate");
        return NO;
    }

    // Mark card session sensitive, because we entered PIN into it and no session should access it in this state.
    self.smartCard.sensitive = YES;

    // Remember in card context that the card is authenticated.
    self.smartCard.context = @(YES);

    return YES;
}

@end

@implementation EstEIDTokenSession

- (TKTokenAuthOperation *)tokenSession:(TKTokenSession *)session beginAuthForOperation:(TKTokenOperation)operation constraint:(TKTokenOperationConstraint)constraint error:(NSError **)error {
    NSLog(@"EstEIDTokenSession beginAuthForOperation");
    if ([constraint isEqual:EstEIDConstraintPIN]) {
        EstEIDAuthOperation *auth = [[EstEIDAuthOperation alloc] init];
        auth.smartCard = self.smartCard;
        const UInt8 template[] = {self.smartCard.cla, 0x20, 0x00, 0x01, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        auth.APDUTemplate = [NSData dataWithBytes:template length:sizeof(template)];
        auth.PINFormat = [[TKSmartCardPINFormat alloc] init];
        auth.PINFormat.PINBitOffset = 5 * 8;
        return auth;
    }
    NSLog(@"EstEIDTokenSession beginAuthForOperation attempt to evaluate unsupported constraint %@", constraint);
    if (error != nil) {
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString(@"WRONG_CONSTR", nil)}];
    }
    return nil;
}

- (BOOL)tokenSession:(TKTokenSession *)session supportsOperation:(TKTokenOperation)operation usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm {
    NSLog(@"EstEIDTokenSession supportsOperation %@ keyID %@", @(operation), keyObjectID);
    TKTokenKeychainKey *keyItem = [self.token.keychainContents keyForObjectID:keyObjectID error:nil];
    if (keyItem == nil) {
        NSLog(@"EstEIDTokenSession supportsOperation key not found");
        return NO;
    }

    BOOL supports = NO;
    switch (operation) {
        case TKTokenOperationSignData:
            supports = keyItem.canSign && [algorithm isAlgorithm:kSecKeyAlgorithmRSASignatureRaw];
            break;
        case TKTokenOperationDecryptData:
            supports = keyItem.canDecrypt && [algorithm isAlgorithm:kSecKeyAlgorithmRSAEncryptionRaw];
            break;
        default:
            break;
    }
    NSLog(@"EstEIDTokenSession supportsOperation key supports: %@", @(supports));
    return supports;
}

- (NSData *)tokenSession:(TKTokenSession *)session signData:(NSData *)dataToSign usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm error:(NSError **)error {
    NSLog(@"EstEIDTokenSession signData %@", keyObjectID);

    TKTokenKeychainKey *keyItem = [self.token.keychainContents keyForObjectID:keyObjectID error:error];
    if (keyItem == nil) {
        NSLog(@"EstEIDTokenSession signData key not found");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeTokenNotFound userInfo:nil];
        }
        return nil;
    }

    if (self.smartCard.context == nil) {
        NSLog(@"EstEIDTokenSession signData unauthicated");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationNeeded userInfo:nil];
        }
        return nil;
    }

    __block NSData *response = nil;
    [self.smartCard inSessionWithError:error executeBlock:^BOOL(NSError **error) {
        UInt16 sw;
        NSData *DEFAULT = [NSData dataWithBytes:(const UInt8[]){ 0x83, 0x00 } length:2]; //Key reference, 8303801100

        [self.smartCard sendIns:0x22 p1:0xF3 p2:0x01 data:nil le:@(0) sw:&sw error:error];
        if (sw != 0x9000) {
            NSLog(@"EstEIDTokenSession signData failed to set sec env");
            if (error != nil) {
                *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
            }
            return NO;
        }

        [self.smartCard sendIns:0x22 p1:0x41 p2:0xB8 data:DEFAULT le:nil sw:&sw error:error];
        if (sw != 0x9000) {
            NSLog(@"EstEIDTokenSession signData failed to select default key");
            if (error != nil) {
                *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
            }
            return NO;
        }

        // Remove PKCS1 1.5 padding 00 01 FF FF 00 ....
        const char *string = dataToSign.bytes;
        char *e = strchr(&string[3], '\0'); // Start at pos 3
        NSUInteger pos = (NSUInteger)(e - string) + 1;
        NSData *sign = [dataToSign subdataWithRange:NSMakeRange(pos, dataToSign.length - pos)];

        self.smartCard.useExtendedLength = NO;
        response = [self.smartCard sendIns:0x88 p1:0x00 p2:0x00 data:sign le:@(0) sw:&sw error:error];
        if (sw == 0x9000) {
            self.smartCard.sensitive = NO;
            self.smartCard.context = nil;
            return YES;
        }

        NSLog(@"EstEIDTokenSession signData failed to sign");
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        return NO;
    }];
    return response;
}

- (NSData *)tokenSession:(TKTokenSession *)session decryptData:(NSData *)ciphertext usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm error:(NSError **)error {
    NSLog(@"EstEIDTokenSession decryptData %@", keyObjectID);
    // FIXME: implement decrypt
    return [self tokenSession:session signData:ciphertext usingKey:keyObjectID algorithm:algorithm error:error];
}

@end
