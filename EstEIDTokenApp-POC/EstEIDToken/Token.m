#import "Token.h"

@implementation TKSmartCard(EstEID)

- (NSData*)selectFile:(UInt8)ins p1:(UInt8)p1 p2:(UInt8)p2 file:(nullable NSData *)file error:(NSError **)error {
    UInt16 sw = 0;
    NSData *data = [self sendIns:ins p1:p1 p2:p2 data:file le:@0 sw:&sw error:error];
    if (sw == 0x9000) {
        return data;
    }
    NSLog(@"EstEIDToken selectFile failed to select: %@", file);
    if (error != nil) {
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
    }
    return nil;
}

- (nullable NSData*)readFile:(NSData*)file error:(NSError **) error {
    NSData *data = [self selectFile:0xA4 p1:0x02 p2:0x00 file:file error:error];
    if (data == nil) {
        return nil;
    }

    __block UInt16 length = 0x0600;
    TKBERTLVRecord *record = [TKBERTLVRecord recordFromData:data];
    if (record != nil) {
        NSArray<TKTLVRecord *> *records = [TKBERTLVRecord sequenceOfRecordsFromData:record.value];
        if (records != nil) {
            [records enumerateObjectsUsingBlock:^(TKTLVRecord *obj, NSUInteger idx, BOOL *stop) {
                if (obj.tag == 0x85) {
                    length = CFSwapInt16BigToHost(*(UInt16*)obj.value.bytes);
                    *stop = YES;
                }
            }];
        }
    }
    
    NSMutableData *fileData = [[NSMutableData alloc] init];
    while (fileData.length < length) {
        UInt16 sw = 0;
        NSData *data = [self sendIns:0xB0 p1:(fileData.length >> 8) p2:fileData.length data:nil le:@0 sw:&sw error:error];
        if (sw == 0x9000) {
            [fileData appendData:data];
            continue;
        }
        NSLog(@"EstEIDToken readFile failed to read file: %@", file);
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
        }
        return nil;
    }
    return [fileData subdataWithRange:NSMakeRange(0, length)];
}

- (nullable NSString*)readRecord:(UInt8)record error:(NSError **) error {
    UInt16 sw = 0;
    NSData *data = [self sendIns:0xB2 p1:record p2:0x04 data:nil le:@0 sw:&sw error:error];
    if (sw == 0x9000) {
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    NSLog(@"EstEIDToken readRecord failed to read record %@", @(record));
    if (error != nil) {
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
    }
    return nil;
}

@end

@implementation TKTokenKeychainItem(EstEIDDataFormat)

- (void)setName:(NSString *)name {
    if (self.label != nil) {
        self.label = [NSString stringWithFormat:@"%@ (%@)", name, self.label];
    } else {
        self.label = name;
    }
}

@end

@implementation EstEIDToken

- (BOOL)populateIdentity:(NSMutableArray<TKTokenKeychainItem *> *)items certificateID:(TKTokenObjectID)certificateID name:(NSString *)certificateName certData:(NSData *)certificateData keyID:(TKTokenObjectID)keyID name:(NSString *)keyName auth:(BOOL)auth error:(NSError **)error {
    NSLog(@"EstEIDToken populateIdentityFromSmartCard cert %@ (%@) key %@ (%@)", certificateName, certificateID, keyName, keyID);
    // Create certificate item.
    id certificate = CFBridgingRelease(SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)certificateData));
    if (certificate == NULL) {
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString(@"CORRUPTED_CERT", nil)}];
        }
        return NO;
    }
    TKTokenKeychainCertificate *certificateItem = [[TKTokenKeychainCertificate alloc] initWithCertificate:(__bridge SecCertificateRef)certificate objectID:certificateID];
    if (certificateItem == nil) {
        return NO;
    }
    [certificateItem setName:certificateName];
    [items addObject:certificateItem];

    // Create key item.
    TKTokenKeychainKey *keyItem = [[TKTokenKeychainKey alloc] initWithCertificate:(__bridge SecCertificateRef)certificate objectID:keyID];
    if (keyItem == nil) {
        return NO;
    }
    [keyItem setName:keyName];

    keyItem.canSign = YES;
    keyItem.canDecrypt = auth;
    keyItem.suitableForLogin = auth;
    NSMutableDictionary<NSNumber *, TKTokenOperationConstraint> *constraints = [NSMutableDictionary dictionary];
    constraints[@(TKTokenOperationSignData)] = EstEIDConstraintPIN;
    if (auth) {
        constraints[@(TKTokenOperationDecryptData)] = EstEIDConstraintPIN;
    }
    keyItem.constraints = constraints;
    [items addObject:keyItem];
    return YES;
}

- (nullable instancetype)initWithSmartCard:(TKSmartCard *)smartCard AID:(nullable NSData *)AID tokenDriver:(TKSmartCardTokenDriver *)tokenDriver error:(NSError **)error {
    NSLog(@"EstEIDToken initWithSmartCard");
    // FIXME: SIGN cert disabled

    __block NSString *instanceID;
    __block NSData *auth/*, *sign*/;
    if (![smartCard inSessionWithError:error executeBlock:^BOOL(NSError **error) {
        NSData *EEEE = [NSData dataWithBytes:(const UInt8[]){ 0xEE, 0xEE } length:2];
        NSData *PERSO = [NSData dataWithBytes:(const UInt8[]){ 0x50, 0x44 } length:2];
        NSData *AUTH = [NSData dataWithBytes:(const UInt8[]){ 0xAA, 0xCE } length:2];
        //NSData *SIGN = [NSData dataWithBytes:(const UInt8[]){ 0xDD, 0xCE } length:2];
        return [smartCard selectFile:0xA4 p1:0x00 p2:0x0C file:nil error:error] != nil &&
            [smartCard selectFile:0xA4 p1:0x01 p2:0x0C file:EEEE error:error] != nil &&
            [smartCard selectFile:0xA4 p1:0x02 p2:0x0C file:PERSO error:error] != nil &&
            (instanceID = [smartCard readRecord:0x08 error:error]) != nil &&
            (auth = [smartCard readFile:AUTH error:error]) != nil/* &&
            (sign = [smartCard readFile:SIGN error:error]) != nil*/;
    }]) {
        NSLog(@"EstEIDToken initWithSmartCard failed to read card");
        return nil;
    }
    NSLog(@"EstEIDToken initWithSmartCard %@", instanceID);

    if (self = [super initWithSmartCard:smartCard AID:AID instanceID:instanceID tokenDriver:tokenDriver]) {
        // Prepare array with keychain items representing on card objects.
        NSMutableArray<TKTokenKeychainItem *> *items = [NSMutableArray arrayWithCapacity:4];
        if (![self populateIdentity:items
                      certificateID:@(0xAACE) name:NSLocalizedString(@"AUTH_CERT", nil) certData:auth
                              keyID:@(0x1100) name:NSLocalizedString(@"AUTH_KEY", nil) auth:YES error:error]/* ||
            ![self populateIdentity:items
                      certificateID:@(0xDDCE) name:NSLocalizedString(@"SIGN_CERT", nil) certData:sign
                              keyID:@(0x0100) name:NSLocalizedString(@"SIGN_KEY", nil) auth:NO error:error]*/) {
            return nil;
        }

        // Populate keychain state with keys.
        [self.keychainContents fillWithItems:items];
    }

    return self;
}

- (TKTokenSession *)token:(TKToken *)token createSessionWithError:(NSError **)error {
    NSLog(@"EstEIDToken createSessionWithError");
    return [[EstEIDTokenSession alloc] initWithToken:self];
}

@end

@implementation EstEIDTokenDriver

- (TKSmartCardToken *)tokenDriver:(TKSmartCardTokenDriver *)driver createTokenForSmartCard:(TKSmartCard *)smartCard AID:(NSData *)AID error:(NSError **)error {
    NSLog(@"EstEIDTokenDriver createTokenForSmartCard atr %@", smartCard.slot.ATR.bytes);

    const NSArray *supported = @[
        [NSData dataWithBytes:(const UInt8[]) // EstEID34_cold
        {0x3b, 0xfe, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2e, 0x30, 0xa8} length:24],
                                 
        [NSData dataWithBytes:(const UInt8[]) // EstEID35_cold
        {0x3b, 0xfa, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0xfe, 0x65, 0x49, 0x44, 0x20, 0x2f, 0x20, 0x50, 0x4b, 0x49, 0x03} length:20],

        [NSData dataWithBytes:(const UInt8[]) // EstEID34/5_warm
        {0x3b, 0xfe, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xa4, 0x16, 0x2a, 0x00, 0x83, 0x0f, 0x90, 0x00, 0xef} length:24]
    ];
    if ([supported containsObject:smartCard.slot.ATR.bytes]) {
        return [[EstEIDToken alloc] initWithSmartCard:smartCard AID:AID tokenDriver:self error:error];
    }
    if (error != nil) {
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeTokenNotFound userInfo:nil];
    }
    return nil;
}

@end
