/*
 * EstEID.tokend
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 *
 */

/*
 *  EstEIDToken.h
 */

#ifndef _ESTEIDTOKEN_H_
#define _ESTEIDTOKEN_H_

#include <security_utilities/pcsc++.h>
#include "../tokend/Token.h"
#include "PinString.h"

class EstEIDSchema;
class EstEIDTokenPriv;

//
// "The" token
//
class EstEIDToken : public Tokend::ISO7816Token {
    friend class EstEIDRecord;
    friend class EstEIDCertRecord;
    friend class EstEIDKeyHandle;
    
    NOCOPY(EstEIDToken)

public:
    EstEIDToken();
    ~EstEIDToken();
    
    virtual uint32 probe(SecTokendProbeFlags flags, char tokenUid[TOKEND_MAX_UID]);
    virtual void establish(const CSSM_GUID *guid, uint32 subserviceId, SecTokendEstablishFlags flags,
                           const char *cacheDirectory, const char *workDirectory,
                           char mdsDirectory[PATH_MAX], char printName[PATH_MAX]);
    virtual void getOwner(AclOwnerPrototype &owner);
    virtual void getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls);
    virtual uint32_t pinStatus(int pinNum);
    virtual void verifyPIN(int pinNum, const unsigned char *pin, size_t pinLength);
    virtual void unverifyPIN(int pinNum);
    
    // ----- card communication -----
    void readBinary(uint8_t *result, size_t &resultLength);
    void selectMF();
    void selectDF(uint16_t fileID);
    void selectEF(uint16_t fileID);
    void setSecEnv(uint8_t envNo);
    string readRecord(uint8_t recNo);
    uint16_t getActiveAuthKeyRef();
    void setActiveAuthKey(uint16_t authKeyRef);
    string getTLSResponse(std::vector<uint8_t> hash);
    uint32_t verify(uint8_t pinNum, const unsigned char *pin, uint8_t pinLength);

    virtual void didDisconnect();
    virtual void didEnd();
    
    enum CardApplicationVersion {
        VER_INVALID,
        VER_1_0,
        VER_1_0_2007,
        VER_1_1,
        VER_3_4,
        VER_3_5,
    };

protected:
    void populate();
    void populatePersonalData();
    int _connectAndBeginTransaction();
    void _endTransaction();
    void _verifyPin(PinString pin);
    
private:
    void setUpTokenPrintName();
    CardApplicationVersion appVersion;
    map<string, string> personalData;
    static const map<string, CardApplicationVersion> supportedATRs;
    CssmData getCert();
    size_t getKeySize(CssmData certData);
    string getCommonName(CssmData certData);
    PinString pin1;
    PinString getPIN1();
    void setPIN1(PinString PIN1);
    
public:
    uint32_t mPinStatus;
    uint16_t mAuthKeyRef;
    
    void authenticate(CSSM_DB_ACCESS_TYPE mode, const AccessCredentials *cred);
    uint32_t exchangeAPDU(uint8_t *apdu, size_t apduLength, uint8_t *result, size_t &resultLength);
    static int usleep(int iTimeVal);

    // temporary ACL cache hack - to be removed
    AutoAclOwnerPrototype mAclOwner;
    AutoAclEntryInfoList mAclEntries;
};

#endif /* !_ESTEIDTOKEN_H_ */




