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
 *  EstEIDToken.cpp
 */
#include "EstEIDToken.h"

#include "EstEIDError.h"
#include "EstEIDRecord.h"
#include "EstEIDSchema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <security_cdsa_client/aclclient.h>
#include <Security/SecKey.h>

#include "../tokend/Adornment.h"
#include "EstEID_utility.h"


#define LOBYTE(w)           ((uint8_t)(((unsigned long)(w)) & 0xff))
#define HIBYTE(w)           ((uint8_t)((((unsigned long)(w)) >> 8) & 0xff))

#define INTER_COMMAND_DELAY	10000	// delay in microseconds between commands

#define OFF_CLA  0
#define OFF_INS  1
#define OFF_P1   2
#define OFF_P2   3
#define OFF_LC   4
#define OFF_DATA 5

#define ESTEID_MIN_PIN_LEN	4
#define ESTEID_MAX_PIN_LEN	4

#define ESTEID_MAXSIZE_CERT           4000

using namespace std;
using CssmClient::AclFactory;

static map<string,EstEIDToken::CardApplicationVersion> create_map()
{
    map<string,EstEIDToken::CardApplicationVersion> m;
    
    m["3BFE9400FF80B1FA451F034573744549442076657220312E3043"] = EstEIDToken::VER_1_0;
    m["3B6E00FF4573744549442076657220312E30"] = EstEIDToken::VER_1_0;
    m["3BDE18FFC080B1FE451F034573744549442076657220312E302B"] = EstEIDToken::VER_1_0_2007;
    m["3B5E11FF4573744549442076657220312E30"] = EstEIDToken::VER_1_0_2007;
    m["3B6E00004573744549442076657220312E30"] = EstEIDToken::VER_1_1;
    
    m["3BFE1800008031FE454573744549442076657220312E30A8"] = EstEIDToken::VER_3_4;
    m["3BFE1800008031FE45803180664090A4561B168301900086"] = EstEIDToken::VER_3_4;
    m["3BFE1800008031FE45803180664090A4162A0083019000E1"] = EstEIDToken::VER_3_4;
    m["3BFE1800008031FE45803180664090A4162A00830F9000EF"] = EstEIDToken::VER_3_4;
    
    m["3BF9180000C00A31FE4553462D3443432D303181"] = EstEIDToken::VER_3_5;
    m["3BF81300008131FE454A434F5076323431B7"] = EstEIDToken::VER_3_5;
    m["3BFA1800008031FE45FE654944202F20504B4903"] = EstEIDToken::VER_3_5;
    m["3BFE1800008031FE45803180664090A4162A00830F9000EF"] = EstEIDToken::VER_3_5;
    
    return m;
}
const map<string, EstEIDToken::CardApplicationVersion> EstEIDToken::supportedATRs =  create_map();
const static string CERT_LABEL = string("ESTEID_AUTH_CERTIFICATE");


EstEIDToken::EstEIDToken() : mPinStatus(0) {
    mTokenContext = this;
    mSession.open();
    _log("new EstEIDToken()");
}

EstEIDToken::~EstEIDToken() {
    delete mSchema;
    mSession.close();
    _log("~EstEIDToken()");
}

uint32 EstEIDToken::probe(SecTokendProbeFlags flags, char tokenUid[TOKEND_MAX_UID]) {
    
    _log("                      _          ");
    _log("      _ __  _ __ ___ | |__   ___ ");
    _log("     | '_ \\| '__/ _ \\| '_ \\ / _ \\");
    _log("     | |_) | | | (_) | |_) |  __/");
    _log("     | .__/|_|  \\___/|_.__/ \\___|");
    _log("     |_|                         ");
    
    uint32 score = 0;
    
    try {
        
        const SCARD_READERSTATE &readerState = *(*startupReaderInfo)();
        std::string atr = EstEidUtility::charsToHex((char *)readerState.rgbAtr, readerState.cbAtr);
        _log("current ATR: '%s'", atr.c_str());
        
        auto it = supportedATRs.find(atr);
        if (it != supportedATRs.end()) {
            appVersion = it -> second;
        
            _connectAndBeginTransaction();
            populatePersonalData();
            _endTransaction();
            std::memcpy(tokenUid,  personalData["documentNumber"].c_str(), personalData["documentNumber"].length());
            _log("Token recognized as '%s'", tokenUid);
            score = 310;
        } else {
            _log("This card is not supported!");
        }
        
    } catch (PCSC::Error &e) {
        _log("PCSC returned an error: %s (0x%lX)\n", pcsc_stringify_error(e.error), e.error);
        disconnect();
    } catch(const std::exception& ex) {
        _log("Something went wrong: %s", ex.what());
        disconnect();
    } catch(...) {
        _log("Unknown failure occured. Possible memory corruption");
        disconnect();
    }
    _log("Probe finished with score: %u!", score);
    return score;
}

void EstEIDToken::establish(const CSSM_GUID *guid, uint32 subserviceId,
    SecTokendEstablishFlags flags, const char *cacheDirectory,
    const char *workDirectory, char mdsDirectory[PATH_MAX],
    char printName[PATH_MAX]) {

    _log("              _        _     _ _     _     ");
    _log("     ___  ___| |_ __ _| |__ | (_)___| |__  ");
    _log("    / _ \\/ __| __/ _` | '_ \\| | / __| '_ \\ ");
    _log("   |  __/\\__ \\ || (_| | |_) | | \\__ \\ | | |");
    _log("    \\___||___/\\__\\__,_|_.__/|_|_|___/_| |_|");

    _log("printName = %s, cacheDir = %s, mdsDir = %s", printName, cacheDirectory, mdsDirectory);

    try {
        _connectAndBeginTransaction();
        Tokend::Token::establish(guid, subserviceId, flags, cacheDirectory, workDirectory, mdsDirectory, printName);
        
        CssmData authCert = getCert();
        size_t keySize = getKeySize(authCert);
        _log("Key size = %u", keySize);
        string cn = getCommonName(authCert);
        _log("CN = %s", cn.c_str() );
        string myPrintName = cn.append(" (PIN1)");
        strcat(printName, myPrintName.c_str());
        _log("PrintName = %s", myPrintName.c_str());
        mAuthKeyRef = getActiveAuthKeyRef();
        _log("Active authKey ref = %x", mAuthKeyRef);

        mSchema = new EstEIDSchema(keySize);
        mSchema->create();
        populate();
    } catch (PCSC::Error &e) {
        _log("PCSC returned an error: %s (0x%lX)\n", pcsc_stringify_error(e.error), e.error);
    } catch(const std::exception& ex) {
        _log("Something went wrong: %s", ex.what());
    } catch(...) {
        _log("Unknown failure occured. Possible memory corruption");
    }
    
    _endTransaction();
}

void EstEIDToken::authenticate(CSSM_DB_ACCESS_TYPE mode, const AccessCredentials *cred) {
    _log("authenticate mode = %u", mode);
    Token::authenticate(mode, cred);
}

void EstEIDToken::verifyPIN(int pinNum, const unsigned char *pin, size_t pinLength) {
  
    _log("                    _  __       ____ ___ _   _     ");
    _log("    __   _____ _ __(_)/ _|_   _|  _ \\_ _| \\ | |  ");
    _log("    \\ \\ / / _ \\ '__| | |_| | | | |_) | ||  \\| |");
    _log("     \\ V /  __/ |  | |  _| |_| |  __/| || |\\  |  ");
    _log("      \\_/ \\___|_|  |_|_|  \\__, |_|  |___|_| \\_|");
    _log("                          |___/                ");
    _log("pinNum = %u, pin length = %u!", pinNum, pinLength);
    
    if (pinNum != 1) {
        CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);
    }
    if (pinLength < ESTEID_MIN_PIN_LEN || pinLength > ESTEID_MAX_PIN_LEN) {
        _log("pin length:'%u' invalid!", pinLength);
        CssmError::throwMe(CSSM_ERRCODE_OPERATION_AUTH_DENIED);
    }
    for (uint32_t ix = 0; ix < pinLength;ix++) {
        if ( pin[ix] < '0' || pin[ix] > '9') {
            _log("pin contains invalid character (%u)! Only numbers allowed!" , pin[ix]);
            CssmError::throwMe(CSSMERR_DL_OPERATION_AUTH_DENIED);
        }
    }

    try {
        _connectAndBeginTransaction();
        PinString pinStr((char *) pin, pinLength);
        _verifyPin(pinStr);
        setPIN1(pinStr);
        // leave the transaction open, to allow signature generation in the same batch!
    } catch (EstEIDError &e) {
        _log("PIN verification failed! %s (0x%lX)\n\n\n", e.what(), mPinStatus);
        _endTransaction();
        throw;
    } catch (PCSC::Error &e) {
        _log("PCSC returned an error: %s (0x%lX)\n", pcsc_stringify_error(e.error), e.error);
        _endTransaction();
    } catch(const std::exception& ex) {
        _log("Something went wrong: %s", ex.what());
        _endTransaction();
    } catch(...) {
        _log("Unknown failure occured. Possible memory corruption");
        _endTransaction();
    }
}

void EstEIDToken::_verifyPin(PinString pin)  {
    selectMF();
    selectDF(0xEEEE);
    setSecEnv(0x01);
    setActiveAuthKey(mAuthKeyRef);
    mPinStatus = verify(1, (const unsigned char *)&pin[0], pin.length());
    EstEIDError::check(mPinStatus);
    _log("PIN verified successfully! (0x%lX)\n", mPinStatus);
}

CssmData EstEIDToken::getCert() {
    
    _log("getCert");
    CssmData data;
    
    if (cachedObject(0, CERT_LABEL, data)) {
        _log("using CACHED cert!");
        return data;
    } else {
        
        _log("read cert from token!");
        try {
            selectMF();
            selectDF(0xEEEE);
            selectEF(0xAACE);
            
            uint8 certificate[ESTEID_MAXSIZE_CERT];
            size_t certificateLength = sizeof(certificate);
            readBinary(certificate, certificateLength);
            
            _log("authentication certificate read (%u bytes): %s", certificateLength, EstEidUtility::charsToHex((char *) certificate, certificateLength).c_str());

            // remove padding
            if (certificateLength > 500 && certificate[0] == 0x30 && certificate[1] == 0x82) {
                size_t realCertLength = 256 * certificate[2] + certificate[3] + 4;
                if (realCertLength > 500 && realCertLength < certificateLength) {
                    data.Length = realCertLength;
                }
            } else {
                data.Length = certificateLength;
            }
            
            data.Data = reinterpret_cast<uint8 *>(malloc(data.Length + 1));
            memcpy(data.Data, &certificate[0], data.Length);
            _log("store cert in local cache: mDescription: %s", CERT_LABEL.c_str());
            cacheObject(0, CERT_LABEL, data);
            _log("authentication certificate read(%u bytes): %s", data.Length, EstEidUtility::charsToHex((char *) data.Data, data.Length).c_str());
            
        } catch (PCSC::Error &e) {
            _log("PCSC returned an error: %s (0x%lX)\n", pcsc_stringify_error(e.error), e.error);
        } catch(const std::exception& ex) {
            _log("Something went wrong: %s", ex.what());
        } catch(...) {
            _log("Unknown failure occured. Possible memory corruption");
        }
        
        return data;
    }
}

string EstEIDToken::getCommonName(CssmData certData) {
    
    const char *cn = NULL;
    SecCertificateRef certRef = 0;
    CFStringRef commonName = NULL;
    string result = "unknown";
    
    
    OSStatus status = SecCertificateCreateFromData(&certData, CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_BER, &certRef);
    if (!status)
    {
        CFStringRef commonName = NULL;
        SecCertificateCopyCommonName(certRef, &commonName);
        if (commonName) {
            
            CFIndex length = CFStringGetLength(commonName);
            CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
            char *buffer = (char *)malloc(maxSize);
                
            if (CFStringGetCString(commonName, buffer, maxSize, kCFStringEncodingUTF8)) {
                cn = buffer;
                result = string(buffer);
                if(buffer)
                    free(buffer);
            }
        }
    }

    if(certRef)
        CFRelease(certRef);
    if (commonName)
        CFRelease(commonName);
    
    return result;
}

size_t EstEIDToken::getKeySize(CssmData certData) {
    
    
    size_t keySize = 0;
    SecCertificateRef certRef = 0;
    SecKeyRef keyRef = 0;
    const CSSM_KEY *cssmKey = NULL;
    
    OSStatus status = SecCertificateCreateFromData(&certData, CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_BER, &certRef);
    if(status != noErr) goto done;
        status = SecCertificateCopyPublicKey(certRef, &keyRef);
    if(status != noErr) goto done;
        status = SecKeyGetCSSMKey(keyRef, &cssmKey);
    if(status != noErr) goto done;
        keySize = cssmKey->KeyHeader.LogicalKeySizeInBits;
done:
    if(keyRef)
        CFRelease(keyRef);
    if(certRef)
        CFRelease(certRef);
    return keySize;
}

uint32_t EstEIDToken::pinStatus(int pinNum) {
    FLOG;
    if (pinNum != 1) {
        CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);
    }
    return mPinStatus;
}

void EstEIDToken::unverifyPIN(int pinNum) {
    FLOG;
    if (pinNum != 1) {
        CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);
    }
    
    end(SCARD_RESET_CARD);
}

void EstEIDToken::getOwner(AclOwnerPrototype &owner) {
    FLOG;
    // we don't really know (right now), so claim we're owned by PIN #0
    if (!mAclOwner) {
        mAclOwner.allocator(Allocator::standard());
        mAclOwner = AclFactory::PinSubject(Allocator::standard(), 0);
    }
    owner = mAclOwner;
}

void EstEIDToken::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls) {
    FLOG;
    // get pin list, then for each pin in the future
    if (!mAclEntries) {
        _log("Init EstEIDToken ACL entries");
        mAclEntries.allocator(Allocator::standard());
        // Anyone can read the attributes and data of any record on this token (it's further limited by the object itself).
        mAclEntries.add(CssmClient::AclFactory::AnySubject(mAclEntries.allocator()), AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));
        mAclEntries.addPin(AclFactory::PWSubject(mAclEntries.allocator()), 1);
        mAclEntries.addPin(AclFactory::PromptPWSubject(mAclEntries.allocator(), CssmData()), 1);
    }
    count = mAclEntries.size();
    acls = mAclEntries.entries();
}

void EstEIDToken::populate() {
    FLOG;
    
    Tokend::Relation &certRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_X509_CERTIFICATE);
    Tokend::Relation &privateKeyRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_PRIVATE_KEY);
    
    RefPointer<Tokend::Record> eAuthCert(new EstEIDCertRecord("Authentication Certificate"));
    certRelation.insertRecord(eAuthCert);

    RefPointer<Tokend::Record> eAuthKey(new EstEIDKeyRecord("Authentication Key", privateKeyRelation.metaRecord(), true));
    privateKeyRelation.insertRecord(eAuthKey);
    eAuthKey->setAdornment(mSchema->publicKeyHashCoder().certificateKey(), new Tokend::LinkedRecordAdornment(eAuthCert));
}

#define READ_BLOCK_SIZE  0xF4

/*
	A full transaction for the readBinary command seems to be the following:
	
	- Select the appropriate file [ref INS_SELECT_FILE]
	- Issue read binary command (0xB0) for READ_BLOCK_SIZE (0xF4) bytes
	- usually, it will come back with a response of "6C xx", where xx is the
 actual number of bytes available
	- Issue a new read binary command with correct size
	
 */

/*
	See NIST IR 6887, 5.1.1.2 Read Binary APDU
 
	Function Code 0x02
	
	CLA			0x00
	INS			0xB0
	P1			High-order byte of 2-byte offset
	P2			Low-order byte of 2-byte offset
	Lc			Empty
	Data Field	Empty
	Le			Number of bytes to read
 
 
	Processing State returned in the Response Message
 
	SW1 SW2		Meaning
	---	---	-----------------------------------------------------
	62	81	Part of returned data may be corrupted
	62	82	End of file reached before reading Le bytes
	67	00	Wrong length (wrong Le field)
	69	81	Command incompatible with file structure
	69	82	Security status not satisfied
	69	86	Command not allowed (no current EF)
	6A	81	Function not supported
	6A	82	File not found
	6B	00	Wrong parameters (offset outside the EF)
	6C	XX	Wrong length (wrong Le field; XX indicates the exact length)
	90	00	Successful execution
	
	Non-fatal errors:
	62	82	End of file reached before reading Le bytes
	6B	00	Wrong parameters (offset outside the EF)
	6C	XX	Wrong length (wrong Le field; XX indicates the exact length)
	90	00	Successful execution
 */

void EstEIDToken::readBinary(uint8_t *result, size_t &resultLength) {
    // Attempt to read READ_BLOCK_SIZE bytes
    
    unsigned char rcvBuffer[MAX_BUFFER_SIZE];		// N.B. Must be > READ_BLOCK_SIZE
    size_t bytesReceived = sizeof(rcvBuffer);
    size_t returnedDataLength = 0;
    
    // The initial "Read Binary" command, with offset 0 and length READ_BLOCK_SIZE
    unsigned char apdu[] = { 0x00, 0xB0, 0x00, 0x00, READ_BLOCK_SIZE };
    size_t apduSize = sizeof(apdu);
    // Talk to token here to get data
    uint16_t rx;
    uint32_t offset = 0;
    bool requestedTooMuch = false;
    for (bool done = false; !done; ) {
        
        bytesReceived = sizeof(rcvBuffer);	// must reset each time
        _log("readBinary: attempting read of %d bytes at offset: %d", apdu[OFF_LC], (apdu[OFF_P1] << 8 | apdu[OFF_P2]));
        transmit(apdu, apduSize, rcvBuffer, bytesReceived);
        if (bytesReceived < 2)
        break;
        
        rx = (rcvBuffer[bytesReceived - 2] << 8) + rcvBuffer[bytesReceived - 1];
        _log("readBinary result 0x%02X (masked: 0x%02X)", rx, rx & 0xFF00);
        
        switch (rx & 0xFF00) {
            case SCARD_BYTES_LEFT_IN_SW2:		// 0x6100
            case SCARD_LE_IN_SW2:				// 0x6C00
                _log("readBinary should only have read: %d bytes", rx & 0x00FF);
                // Re-read from same offset with new, shorter length
                apdu[OFF_LC] = (uint8_t)(rx & 0xFF);
                requestedTooMuch = true;				// signal that we are almost done
                break;
            case SCARD_WRONG_PARAMETER_P1_P2:			// we read past the end, (probably) non-fatal
                done = true;
                break;
            case SCARD_SUCCESS:
                offset += (bytesReceived - 2);
                apdu[OFF_P1] = offset >> 8;
                apdu[OFF_P2] = offset & 0xFF;
                apdu[OFF_LC] = READ_BLOCK_SIZE & 0xFF;
                if (requestedTooMuch)
                    done = true;
                if (resultLength >= (returnedDataLength + bytesReceived - 2)) {
                    memcpy(result + returnedDataLength, rcvBuffer, bytesReceived - 2);
                    returnedDataLength += bytesReceived - 2;
                } else {
                    done = true;
                }
                break;
            case SCARD_EXECUTION_WARNING:	// No way to recover from SCARD_END_OF_FILE_REACHED, so fall through
                done = true;
                break;
            default:
                EstEIDError::check(rx);
                return;						// will actually throw above
        }
    }
    
    _log("readBinary read a total of %ld bytes", returnedDataLength);
    resultLength = returnedDataLength;
}

// ----- Card commands -----

void EstEIDToken::selectMF() {
    _log("SELECT MF");
    uint8_t command[] = { 0x00, 0xA4, 0x00, 0x0C };
    unsigned char result[MAX_BUFFER_SIZE];
    size_t resultLength = sizeof(result);
    EstEIDError::check(exchangeAPDU(command, sizeof(command), result, resultLength));
}

void EstEIDToken::selectDF(uint16_t fileID) {
    _log("SELECT DF");
    uint8_t command[] = { 0x00, 0xA4, 0x01, 0x04, 0x02, HIBYTE(fileID), LOBYTE(fileID) };
    unsigned char result[MAX_BUFFER_SIZE];
    size_t resultLength = sizeof(result);
    EstEIDError::check(exchangeAPDU(command, sizeof(command), result, resultLength));
}

uint16_t EstEIDToken::getActiveAuthKeyRef() {
    selectMF();
    selectDF(0xEEEE);
    selectEF(0x0033);
    string record = readRecord(0x01);
    uint8_t const *c = (uint8_t const *)record.substr(9,10).c_str();
    return (c[0] << 8) + c[1];
}

void EstEIDToken::setActiveAuthKey(uint16_t authKeyRef) {
    _log("SET ACTIVE AUTH KEY to 0x%lX 0x%lX", HIBYTE(mAuthKeyRef), LOBYTE(mAuthKeyRef));
    uint8_t command[] = { 0x00, 0x22, 0x41, 0xB8, 0x05, 0x83, 0x03, 0x80, HIBYTE(authKeyRef), LOBYTE(authKeyRef)};
    unsigned char result[MAX_BUFFER_SIZE];
    size_t resultLength = sizeof(result);
    EstEIDError::check(exchangeAPDU(command, sizeof(command), result, resultLength));
}

uint32_t EstEIDToken::verify(uint8_t pinNum, const unsigned char *pin, uint8_t pinLength) {
    _log("VERIFY");
    uint8_t command[] = { 0x00, 0x20, 0x00, pinNum, 0x04, 0xFF, 0xFF, 0xFF, 0xFF };
    uint32_t offset = 4;
    command[offset++] = pinLength;
    for (uint32_t ix = 0; ix < pinLength;ix++) {
        command[offset++] = static_cast<unsigned>(pin[ix]);
    }
    unsigned char result[MAX_BUFFER_SIZE];
    size_t resultLength = sizeof(result);
    return exchangeAPDU(command, sizeof(command), result, resultLength);
}

void EstEIDToken::selectEF(uint16_t fileID) {
    _log("SELECT EF");
    uint8_t command[] = { 0x00, 0xA4, 0x02, 0x04, 0x02, HIBYTE(fileID), LOBYTE(fileID) };
    unsigned char result[MAX_BUFFER_SIZE];
    size_t resultLength = sizeof(result);
    EstEIDError::check(exchangeAPDU(command, sizeof(command), result, resultLength));
}

void EstEIDToken::setSecEnv(uint8_t envNo) {
    _log("MANAGE SECURITY ENVIRONMENT");
    uint8_t command[] = { 0x00, 0x22, 0xF3, envNo };
    unsigned char result[MAX_BUFFER_SIZE];
    size_t resultLength = sizeof(result);
    EstEIDError::check(exchangeAPDU(command, sizeof(command), result, resultLength));
}

string EstEIDToken::readRecord(uint8_t recNo) {
    _log("READ RECORD");
    uint8_t command[] = { 0x00, 0xB2, recNo, 0x04 };
    unsigned char result[MAX_BUFFER_SIZE];
    size_t resultLength = sizeof(result);
    EstEIDError::check(exchangeAPDU(command, sizeof(command), result, resultLength));
    return string( (char *)result, resultLength - 2 );
}

void EstEIDToken::populatePersonalData() {
    _log("READ PERSONAL DATA FROM CARD");
    selectMF();
    selectDF(0xEEEE);
    selectEF(0x5044);
    string docNo = readRecord(0x08);
    personalData["documentNumber"] = docNo;
}

string EstEIDToken::getTLSResponse(std::vector<uint8_t> hash) {
    unsigned char result[MAX_BUFFER_SIZE];
    size_t resultLength = sizeof(result);
    uint8_t signCmdAut[] = { 0x00, 0x88, 0x00, 0x00 };
    std::vector<uint8_t> cmd = std::vector<uint8_t>(signCmdAut, signCmdAut + (sizeof(signCmdAut)/sizeof(*(signCmdAut))));
    cmd.push_back((char) (hash.size()));
    cmd.insert(cmd.end(), hash.begin(), hash.end());
    EstEIDError::check(exchangeAPDU(&cmd[0], (unsigned long)cmd.size(), result, resultLength));
    return string( (char *)result, resultLength - 2 );
}

uint32_t EstEIDToken::exchangeAPDU(uint8_t *apdu, size_t apduLength, uint8_t *result, size_t &resultLength) {

    _log("-----[ apdu to be executed (%u bytes) ] -----> %s", apduLength, EstEidUtility::charsToHex((char *) apdu, apduLength).c_str());
    size_t savedLength = resultLength;
    transmit(apdu, apduLength, result, resultLength);
    _log("-----[ apdu response (%u bytes)       ] <----- %s", resultLength, EstEidUtility::charsToHex((char *) result, resultLength).c_str());
    if (resultLength == 2 && result[0] == 0x61) {
        
        resultLength = savedLength;
        uint8 expectedLength = result[1];
        _log("reading expected result of %u bytes", expectedLength);
        unsigned char getResult[] = { 0x00, 0xC0, 0x00, 0x00, expectedLength };
        EstEIDToken::usleep(INTER_COMMAND_DELAY);
        transmit(getResult, sizeof(getResult), result, resultLength);
        _log("-----[ apdu response (%u bytes)      ] <----- %s", resultLength, EstEidUtility::charsToHex((char *) result, resultLength).c_str());
        
        if ((resultLength - 2 != expectedLength) && resultLength < 2) {
            PCSC::Error::throwMe(SCARD_E_PROTO_MISMATCH);
        }
    }
    
    if (resultLength < 2)
        PCSC::Error::throwMe(SCARD_E_PROTO_MISMATCH);
    
    return (result[resultLength - 2] << 8) + result[resultLength - 1];
}

/**
 * @brief Makes the current process sleep for some microseconds.
 *
 * @param[in] iTimeVal Number of microseconds to sleep.
 */
int EstEIDToken::usleep(int iTimeVal) {
    struct timespec mrqtp;
    mrqtp.tv_sec = iTimeVal/1000000;
    mrqtp.tv_nsec = (iTimeVal - (mrqtp.tv_sec * 1000000)) * 1000;
    return nanosleep(&mrqtp, NULL);
}


/**
 * Sets up a valid connection and transaction
 */
int EstEIDToken::_connectAndBeginTransaction() {

    const SCARD_READERSTATE &readerState = *(*startupReaderInfo)();

    int maxRetries = 5;
    
    // if someone or something has reset the card in between, then try to cope with that
    for (int i = 0; i < maxRetries; i++) {
        
        if (i > 0) {
            _log("Waiting 0,5 sec to retry %u", i);
            usleep(500000); // wait for 0,5 sec
        }
        
        // reestablish connection if necessary
        if (!isConnected())  {
            try {
                _log("Connecting using reader: %s - current state: 0x%lX, event state: 0x%lX", readerState.szReader, readerState.dwCurrentState, readerState.dwEventState);
                connect(mSession, readerState.szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0);
                _log("Connected!");
            } catch (PCSC::Error &e) {
                _log("PCSC returned an error while connecting: %s (0x%lX)\n", pcsc_stringify_error(e.error), e.error);
                continue;
            }
        } else {
            _log("Already connected!");
        }
        
        
        if (!isInTransaction()) {
            try {
                _log("Start transaction...");
                begin();
                return i; // we are all set up, return with retry count!
            } catch (PCSC::Error &e) {
                _log("PCSC returned an error while starting transaction: %s (0x%lX)\n", pcsc_stringify_error(e.error), e.error);
            }
        } else {
            _log("Already in transaction!");
            return i; // we are all set up, return with retry count!
        }
        
    }
    
    _log("Retry count exceeded!");
    return maxRetries;
}

/**
 * Silently ends transaction (ignores SCARD_W_RESET_CARD errors)
 */
void EstEIDToken::_endTransaction() {
    try {
        if (isInTransaction()) 
            end();
    } catch (PCSC::Error &e) {
        if (e.error == SCARD_W_RESET_CARD)
            _log("PCSC returned an error while ending transaction: %s (0x%lX)\n", pcsc_stringify_error(e.error), e.error);
        else
            throw e;
    }
}

void EstEIDToken::didDisconnect() {
    _log("did disconnect");
    PCSC::Card::didDisconnect();
    mPinStatus = 0;
}

void EstEIDToken::didEnd() {
    _log("did end");
    PCSC::Card::didEnd();
    mPinStatus = 0;
}

void EstEIDToken::setPIN1(PinString PIN1)
{
    FLOG;
    this->pin1 = PIN1;
}

PinString EstEIDToken::getPIN1()
{
    FLOG;
    return this->pin1;
}

