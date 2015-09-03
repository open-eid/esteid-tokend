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
 *  EstEIDKeyHandle.cpp
 */

#include "EstEIDKeyHandle.h"

#include "EstEIDRecord.h"
#include "EstEIDToken.h"
#include "EstEIDError.h"

#include "EstEID_utility.h"

//
// EstEIDKeyHandle
//
EstEIDKeyHandle::EstEIDKeyHandle(EstEIDToken &token, const Tokend::MetaRecord &metaRecord, EstEIDKeyRecord &record) :
Tokend::KeyHandle(metaRecord, &record), mToken(token) {
    _log("new EstEIDKeyHandle()");
}

EstEIDKeyHandle::~EstEIDKeyHandle() {
    _log("~EstEIDKeyHandle()");
}

void EstEIDKeyHandle::getKeySize(CSSM_KEY_SIZE &keySize) {
    FLOG;
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}

uint32 EstEIDKeyHandle::getOutputSize(const Context &context, uint32 inputSize, bool encrypting) {
    FLOG;
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}

void EstEIDKeyHandle::generateSignature(const Context &context, CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature) {

    _log("                                    _       ____  _                   _");
    _log("     __ _  ___ _ __   ___ _ __ __ _| |_ ___/ ___|(_) __ _ _ __   __ _| |_ _   _ _ __ ___");
    _log("    / _` |/ _ \\ '_ \\ / _ \\ '__/ _` | __/ _ \\___ \\| |/ _` | '_ \\ / _` | __| | | | '__/ _ \\");
    _log("   | (_| |  __/ | | |  __/ | | (_| | ||  __/___) | | (_| | | | | (_| | |_| |_| | | |  __/");
    _log("    \\__, |\\___|_| |_|\\___|_|  \\__,_|\\__\\___|____/|_|\\__, |_| |_|\\__,_|\\__|\\__,_|_|  \\___|");
    _log("     |___/                                           |___/");
    _log("EstEIDKeyHandle::generateSignature alg: %u signOnly: %u", context.algorithm(), signOnly);
    IFDUMPING("esteid.tokend", context.dump("signature context"));
    
    if (context.type() != CSSM_ALGCLASS_SIGNATURE)
        CssmError::throwMe(CSSMERR_CSP_INVALID_CONTEXT);

    if (context.algorithm() != CSSM_ALGID_RSA)
        CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);
    
    if (signOnly != CSSM_ALGID_NONE)
        CssmError::throwMe(CSSMERR_CSP_INVALID_DIGEST_ALGORITHM);
    
    _log("SSL signature request - Special case used by SSL (RSA signature, without the ASN1 stuff)");

    try {
        
        int wasReset = mToken._connectAndBeginTransaction();
        
        if (wasReset) {
            _log("Someone has reset the card! Using cached pin, to reset the sec env...");
            mToken._verifyPin(mToken.getPIN1());
        }
        
        _generateRsaSignature(input, signature);
        _log("Signature successfully generated!");
        
    } catch (PCSC::Error &e) {
        _log("PCSC returned an error: %s (0x%lX)\n", pcsc_stringify_error(e.error), e.error);
    } catch(const std::exception& ex) {
        _log("Something went wrong %s", ex.what());
    } catch(...) {
        _log("Unknown failure occured. Possible memory corruption");
    }
    
    mToken._endTransaction();
}

void EstEIDKeyHandle::_generateRsaSignature(const CssmData &input, CssmData &signature) {
    
    /* Use ref to a new buffer item to keep the data around after the function ends */
    unsigned char *outputData;
    
    try {
        _log("Challenge length = %u bytes", input.length());
        string tlsResponse = mToken.getTLSResponse(std::vector<uint8_t>(input.Data, input.Data + input.Length));
        _log("Signature (%u bytes): %s", tlsResponse.length(), EstEidUtility::string_to_hex(tlsResponse).c_str());
        outputData = reinterpret_cast<unsigned char *>(malloc(tlsResponse.length()));
        memcpy(outputData, &tlsResponse[0], tlsResponse.length());
        signature.Data = outputData;
        signature.Length = tlsResponse.length();
    } catch (...) {
        // @@@ Switch to using tokend allocators?
        if (outputData)
            free(outputData);
        throw;
    }
}


void EstEIDKeyHandle::verifySignature(const Context &context, CSSM_ALGORITHMS signOnly, const CssmData &input, const CssmData &signature) {
    FLOG;
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}

void EstEIDKeyHandle::generateMac(const Context &context, const CssmData &input, CssmData &output) {
    FLOG;
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}

void EstEIDKeyHandle::verifyMac(const Context &context, const CssmData &input, const CssmData &compare) {
    FLOG;
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}

void EstEIDKeyHandle::encrypt(const Context &context, const CssmData &clear, CssmData &cipher) {
    FLOG;
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}

void EstEIDKeyHandle::decrypt(const Context &context, const CssmData &cipher, CssmData &clear) {
    FLOG;
    CssmError::throwMe(CSSMERR_CSP_KEY_USAGE_INCORRECT);
}

void EstEIDKeyHandle::exportKey(const Context &context, const AccessCredentials *cred, CssmKey &wrappedKey) {
    FLOG;
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}

//
// EstEIDKeyHandleFactory
//
EstEIDKeyHandleFactory::~EstEIDKeyHandleFactory() {
}


Tokend::KeyHandle *EstEIDKeyHandleFactory::keyHandle(Tokend::TokenContext *tokenContext, const Tokend::MetaRecord &metaRecord,Tokend::Record &record) const {
    FLOG;
    EstEIDKeyRecord &keyRecord = dynamic_cast<EstEIDKeyRecord &>(record);
    EstEIDToken &eToken = static_cast<EstEIDToken &>(*tokenContext);
    return new EstEIDKeyHandle(eToken, metaRecord, keyRecord);
}
