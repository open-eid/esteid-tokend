/*
 * EstEID.tokend
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL)
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 *
 */

/*
 *  EstEIDSchema.cpp
 */
#include "EstEIDSchema.h"
#include "../tokend/MetaAttribute.h"
#include <Security/SecKey.h>
#include "EstEID_utility.h"

using namespace Tokend;

EstEIDSchema::EstEIDSchema(uint32_t keySize) : mKeyAlgorithmCoder(uint32_t(CSSM_ALGID_RSA)), mKeySizeCoder(keySize) {
    _log("new EstEIDSchema: keySize = %u", keySize);
}

EstEIDSchema::~EstEIDSchema() {
    _log("~EstEIDSchema()");
}

Tokend::Relation *EstEIDSchema::createKeyRelation(CSSM_DB_RECORDTYPE keyType) {
    FLOG;

    Relation *rn = createStandardRelation(keyType);

    // Set up coders for key records.
    MetaRecord &mr = rn->metaRecord();
    mr.keyHandleFactory(&mEstEIDKeyHandleFactory);

    // Print name of a key might as well be the key name.
    mr.attributeCoder(kSecKeyPrintName, &mDescriptionCoder);

    // Other key values
    mr.attributeCoder(kSecKeyKeyType, &mKeyAlgorithmCoder);
    mr.attributeCoder(kSecKeyKeySizeInBits, &mKeySizeCoder);
    mr.attributeCoder(kSecKeyEffectiveKeySize, &mKeySizeCoder);

    // Key attributes
    mr.attributeCoder(kSecKeyExtractable, &mFalseCoder);
    mr.attributeCoder(kSecKeySensitive, &mTrueCoder);
    mr.attributeCoder(kSecKeyModifiable, &mFalseCoder);
    mr.attributeCoder(kSecKeyPrivate, &mTrueCoder);
    mr.attributeCoder(kSecKeyNeverExtractable, &mTrueCoder);
    mr.attributeCoder(kSecKeyAlwaysSensitive, &mTrueCoder);

    // Key usage
    mr.attributeCoder(kSecKeyEncrypt, &mFalseCoder);
    mr.attributeCoder(kSecKeyWrap, &mFalseCoder);
    mr.attributeCoder(kSecKeyVerify, &mFalseCoder);
    mr.attributeCoder(kSecKeyDerive, &mFalseCoder);
    mr.attributeCoder(kSecKeySignRecover, &mFalseCoder);
    mr.attributeCoder(kSecKeyVerifyRecover, &mFalseCoder);

    return rn;
}

void EstEIDSchema::create() {
    Schema::create();
    createStandardRelation(CSSM_DL_DB_RECORD_X509_CERTIFICATE);
    createKeyRelation(CSSM_DL_DB_RECORD_PRIVATE_KEY);
}

