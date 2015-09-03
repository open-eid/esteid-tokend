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
 *  EstEIDRecord.cpp
 */
#include "EstEIDRecord.h"
#include "EstEIDError.h"
#include "EstEIDToken.h"
#include <Security/SecKey.h>
#include "../tokend/MetaAttribute.h"
#include <security_cdsa_client/aclclient.h>
#include "EstEID_utility.h"

EstEIDRecord::EstEIDRecord(const char *description) :mDescription(description) {
    _log("new EstEIDRecord: description = '%s' ", mDescription);
}

const char *EstEIDRecord::description() {
    _log("EstEIDRecord::description '%s'", mDescription);
    return mDescription;
}

//
// EstEIDRecord
//
EstEIDRecord::~EstEIDRecord() {
    _log("~EstEIDRecord()");
}

EstEIDKeyRecord::EstEIDKeyRecord(const char *description, const Tokend::MetaRecord &metaRecord, bool signOnly) : EstEIDRecord(description), mSignOnly(signOnly) {
    _log("new EstEIDRecord: description = '%s', signOnly = %i", mDescription, signOnly);
    attributeAtIndex(metaRecord.metaAttribute(kSecKeyDecrypt).attributeIndex(), new Tokend::Attribute(true));
    attributeAtIndex(metaRecord.metaAttribute(kSecKeyUnwrap).attributeIndex(), new Tokend::Attribute(true));
    attributeAtIndex(metaRecord.metaAttribute(kSecKeySign).attributeIndex(), new Tokend::Attribute(true));
}

EstEIDKeyRecord::~EstEIDKeyRecord() {
    _log("~EstEIDKeyRecord()");
}

void EstEIDKeyRecord::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls) {
    FLOG;
    if (!mAclEntries) {
        _log("Init EstEIDKeyRecord ACL entries");
        mAclEntries.allocator(Allocator::standard());
        // Anyone can read the DB record for this key (which is a reference CSSM_KEY)
        mAclEntries.add(CssmClient::AclFactory::AnySubject(mAclEntries.allocator()), AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));

        char tmptag[20];
        int pinNum = 1;
        // This is hardcoded for now.
        // Apparently, more than one PIN slot is not supported.
        snprintf(tmptag, sizeof(tmptag), "PIN%d", pinNum);

        // PIN needs to be entered only once if this key is associated with PIN #1
        // and doesn't have the user consent bit set
        mAclEntries.add(CssmClient::AclFactory::PinSubject(mAclEntries.allocator(), pinNum),
                        AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_ENCRYPT,
                                            CSSM_ACL_AUTHORIZATION_DECRYPT,
                                            CSSM_ACL_AUTHORIZATION_SIGN,
                                            CSSM_ACL_AUTHORIZATION_MAC,
                                            CSSM_ACL_AUTHORIZATION_DERIVE,
                                            0), tmptag);
    }
    count = mAclEntries.size();
    acls = mAclEntries.entries();
}

EstEIDCertRecord::~EstEIDCertRecord() {
    _log("~EstEIDCertRecord()");
}

Tokend::Attribute *EstEIDCertRecord::getDataAttribute(Tokend::TokenContext *tokenContext) {
    _log("getDAtaAttribute, tokenContext = %p", tokenContext);
    EstEIDToken &mToken = static_cast<EstEIDToken &>(*tokenContext);
    CssmData data = mToken.getCert();
    Tokend::Attribute *attribute = new Tokend::Attribute(data.Data, data.Length);
    free(data.Data);
    return attribute;
}

