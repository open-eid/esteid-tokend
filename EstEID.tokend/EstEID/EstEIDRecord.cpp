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
  _log("EstEIDRecord '%s' created", mDescription);
}

const char *EstEIDRecord::description() {
  _log("EstEIDRecord::description '%s'", mDescription);
  return mDescription;
}

//
// EstEIDRecord
//
EstEIDRecord::~EstEIDRecord() {
}

EstEIDKeyRecord::EstEIDKeyRecord(const char *description, const Tokend::MetaRecord &metaRecord, bool signOnly) : EstEIDRecord(description), mSignOnly(signOnly) {
  FLOG;
  attributeAtIndex(metaRecord.metaAttribute(kSecKeyDecrypt).attributeIndex(), new Tokend::Attribute(true));
  attributeAtIndex(metaRecord.metaAttribute(kSecKeyUnwrap).attributeIndex(), new Tokend::Attribute(true));
  attributeAtIndex(metaRecord.metaAttribute(kSecKeySign).attributeIndex(), new Tokend::Attribute(true));
}

EstEIDKeyRecord::~EstEIDKeyRecord() {
}

void EstEIDKeyRecord::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls) {
  FLOG;

  // @@@ Key 1 has any acl for sign, key 2 has pin1 acl, and key3 has pin1
  // acl with auto-lock which we express as a prompted password subject.
  if (!mAclEntries) {
    mAclEntries.allocator(Allocator::standard());
    // Anyone can read the DB record for this key (which is a reference
    // CSSM_KEY)
    mAclEntries.add(CssmClient::AclFactory::AnySubject(mAclEntries.allocator()), AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));

    // Using this key to sign or decrypt will require PIN1
//		mAclEntries.add(CssmClient::AclFactory::PinSubject( mAclEntries.allocator(), 1), AclAuthorizationSet((mSignOnly ? CSSM_ACL_AUTHORIZATION_SIGN : CSSM_ACL_AUTHORIZATION_DECRYPT), 0));



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
}

Tokend::Attribute *EstEIDCertRecord::getDataAttribute(Tokend::TokenContext *tokenContext) {
  FLOG;
  _log("getDAtaAttribute, tokenContext = %p", tokenContext);
  EstEIDToken &token = dynamic_cast<EstEIDToken &>(*tokenContext);

  CssmData data;
  Tokend::Attribute *attribute;

  if (!token.cachedObject(0, mDescription, data)) {
    try {
      std::vector<byte> arrCert = token.getCard().getAuthCert();

      data.Data = reinterpret_cast<uint8 *>(malloc(arrCert.size()));
      memcpy(data.Data, &arrCert[0], arrCert.size());
      data.Length = arrCert.size();
    } catch (std::exception &err) {
      _log("exception thrown in *EstEIDCertRecord::getDataAttribute '%s'", err.what());
      return NULL;
    }
    token.cacheObject(0, mDescription, data);
  }

  attribute = new Tokend::Attribute(data.Data, data.Length);
  delete [] data.Data;

  return attribute;
}



