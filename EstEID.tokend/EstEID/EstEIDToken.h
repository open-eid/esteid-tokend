/*
 * EstEID.tokend
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL) or the BSD License (see LICENSE.BSD).
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
#include "../../smartcardpp/common.h"
#include "../../smartcardpp/EstEIDManager.h"

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

  virtual void establish(const CSSM_GUID *guid, uint32 subserviceId,
      SecTokendEstablishFlags flags, const char *cacheDirectory, const char *workDirectory,
      char mdsDirectory[PATH_MAX], char printName[PATH_MAX]);

  virtual void getOwner(AclOwnerPrototype &owner);

  virtual void getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls);

  virtual uint32_t pinStatus(int pinNum);

  virtual void verifyPIN(int pinNum,
      const unsigned char *pin, size_t pinLength);

  virtual void unverifyPIN(int pinNum);
    
    PinString getPIN1();
    void setPIN1(PinString PIN1);

protected:
  void populate();

  void loadX509SubjectNames();

  EstEIDManager &getCard();

private:
  void checkPrivate();

  map<string, string> X509_subject_names;
    
    PinString pin1;

public:
  void *mConnection;
  EstEIDTokenPriv *d;

  uint32_t mPinStatus;

  void authenticate(CSSM_DB_ACCESS_TYPE mode, const AccessCredentials *cred);

  // temporary ACL cache hack - to be removed
  AutoAclOwnerPrototype mAclOwner;
  AutoAclEntryInfoList mAclEntries;
};


#endif /* !_ESTEIDTOKEN_H_ */

