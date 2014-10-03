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
 *  EstEIDToken.cpp
 */
#include "openssl/x509.h"
#include "EstEIDToken.h"

#include "EstEIDError.h"
#include "EstEIDRecord.h"
#include "EstEIDSchema.h"

#include <security_cdsa_client/aclclient.h>

#include "../tokend/Adornment.h"
#include "EstEID_utility.h"


using CssmClient::AclFactory;

class EstEIDTokenPriv {
  EstEIDManager *eCard;
  EstEIDManager *global;
  
public:
  EstEIDTokenPriv() : eCard(NULL) {
    global = new EstEIDManager();
  }
  
  ~EstEIDTokenPriv() {
    if (global) {
      delete global;
      global = NULL;
    }
  }

  EstEIDManager &card() {
    if (!eCard) throw std::runtime_error("not connected");
    return *eCard;
  }

  bool connectCard(const char *givenReaderName) {
    disconnect();
    uint tokenCount = global->getTokenCount(TRUE);
    _log("token count = %i", tokenCount);
      
    for (uint i = 0; i < tokenCount; i++) {
      eCard = new EstEIDManager(i);
      if (!eCard->isInReader(i)) {
        _log("Skipping reader %i. No card in reader.", i);
        disconnect();
        continue;
      }

      std::string readerName = eCard->getReaderName();
      _log("Found card in reader %s", readerName.c_str() );
      
      if (readerName != givenReaderName) {
        _log("Reader name not matching given reader %s.", givenReaderName);
        disconnect();
        continue;
      }

      _log("We have our reader. Card id: %s", eCard->readDocumentID().c_str());
      return true;
    }
    return false;
  }

  void disconnect() {
    if (eCard) {
      delete eCard;
      eCard = NULL;
    }
  }
};

EstEIDToken::EstEIDToken() : d(NULL), mPinStatus(0) {
  mTokenContext = this;
  try {
    _log("d = %p", d);
    d = new EstEIDTokenPriv;
  } catch(std::exception &) {}
}

EstEIDToken::~EstEIDToken() {
  if (d)
    delete d;
}

void EstEIDToken::checkPrivate() {
  if (!d) {
    _log("PCSSMgr uninitialized");
    CssmError::throwMe(CSSM_ERRCODE_SELF_CHECK_FAILED);
  }
}

uint32 EstEIDToken::probe(SecTokendProbeFlags flags, char tokenUid[TOKEND_MAX_UID]) {
  FLOG;
  checkPrivate();
  uint32 retCode = NULL;

  const SCARD_READERSTATE &readerState = *(*startupReaderInfo)();
  _log("given reader was '%s'", readerState.szReader);
  try {
    if (d->connectCard(readerState.szReader)) {
      _log("document id: %s", d->card().readDocumentID().c_str());
      strncpy(tokenUid, d->card().readDocumentID().c_str(), TOKEND_MAX_UID);
      retCode = 301;
      d->disconnect();
    }
  } catch(std::runtime_error &err) {
    _log("exception: %s", err.what() );
  }
  return retCode;
}

using namespace std;

void EstEIDToken::establish(const CSSM_GUID *guid, uint32 subserviceId, SecTokendEstablishFlags flags, const char *cacheDirectory,
                            const char *workDirectory, char mdsDirectory[PATH_MAX], char printName[PATH_MAX]) {
  FLOG;

  _log("printName = %s, cacheDir = %s, mdsDir = %s", printName, cacheDirectory, mdsDirectory);
  Token::establish(guid, subserviceId, flags, cacheDirectory, workDirectory, mdsDirectory, printName);
  checkPrivate();

  const SCARD_READERSTATE &readerState = *(*startupReaderInfo)();

  try {
    if (d->connectCard(readerState.szReader)) {
      loadX509SubjectNames();

      strcat(printName, X509_subject_names["givenName"].c_str());
      strcat(printName, " ");
      strcat(printName, X509_subject_names["surname"].c_str());
      strcat(printName, ", ");
      strcat(printName, X509_subject_names["serialNumber"].c_str());
      strcat(printName, " (PIN1)");

      mSchema = new EstEIDSchema(d->card().getKeySize());
      mSchema->create();
      populate();
    }

  } catch(std::runtime_error &err) {
    _log("exception: %s", err.what() );
  }
}

void EstEIDToken::loadX509SubjectNames() {
  std::vector<byte> arrCert = d->card().getAuthCert();
  const unsigned char *p = &arrCert[0];
  X509 *x509 = d2i_X509(NULL, &p, arrCert.size());
  X509_name_st *x509Name = X509_get_subject_name(x509);

  unsigned int count = X509_NAME_entry_count(x509Name);
  for (int i = 0; i < count; i++) {
    char *value;
    char name[1024];
    X509_NAME_ENTRY *entry = X509_NAME_get_entry(x509Name, i);

    OBJ_obj2txt(name, sizeof(name), entry->object, 0);

    ASN1_STRING_to_UTF8((unsigned char **) &value, entry->value);
    _log("X509_get_subject_name value %s (%s)", value, name);
    X509_subject_names[name] = value;
  }
}

EstEIDManager & EstEIDToken::getCard() {
  FLOG;
  checkPrivate();
  return d->card();
}

uint32_t EstEIDToken::pinStatus(int pinNum) {
  FLOG;

  if (pinNum != 1)
    CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);
  return mPinStatus;
}

void EstEIDToken::authenticate(CSSM_DB_ACCESS_TYPE mode, const AccessCredentials *cred) {
  FLOG;
  Token::authenticate(mode, cred);
}

void EstEIDToken::verifyPIN(int pinNum, const unsigned char *pin, size_t pinLength) {
  FLOG;
  checkPrivate();

  _log("EstEIDToken::verifyPIN: pin num %d pin len %d", pinNum, pinLength);

  //std::string str(pin);
  PinString pinStr((char *) pin, pinLength);

  byte retries = 0;

  mPinStatus = SCARD_AUTHENTICATION_FAILED;
  switch (pinNum) {
    case 1:
      try {
        d->card().validateAuthPin(pinStr, retries);
        mPinStatus = SCARD_SUCCESS;
      } catch(std::exception &e) {
    _log("authentication failed, %d retries left", retries);
  }
      break;
    default:
      CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);
  }
}

void EstEIDToken::unverifyPIN(int pinNum) {
  FLOG;
  switch (pinNum) {
    case 1:
      mPinStatus = SCARD_AUTHENTICATION_FAILED;
      break;
    default:
      CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);
  }
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
    mAclEntries.allocator(Allocator::standard());
    // Anyone can read the attributes and data of any record on this token
    // (it's further limited by the object itself).
    mAclEntries.add(CssmClient::AclFactory::AnySubject(mAclEntries.allocator()), AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));

    mAclEntries.addPin(AclFactory::PromptPWSubject(mAclEntries.allocator(), CssmData()), 1);
  }
  count = mAclEntries.size();
  acls = mAclEntries.entries();
}

void EstEIDToken::populate() {
  FLOG;

  Tokend::Relation &certRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_X509_CERTIFICATE);
  Tokend::Relation &privateKeyRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_PRIVATE_KEY);
  //Tokend::Relation &dataRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_GENERIC);

  RefPointer<Tokend::Record> eAuthCert(new EstEIDCertRecord("Authentication Certificate"));
//	RefPointer<Tokend::Record> eSignCert(new EstEIDCertRecord( "Signing Certificate"));

  certRelation.insertRecord(eAuthCert);
//	certRelation.insertRecord(eSignCert);

  RefPointer<Tokend::Record> eAuthKey(new EstEIDKeyRecord("Authentication Key", privateKeyRelation.metaRecord(), true));
//	RefPointer<Tokend::Record> eSignKey(new EstEIDKeyRecord("Signature Key", privateKeyRelation.metaRecord(), false));

  privateKeyRelation.insertRecord(eAuthKey);
//	privateKeyRelation.insertRecord(eSignKey);

  eAuthKey->setAdornment(mSchema->publicKeyHashCoder().certificateKey(), new Tokend::LinkedRecordAdornment(eAuthCert));
//	eSignKey->setAdornment(mSchema->publicKeyHashCoder().certificateKey(), new Tokend::LinkedRecordAdornment(eSignCert));
}

