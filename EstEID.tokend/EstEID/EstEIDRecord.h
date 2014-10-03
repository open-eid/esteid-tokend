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
 *  EstEIDRecord.h
 */

#ifndef _ESTEIDRECORD_H_
#define _ESTEIDRECORD_H_

#include "../tokend/Record.h"

class EstEIDRecord : public Tokend::Record {
  NOCOPY(EstEIDRecord)
public:
  EstEIDRecord(const char *description);

  ~EstEIDRecord();

  virtual const char *description();

protected:
  const char *mDescription;
};

class EstEIDKeyRecord : public EstEIDRecord {
  NOCOPY(EstEIDKeyRecord)
public:
  EstEIDKeyRecord(const char *description,
      const Tokend::MetaRecord &metaRecord, bool signOnly);

  virtual ~EstEIDKeyRecord();

  virtual void getAcl(const char *tag, uint32 &count,
      AclEntryInfo *&aclList);

private:
  bool mSignOnly;
  AutoAclEntryInfoList mAclEntries;

};

class EstEIDCertRecord : public EstEIDRecord {
  NOCOPY(EstEIDCertRecord)
public:
  EstEIDCertRecord(const char *description) : EstEIDRecord(description) {
  }

  virtual ~EstEIDCertRecord();

  virtual Tokend::Attribute *getDataAttribute(Tokend::TokenContext *tokenContext);
};

#endif /* !_ESTEIDRECORD_H_ */


