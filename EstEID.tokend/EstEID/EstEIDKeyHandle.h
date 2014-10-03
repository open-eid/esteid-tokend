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
 *  EstEIDKeyHandle.h
 */

#ifndef _ESTEIDKEYHANDLE_H_
#define _ESTEIDKEYHANDLE_H_

#include "../tokend/KeyHandle.h"

class EstEIDToken;

class EstEIDKeyRecord;


class EstEIDKeyHandle : public Tokend::KeyHandle {
  NOCOPY(EstEIDKeyHandle)
public:
  EstEIDKeyHandle(EstEIDToken &token,
      const Tokend::MetaRecord &metaRecord, Tokend::Record &record);

  ~EstEIDKeyHandle();

  virtual void getKeySize(CSSM_KEY_SIZE &keySize);

  virtual uint32 getOutputSize(const Context &context, uint32 inputSize,
      bool encrypting);

  virtual void generateSignature(const Context &context,
      CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature);

  virtual void verifySignature(const Context &context,
      CSSM_ALGORITHMS signOnly, const CssmData &input,
      const CssmData &signature);

  virtual void generateMac(const Context &context, const CssmData &input,
      CssmData &output);

  virtual void verifyMac(const Context &context, const CssmData &input,
      const CssmData &compare);

  virtual void encrypt(const Context &context, const CssmData &clear,
      CssmData &cipher);

  virtual void decrypt(const Context &context, const CssmData &cipher,
      CssmData &clear);

  virtual void exportKey(const Context &context,
      const AccessCredentials *cred, CssmKey &wrappedKey);

private:
  EstEIDToken &mToken;
};


//
// A factory that creates EstEIDKeyHandle objects.
//
class EstEIDKeyHandleFactory : public Tokend::KeyHandleFactory {
  NOCOPY(EstEIDKeyHandleFactory)
public:
  EstEIDKeyHandleFactory() {
  }

  virtual ~EstEIDKeyHandleFactory();

  virtual Tokend::KeyHandle *keyHandle(Tokend::TokenContext *tokenContext,
      const Tokend::MetaRecord &metaRecord, Tokend::Record &record) const;
};


#endif /* !_ESTEIDKEYHANDLE_H_ */


