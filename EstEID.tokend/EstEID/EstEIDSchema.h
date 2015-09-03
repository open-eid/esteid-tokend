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
 *  EstEIDSchema.h
 */

#ifndef _ESTEIDSCHEMA_H_
#define _ESTEIDSCHEMA_H_

#include "../tokend/Schema.h"
#include "EstEIDKeyHandle.h"

namespace Tokend {
    class Relation;
    class MetaRecord;
    class AttributeCoder;
}

class EstEIDSchema : public Tokend::Schema {
    NOCOPY(EstEIDSchema)

public:
    EstEIDSchema(uint32_t keySize);
    virtual ~EstEIDSchema();
    virtual void create();

protected:
    Tokend::Relation *createKeyRelation(CSSM_DB_RECORDTYPE keyType);

private:
    Tokend::DataAttributeCoder mEstEIDDataAttributeCoder;
    Tokend::ConstAttributeCoder mKeyAlgorithmCoder;
    Tokend::ConstAttributeCoder mKeySizeCoder;

    EstEIDKeyHandleFactory mEstEIDKeyHandleFactory;
};

#endif /* !_ESTEIDSCHEMA_H_ */

