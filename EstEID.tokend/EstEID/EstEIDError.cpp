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
 *  EstEIDError.cpp
 */

#include "EstEIDError.h"

//
// EstEIDError exceptions
//
EstEIDError::EstEIDError(uint16_t sw) : SCardError(sw) {
  IFDEBUG(debugDiagnose(this));
}

EstEIDError::~EstEIDError() throw () {
}

const char *EstEIDError::what() const throw () {
  return "EstEID error";
}

void EstEIDError::throwMe(uint16_t sw) {
  throw EstEIDError(sw);
}

#if !defined(NDEBUG)

void EstEIDError::debugDiagnose(const void *id) const {
/*    secdebug("tok_esteid", "%p EstEIDError %s (%04hX)",
             id, errorstr(statusWord), statusWord);*/
}

#endif //NDEBUG

