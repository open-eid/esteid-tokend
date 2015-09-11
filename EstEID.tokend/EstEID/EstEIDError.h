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
 *  EstEIDError.h
 */

#ifndef _ESTEIDERROR_H_
#define _ESTEIDERROR_H_

#include "../tokend/SCardError.h"


class EstEIDError : public Tokend::SCardError {
protected:
  EstEIDError(uint16_t sw);

  virtual ~EstEIDError() throw ();

public:
  virtual const char *what() const throw ();

  static void check(uint16_t sw) {
    if (sw != SCARD_SUCCESS) throwMe(sw);
  }

  static void throwMe(uint16_t sw) __attribute__((noreturn));

protected:
  IFDEBUG(void debugDiagnose(const void *id) const;)
};

#endif /* !_ESTEIDERROR_H_ */

