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
 * esteid.cpp - EstEID.tokend main program
 */

#include "EstEIDToken.h"
#include "EstEID_utility.h"

int main(int argc, const char *argv[]) {
    _log("main starting with %d arguments", argc);
    secdelay("/tmp/delay/EstEID");
    token = new EstEIDToken();
    return SecTokendMain(argc, argv, token->callbacks(), token->support());
}

