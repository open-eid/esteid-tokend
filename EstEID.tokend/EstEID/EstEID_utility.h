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

#include <stdio.h>
#include <string>
#include <iostream>

using namespace std;

#define TIMESTAMP_BUFFER_LEN 30

void write_log(const char *func, const char *file, int line, const char *message, ...);

FILE *openLog(const char *func, const char *file, int line);

#define FLOG _log("");
#define _log(...) write_log(__func__, __FILE__, __LINE__, __VA_ARGS__)
