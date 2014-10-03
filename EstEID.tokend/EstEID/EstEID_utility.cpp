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

#include "EstEID_utility.h"
#include <sys/time.h>

const char *getLogFilename() {
	return "/tmp/esteid-tokend.log";
}

void write_log(const char *func, const char *file, int line, const char *message, ...) {
  FILE *log;
  va_list args;
  
  if (access(getLogFilename(), W_OK) == -1) {
    return;
  }
  
  log = openLog(func, file, line);
  va_start(args, message);
  vfprintf(log, message, args);
  va_end(args);
  fprintf(log, "\n");
  fclose(log);
}

FILE *openLog(const char *func, const char *file, int line) {
	char timestamp[TIMESTAMP_BUFFER_LEN];
	char delimiter = '/';
	struct timeval tv;
	time_t curtime;
	gettimeofday(&tv, NULL);
	curtime = tv.tv_sec;
	
  strftime(timestamp, 30, "%Y-%m-%d %T", localtime(&curtime));
	sprintf(timestamp + strlen(timestamp), ".%03i ", tv.tv_usec / 1000);
	FILE *log = fopen(getLogFilename(), "a");

	fprintf(log, "%s ", timestamp);
	if (file) {
		char *f = strrchr((char *)file, delimiter);
		if (!f) f = (char *)file;
		else f++;
		fprintf(log, "%s() [%s:%i] ", func, f, line);
	}
	return log;
}
