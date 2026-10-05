#ifndef FUZZ_APP_H
#define FUZZ_APP_H

#include "api.h"
#include "rawfile.h"

/* Opens name with the application's key (or key, when set) and settings, or returns NULL when it would not open it. */
sqlite3 *app_open(const struct fuzz_sqlite *api, const char *name, const struct rawfile *in, const char *key);

/* Installs the input's file images in memvfs, then opens them the way an application that did not write them would:
   its own key and settings, followed by the input's actions. Closes every connection it opened. */
void app_run(const struct fuzz_sqlite *api, const struct rawfile *in);

#endif
