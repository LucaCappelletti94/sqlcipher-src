#ifndef FUZZ_APP_H
#define FUZZ_APP_H

#include "api.h"
#include "rawfile.h"

/* Opens name with the application's key (or key, when set) and settings, or returns NULL when it would not open it. */
sqlite3 *app_open(const struct fuzz_sqlite *api, const char *name, const struct rawfile *in, const char *key);

/* Opens the input's file images as an application that did not write them, with its own key, settings and actions. */
void app_run(const struct fuzz_sqlite *api, const struct rawfile *in);

#endif
