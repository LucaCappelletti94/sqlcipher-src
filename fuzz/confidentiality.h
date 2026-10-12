#ifndef FUZZ_CONFIDENTIALITY_H
#define FUZZ_CONFIDENTIALITY_H

#include "api.h"

/* Confidentiality oracle: a canary planted through SQL must never appear in the raw bytes of a file a key reached. */
/* Keys are not scanned for, since mutators copy input chunks, keys included, into ordinary row content. */

/* Clears the planted canaries and the keyed files, before each input. */
void confidentiality_reset(void);

/* Stops expecting file to be encrypted, when a new connection, attach or backup starts over on it. */
void confidentiality_forget_file(int file);

/* Expects file to be encrypted, once a non-empty key is proven to have reached it. */
void confidentiality_mark_keyed(int file);

/* Plants a canary as a table name, a column name, a text value and a blob value in db's main schema. */
void confidentiality_plant(const struct fuzz_sqlite *api, sqlite3 *db);

/* Aborts when any keyed file among files[0, count) holds a planted canary in its raw bytes. */
void confidentiality_check(const char *const *files, int count);

#endif
