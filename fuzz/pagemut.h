#ifndef FUZZ_PAGEMUT_H
#define FUZZ_PAGEMUT_H

#include <stddef.h>
#include <stdint.h>

#include "api.h"

/* The largest page sqlite_dbpage can report, so a caller's scratch buffer for pagemut_read_page is always large
   enough. */
#define PAGEMUT_MAX_PAGE 65536

/* Reads page pgno of db through sqlite_dbpage into out (at least PAGEMUT_MAX_PAGE bytes) and returns its length,
   or 0. */
int pagemut_read_page(const struct fuzz_sqlite *api, sqlite3 *db, int pgno, uint8_t *out);

/* Structure-aware mutation for keyed_file: opens the input's main database with the application's key, rewrites one
   page through sqlite_dbpage so the library itself re-encodes it, and stores the resulting file back in the input.
   Returns the new size, or 0 when the input cannot be opened that way, so the caller falls back to byte mutation. */
size_t pagemut_mutate(const struct fuzz_sqlite *api, uint8_t *data, size_t size, size_t max, unsigned seed,
                      size_t (*mutate)(uint8_t *, size_t, size_t));

#endif
