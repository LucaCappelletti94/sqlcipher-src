#ifndef FUZZ_PAGEMUT_H
#define FUZZ_PAGEMUT_H

#include <stddef.h>
#include <stdint.h>

#include "api.h"

/* The largest page sqlite_dbpage reports, the size a pagemut_read_page buffer needs. */
#define PAGEMUT_MAX_PAGE 65536

/* Reads page pgno through sqlite_dbpage into out and returns its length, or 0. */
int pagemut_read_page(const struct fuzz_sqlite *api, sqlite3 *db, int pgno, uint8_t *out);

/* Rewrites one page through sqlite_dbpage under the application's key, so the library re-encodes it. */
/* Returns 0 when the input does not open that way, and the caller falls back to byte mutation. */
size_t pagemut_mutate(const struct fuzz_sqlite *api, uint8_t *data, size_t size, size_t max, unsigned seed,
                      size_t (*mutate)(uint8_t *, size_t, size_t));

#endif
