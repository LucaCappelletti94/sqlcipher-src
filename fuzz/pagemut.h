#ifndef FUZZ_PAGEMUT_H
#define FUZZ_PAGEMUT_H

#include <stddef.h>
#include <stdint.h>

#include "api.h"

/* Structure-aware mutation for keyed_file: opens the input's main database with the application's key, rewrites one
   page through sqlite_dbpage so the library itself re-encodes it, and stores the resulting file back in the input.
   Returns the new size, or 0 when the input cannot be opened that way, so the caller falls back to byte mutation. */
size_t pagemut_mutate(const struct fuzz_sqlite *api, uint8_t *data, size_t size, size_t max, unsigned seed,
                      size_t (*mutate)(uint8_t *, size_t, size_t));

#endif
