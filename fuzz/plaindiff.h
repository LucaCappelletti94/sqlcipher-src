#ifndef FUZZ_PLAINDIFF_H
#define FUZZ_PLAINDIFF_H

#include "api.h"
#include "rawfile.h"

/* Aborts when SQLCipher reading the input disagrees with plain SQLite reading the pages SQLCipher decodes. */
void plaindiff_check(const struct fuzz_sqlite *cipher, const struct fuzz_sqlite *plain, const struct rawfile *in);

#endif
