#ifndef FUZZ_PLAINDIFF_H
#define FUZZ_PLAINDIFF_H

#include "api.h"
#include "rawfile.h"

/* Oracle for keyed_file: SQLCipher reading the input with the application's key must return exactly what plain SQLite
   returns for the plaintext pages SQLCipher itself decodes. Aborts with a one-line reason on any difference. */
void plaindiff_check(const struct fuzz_sqlite *cipher, const struct fuzz_sqlite *plain, const struct rawfile *in);

#endif
