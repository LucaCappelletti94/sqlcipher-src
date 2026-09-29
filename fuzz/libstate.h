#ifndef FUZZ_LIBSTATE_H
#define FUZZ_LIBSTATE_H

#include "api.h"

/* Puts a library's process-wide settings back to the same state before every input, and caches its major version. */
void lib_reset(const struct fuzz_sqlite *api);

/* SQLCipher major version of a library lib_reset has seen. */
int lib_major(const struct fuzz_sqlite *api);

/* Runs every statement in sql, reading every column of every row, and returns the first failure. */
int lib_exec(const struct fuzz_sqlite *api, sqlite3 *handle, const char *sql);

/* The first column of the first row of sql as an integer, or 0. */
int lib_int(const struct fuzz_sqlite *api, sqlite3 *handle, const char *sql);

#endif
