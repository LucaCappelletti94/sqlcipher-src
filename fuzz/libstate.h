#ifndef FUZZ_LIBSTATE_H
#define FUZZ_LIBSTATE_H

#include <stddef.h>

#include "api.h"

/* Forward-declared, since plaindiff.c has its own struct dump. */
struct dump;

/* Puts a library's process-wide settings back to the same state before every input, and caches its major version. */
void lib_reset(const struct fuzz_sqlite *api);

/* SQLCipher major version of a library lib_reset has seen, or 0 for plain SQLite. */
int lib_major(const struct fuzz_sqlite *api);

/* Runs every statement in sql, reading every column of every row, and returns the first failure. */
int lib_exec(const struct fuzz_sqlite *api, sqlite3 *handle, const char *sql);

/* The first column of the first row of sql as an integer, or 0. */
int lib_int(const struct fuzz_sqlite *api, sqlite3 *handle, const char *sql);

/* api's main database's codec page size on handle, or 0 when it has no codec. */
int fuzz_codec_page_size(const struct fuzz_sqlite *api, sqlite3 *handle);

/* Puts memvfs, the tamper record and the replayable entropy stream back to their reset state, before each input. */
void fuzz_reset_all(void);

/* FNV-1a, a fingerprint cheap enough to take of every region and file an oracle tracks. */
unsigned long long fuzz_fnv1a(const unsigned char *bytes, size_t len);

/* Appends to a doubling buffer, dropping appends past max and aborting when allocation fails. */
void fuzz_grow_append(unsigned char **bytes, size_t *len, size_t *cap, size_t max, const void *data, size_t add_len);

/* Lowercase hex digits for bytes, out sized at least 2 * len + 1. */
void fuzz_hex(char *out, const unsigned char *bytes, int len);

/* Reports the first byte where writer and reader differ to stderr. */
void fuzz_report_first_difference(int file, const char *writer_name, const struct dump *writer,
                                  const char *reader_name, const struct dump *reader);

#endif
