#ifndef FUZZ_LIBSTATE_H
#define FUZZ_LIBSTATE_H

#include <stddef.h>

#include "api.h"

/* script.h's own type, forward-declared rather than included: some consumers of this header (plaindiff.c) define
   their own, differently-shaped struct dump, and never call fuzz_report_first_difference. */
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

/* Puts every oracle module (memvfs, tamper, confidentiality, uniqueness, model, fault, random) back to its own
   reset state, the sequence every entry point runs before each input. */
void fuzz_reset_all(void);

/* FNV-1a, for a name or content fingerprint cheap enough to run on every table a snapshot touches. */
unsigned long long fuzz_fnv1a(const unsigned char *bytes, size_t len);

/* Appends add_len bytes at data to the buffer (*bytes, *len, *cap), growing *bytes by doubling when needed, up to
   max total bytes (silently dropping the append past max). Aborts on allocation failure. */
void fuzz_grow_append(unsigned char **bytes, size_t *len, size_t *cap, size_t max, const void *data, size_t add_len);

/* Lowercase hex digits for bytes, out sized at least 2 * len + 1. */
void fuzz_hex(char *out, const unsigned char *bytes, int len);

/* Scans writer and reader for their first differing byte and reports it to stderr, named for file and each side's
   own name. */
void fuzz_report_first_difference(int file, const char *writer_name, const struct dump *writer,
                                  const char *reader_name, const struct dump *reader);

#endif
