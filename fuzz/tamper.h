#ifndef FUZZ_TAMPER_H
#define FUZZ_TAMPER_H

#include "api.h"

/* Tamper oracle: a byte range damaged outside a script write must never read back non-zero with SQLITE_OK. */
/* A range is dropped once its cipher-block window changes, so whatever rewrites the page heals it without a list. */

/* Clears every recorded tamper, before each input. */
void tamper_reset_all(void);

/* Drops the ranges of file a write has healed, called before new damage lands so the damage is not taken for one. */
void tamper_prune(int file, const char *file_name);

/* Records that [offset, offset + len) of file was overwritten outside a script write. */
void tamper_note(int file, const char *file_name, long long offset, long long len);

/* Records that one byte of file was XORed with mask, dropping the range when repeated flips cancel. */
void tamper_flip(int file, const char *file_name, long long offset, unsigned char mask);

/* Reads every still-tampered authenticated slice of file through sqlite_dbpage on db, aborting on non-zero data. */
void tamper_check(const struct fuzz_sqlite *api, sqlite3 *db, int file, const char *file_name);

/* A fingerprint of file_name's raw bytes, or 0 when it does not exist. */
unsigned long long tamper_hash_file(const char *file_name);

/* Aborts when a key read rc rejected left file_name's bytes different from before_hash. */
void tamper_check_wrong_key(int rc, unsigned long long before_hash, const char *file_name);

#endif
