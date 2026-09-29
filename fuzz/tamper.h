#ifndef FUZZ_TAMPER_H
#define FUZZ_TAMPER_H

#include "api.h"

/* Tracks byte ranges op_damage corrupted outside a script write, and checks that a later read of the page such a
   range falls in never returns data through sqlite_dbpage with SQLITE_OK. Two mechanisms drop a region before that
   check, each catching a cure the other cannot: a repeat flip at the same offset cancels the cumulative XOR mask
   back to 0 when op_damage undoes its own damage, and a hash of the region's current bytes taken at record time
   stops matching once anything else, a rekey and an ordinary write both included, rewrites the range. Neither
   needs a list of which operations might cure damage. A page whose decrypt failure already returns a zero-filled
   buffer (ledger L4) is exempt, since that finding is filed and its propagation through other readers belongs to a
   future model oracle. cipher_use_hmac = OFF, the unauthenticated part of a plaintext header, and the unpopulated
   tail of a page's reserve are exempt by design. */

/* Clears every recorded tamper, before each input. */
void tamper_reset_all(void);

/* Records that [offset, offset + len) of file changed outside a script write, hashing its current bytes so a later
   check can tell whether something has since rewritten the range. */
void tamper_note(int file, const char *file_name, long long offset, long long len);

/* Records that a single byte of file was XORed with mask. A second flip at the same offset XORs into the same
   region's running mask instead of adding a new one, dropping the region outright once that mask cancels to 0. */
void tamper_flip(int file, const char *file_name, long long offset, unsigned char mask);

/* Checks every page a still-matching recorded tamper for file falls in, reading it through sqlite_dbpage on db.
   Aborts with a one-line reason naming the oracle, file_name and the page on a non-zero, successful read. */
void tamper_check(const struct fuzz_sqlite *api, sqlite3 *db, int file, const char *file_name);

#endif
