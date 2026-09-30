#ifndef FUZZ_CONFIDENTIALITY_H
#define FUZZ_CONFIDENTIALITY_H

#include "api.h"

/* Checks that plaintext never reaches a keyed file's raw bytes. A canary op plants a distinctive marker as a
   table name, a column name, a text value and a blob value on an open connection; the check scans every named
   file for it at the end of a run, skipping a file no non-empty key was ever applied to, since a deliberate
   unencrypted export (VACUUM INTO, a backup or an export target given no key) legitimately carries the same
   bytes on purpose. Every marker is a fixed prefix nothing else the harness writes ever produces, followed by a
   counter, so two markers never collide and a marker never matches content another op happened to write by
   coincidence.

   The key itself is deliberately not scanned for: unlike a marker, it is read straight off the fuzzer input, the
   same input op_statement's bound text and blobs read from, so a mutator that duplicates a chunk of the input
   (InsertRepeatedBytes, CopyPart) routinely makes a key's bytes recur elsewhere in the very same run as ordinary,
   unrelated row content, a coincidence a real application's independently-chosen key could not produce. */

/* Clears every planted marker and every per-file expecting-encryption flag, before each input. */
void confidentiality_reset(void);

/* Clears file's expecting-encryption flag, when a fresh connection opens it with no key inherited from whatever
   a previous, separate connection to the same file index left behind: a key applied there never retroactively
   encrypted content this new, unrelated connection can go on to write in the clear. Leaves every planted marker
   in place, since a marker planted through file's earlier connection can still legitimately turn up, re-encrypted,
   in a different file a backup or an export copies it into. */
void confidentiality_forget_file(int file);

/* Marks file (a script.c file index) as expecting encryption, once its caller already knows a non-empty key
   reached it and, for key_v2 specifically, that a read through it actually decodes: key_v2 never retroactively
   encrypts content the file already had, unlike rekey_v2, so its success alone does not prove this. */
void confidentiality_mark_keyed(int file);

/* Plants a fresh marker in db's main schema: a table and a column named after its hex encoding, holding one row
   with the same bytes as both a text and a blob value. Does not by itself mark any file as expecting encryption;
   confidentiality_mark_keyed does that once a key reaches it. */
void confidentiality_plant(const struct fuzz_sqlite *api, sqlite3 *db);

/* Scans every named file in files[0, count) that expects encryption for every planted marker. Aborts with a
   one-line reason naming the oracle and the file on a hit. */
void confidentiality_check(const char *const *files, int count);

#endif
