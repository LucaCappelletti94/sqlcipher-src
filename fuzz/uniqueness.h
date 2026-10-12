#ifndef FUZZ_UNIQUENESS_H
#define FUZZ_UNIQUENESS_H

#include "api.h"

/* Uniqueness oracle: no page IV repeats within a file, and no salt repeats across files, within one run. */
/* IVs and salts sit in clear in the file, so they are read straight from memvfs at every close or detach. */

/* Clears every recorded fingerprint, before each input. */
void uniqueness_reset(void);

/* Stops checking file, once raw damage has written input bytes into it. */
void uniqueness_note_damage(int file);

/* Stops checking file's salt, once a salt was set on purpose through cipher_salt or a salted raw key. */
void uniqueness_note_explicit_salt(int file);

/* Fingerprints the IVs and salt of file under schema on db, aborting on a fresh draw that repeats an earlier one. */
void uniqueness_check(const struct fuzz_sqlite *api, sqlite3 *db, const char *schema, int file,
                      const char *file_name);

#endif
