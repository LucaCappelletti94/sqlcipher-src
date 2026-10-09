#ifndef FUZZ_MODEL_H
#define FUZZ_MODEL_H

#include "api.h"

/* Model oracle: reopen, rekey, cipher_migrate, backup and attach that report success leave logical content as it was. */
/* sqlcipher_export only adds tables, so its target must still contain every source table unchanged. */
/* Each snapshot and its check happen inside one script op, so one scratch snapshot is enough. */

/* Clears the scratch snapshot and every damaged mark, before each input. */
void model_reset(void);

/* Stops checking file, once raw damage or truncation reached it outside SQLite. */
void model_note_damage(int file);

/* Drops the scratch snapshot, when the operation it was taken for failed. */
void model_discard(void);

/* Snapshots the tables of schema on handle, read from file. */
void model_snapshot(const struct fuzz_sqlite *api, sqlite3 *handle, const char *schema, int file);

/* Aborts when schema on handle, read from file, no longer holds exactly the snapshot's tables and rows. */
void model_check(const struct fuzz_sqlite *api, sqlite3 *handle, const char *schema, int file,
                 const char *file_name, const char *op);

/* Aborts when schema on handle, read from file, lacks a snapshot table or holds it with different rows. */
void model_check_contains(const struct fuzz_sqlite *api, sqlite3 *handle, const char *schema, int file,
                          const char *file_name, const char *op);

#endif
