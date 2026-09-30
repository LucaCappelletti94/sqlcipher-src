#ifndef FUZZ_MODEL_H
#define FUZZ_MODEL_H

#include "api.h"

/* Checks that reopen, rekey, cipher_migrate, sqlcipher_export, backup and attach never silently change or lose
   logical content: reopen, rekey and cipher_migrate are a pure re-encoding of what a schema already holds, so
   what comes back out has to equal what went in table for table, row for row; backup replaces the destination's
   entire main schema with a copy of the source, the same exact shape; attach's own read-only path is a view onto
   content nothing else touches while it is live, also exact. sqlcipher_export is different: it mirrors the
   source's tables into the destination with `CREATE TABLE` and `INSERT INTO ... SELECT`, never dropping or
   clearing whatever the destination already had, so the destination afterward only has to still contain every
   table the source had before, unchanged, not equal it outright. None of these six is a write a real application
   makes to add, change or remove a row on its own terms, so every one of them has an expected before-and-after
   shape a fuzzer-driven `INSERT`/`UPDATE`/`DELETE` does not: content in, the same content still there, or the
   call itself reporting failure.

   Every snapshot and check happens inside a single script.c op, back to back, with nothing else able to run in
   between (script_run dispatches one op at a time), so there is never a need to hold a snapshot across ops the
   way the tamper, confidentiality and uniqueness oracles have to: one shared scratch snapshot, filled immediately
   before the operation and compared immediately after, is enough. A snapshot reduces every table in the target
   schema to one name hash and one content hash (every row, typed and length-prefixed the same way script.c's own
   read-back dump already does, plus the read's own final result code), which is stable across the pair as long
   as nothing in between reorders a b-tree; none of the six operations this module checks does that on their own.
   Only a call that itself reports success is ever compared: a failed rekey, a migrate that bails out on a
   missing underived passphrase, or a blocked backup already means nothing happened, which is not this module's
   finding to make.

   op_damage and op_cache_race write raw bytes into a file, or truncate it, outside the SQL layer entirely, and a
   connection that already has the pre-damage page cache-resident can keep reading it from memory for a while
   after, showing this module's own "before" snapshot content the codec itself has not actually decoded since; a
   reopen after that forces a fresh read and is expected to show the damage or the loss, not this module's own
   finding. A file op_damage or op_cache_race ever touches, truncation included, is therefore marked and skipped
   for the rest of the run, the same file index tamper_flip, tamper_note and uniqueness_note_damage already use.

   A reopen's own close_db rolls back an explicit transaction script.c's own BEGIN/SAVEPOINT statements left open,
   the same documented sqlite3_close_v2 behaviour any real application gets: a connection can see its own
   uncommitted writes right up until it closes, then loses them, which is not this module's finding either.
   script.c checks sqlite3_get_autocommit itself before ever calling model_snapshot for a reopen, so this module
   never has to. */

/* Clears the shared scratch snapshot and every file's damaged mark, before each input. */
void model_reset(void);

/* Marks file (a script.c file index) as damaged, once op_damage or op_cache_race writes raw bytes into it
   directly: every later model_snapshot or model_check call naming that file is a no-op for the rest of this run. */
void model_note_damage(int file);

/* Clears the shared scratch snapshot without comparing it to anything. Call this whenever model_snapshot ran for
   an operation that then failed or was skipped, so the pending snapshot never lingers to be picked up by some
   later, unrelated model_check or model_check_contains call for a different file or a different operation
   entirely: every model_snapshot call must be paired with exactly one of model_check, model_check_contains or
   model_discard, with no path that leaves the snapshot pending across more than one op. */
void model_discard(void);

/* Snapshots handle's current logical content under schema into the shared scratch snapshot, discarding whatever a
   previous snapshot held. Call immediately before an operation this module's header comment promises is
   content-preserving or a verbatim copy, naming file as the file index the snapshot is taken from. */
void model_snapshot(const struct fuzz_sqlite *api, sqlite3 *handle, const char *schema, int file);

/* Compares handle's current logical content under schema against the scratch snapshot table for table, aborting
   with a one-line reason naming op on any difference in count, name or content. Call immediately after reopen,
   rekey, cipher_migrate, backup or attach's own read-only path reports success; never call this after a failure,
   per this module's own definition of the property it checks. file is the file index handle's schema is being
   read from now, checked against its own damaged mark independently of whichever file the snapshot came from. */
void model_check(const struct fuzz_sqlite *api, sqlite3 *handle, const char *schema, int file,
                  const char *file_name, const char *op);

/* Like model_check, but for sqlcipher_export specifically: aborts only when some table the scratch snapshot
   named is now missing from handle's schema or has different content, ignoring any table handle's schema has
   that the snapshot never named, since export only ever adds tables to a destination, never removes or clears
   what was already there. */
void model_check_contains(const struct fuzz_sqlite *api, sqlite3 *handle, const char *schema, int file,
                           const char *file_name, const char *op);

#endif
