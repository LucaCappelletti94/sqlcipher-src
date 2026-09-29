/* Included once at the end of each library translation unit, after its amalgamation, with FUZZ_LIBRARY naming the table. */
#include "api.h"
#include "memvfs.h"

int sqlite3_os_init(void) {
  return sqlite3_vfs_register(memvfs_create(), 1);
}

int sqlite3_os_end(void) {
  return SQLITE_OK;
}

#define FUZZ_NAME(symbol) FUZZ_QUOTE(symbol)
#define FUZZ_QUOTE(symbol) #symbol

const struct fuzz_sqlite FUZZ_LIBRARY = {
    .name = FUZZ_NAME(FUZZ_LIBRARY),
    .open_v2 = sqlite3_open_v2,
    .close_v2 = sqlite3_close_v2,
    .prepare_v2 = sqlite3_prepare_v2,
    .step = sqlite3_step,
    .finalize = sqlite3_finalize,
    .column_count = sqlite3_column_count,
    .column_type = sqlite3_column_type,
    .column_int64 = sqlite3_column_int64,
    .column_double = sqlite3_column_double,
    .column_blob = sqlite3_column_blob,
    .column_bytes = sqlite3_column_bytes,
    .bind_int64 = sqlite3_bind_int64,
    .bind_blob = sqlite3_bind_blob,
    .bind_text = sqlite3_bind_text,
    .key_v2 = sqlite3_key_v2,
    .rekey_v2 = sqlite3_rekey_v2,
    .set_authorizer = sqlite3_set_authorizer,
    .progress_handler = sqlite3_progress_handler,
    .limit = sqlite3_limit,
    .hard_heap_limit64 = sqlite3_hard_heap_limit64,
    .soft_heap_limit64 = sqlite3_soft_heap_limit64,
    .randomness = sqlite3_randomness,
    .backup_init = sqlite3_backup_init,
    .backup_step = sqlite3_backup_step,
    .backup_finish = sqlite3_backup_finish,
};
