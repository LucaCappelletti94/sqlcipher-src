#include <stdio.h>
#include <stdlib.h>

#include "libstate.h"

static struct {
  const struct fuzz_sqlite *api;
  int major;
} seen[8];

int lib_int(const struct fuzz_sqlite *api, sqlite3 *handle, const char *sql) {
  sqlite3_stmt *stmt = NULL;
  int value = 0;
  if (api->prepare_v2(handle, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
  if (api->step(stmt) == SQLITE_ROW) value = (int)api->column_int64(stmt, 0);
  api->finalize(stmt);
  return value;
}

int lib_exec(const struct fuzz_sqlite *api, sqlite3 *handle, const char *sql) {
  int result = SQLITE_OK;
  while (sql && *sql) {
    sqlite3_stmt *stmt = NULL;
    const char *tail = NULL;
    int rc = api->prepare_v2(handle, sql, -1, &stmt, &tail);
    if (rc == SQLITE_OK && stmt) {
      while ((rc = api->step(stmt)) == SQLITE_ROW) {
        for (int i = 0; i < api->column_count(stmt); i++) {
          api->column_blob(stmt, i);
          api->column_bytes(stmt, i);
        }
      }
      api->finalize(stmt);
      if (rc == SQLITE_DONE) rc = SQLITE_OK;
    }
    if (result == SQLITE_OK) result = rc;
    if (rc != SQLITE_OK && !stmt) break;
    sql = tail;
  }
  return result;
}

int lib_major(const struct fuzz_sqlite *api) {
  for (size_t i = 0; i < sizeof seen / sizeof *seen; i++) {
    if (seen[i].api == api) return seen[i].major;
  }
  abort();
}

void lib_reset(const struct fuzz_sqlite *api) {
  sqlite3 *handle = NULL;
  char reset[256];
  size_t slot = 0;
  api->hard_heap_limit64(0);
  api->soft_heap_limit64(0);
  api->randomness(0, NULL);
  if (api->open_v2(":memory:", &handle, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) abort();
  while (seen[slot].api && seen[slot].api != api) {
    if (++slot == sizeof seen / sizeof *seen) abort();
  }
  if (!seen[slot].api) {
    int major = lib_int(api, handle, "PRAGMA cipher_version");
    if (major < 4) abort();
    seen[slot].api = api;
    seen[slot].major = major;
  }
  int major = seen[slot].major;
  /* cipher_default_compatibility also restores the default page size, HMAC and KDF settings. */
  snprintf(reset, sizeof reset,
           "PRAGMA cipher_default_compatibility = %d;"
           "PRAGMA cipher_default_kdf_iter = 2;"
           "PRAGMA cipher_default_plaintext_header_size = 0;%s",
           major,
           major >= 5 ? "PRAGMA cipher_default_hmac_fast_kdf = 0" : "PRAGMA cipher_hmac_salt_mask = \"x'3a'\"");
  if (lib_exec(api, handle, reset) != SQLITE_OK) abort();
  api->close_v2(handle);
}
