#include <string.h>

#include "app.h"
#include "libstate.h"
#include "memvfs.h"
#include "pagemut.h"
#include "random.h"
#include "rawfile.h"

#define MAX_PAGE 65536
#define MAX_OUT (3 * 65536 + 64)

static int page_count(const struct fuzz_sqlite *api, sqlite3 *db) {
  return lib_int(api, db, "PRAGMA page_count");
}

/* Reads page pgno through sqlite_dbpage into out and returns its length, or 0. */
static int read_page(const struct fuzz_sqlite *api, sqlite3 *db, int pgno, uint8_t *out) {
  sqlite3_stmt *stmt = NULL;
  int len = 0;
  if (api->prepare_v2(db, "SELECT data FROM sqlite_dbpage WHERE pgno = ?1", -1, &stmt, NULL) != SQLITE_OK) return 0;
  api->bind_int64(stmt, 1, pgno);
  if (api->step(stmt) == SQLITE_ROW) {
    const void *bytes = api->column_blob(stmt, 0);
    len = api->column_bytes(stmt, 0);
    if (!bytes || len <= 0 || len > MAX_PAGE) {
      len = 0;
    } else {
      memcpy(out, bytes, (size_t)len);
    }
  }
  api->finalize(stmt);
  return len;
}

static int write_page(const struct fuzz_sqlite *api, sqlite3 *db, int pgno, const uint8_t *bytes, int len) {
  sqlite3_stmt *stmt = NULL;
  if (api->prepare_v2(db, "UPDATE sqlite_dbpage SET data = ?2 WHERE pgno = ?1", -1, &stmt, NULL) != SQLITE_OK) {
    return SQLITE_ERROR;
  }
  api->bind_int64(stmt, 1, pgno);
  api->bind_blob(stmt, 2, bytes, len, SQLITE_TRANSIENT);
  int rc = api->step(stmt);
  api->finalize(stmt);
  return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

size_t pagemut_mutate(const struct fuzz_sqlite *api, uint8_t *data, size_t size, size_t max, unsigned seed,
                      size_t (*mutate)(uint8_t *, size_t, size_t)) {
  static uint8_t page[MAX_PAGE];
  static uint8_t main_copy[65536];
  static uint8_t out[MAX_OUT];
  struct rawfile in;
  if (!rawfile_decode(data, size, &in) || !in.files[RAWFILE_MAIN].bytes) return 0;
  memvfs_reset();
  fuzz_random_reset();
  lib_reset(api);
  /* WAL and journal are left out, so the rewritten main file stands alone. */
  memvfs_install("main.db", in.files[RAWFILE_MAIN].bytes, in.files[RAWFILE_MAIN].len);
  sqlite3 *db = app_open(api, "main.db", &in, NULL);
  if (!db) return 0;
  int pages = page_count(api, db);
  size_t result = 0;
  if (pages > 0) {
    int pgno = (int)(seed % (unsigned)pages) + 1;
    int len = read_page(api, db, pgno, page);
    if (len > 0) {
      mutate(page, (size_t)len, (size_t)len);
      if (write_page(api, db, pgno, page, len) == SQLITE_OK) result = 1;
    }
  }
  api->close_v2(db);
  if (!result) return 0;
  size_t len = 0;
  const unsigned char *bytes = memvfs_peek("main.db", &len);
  if (!bytes || !len || len > sizeof main_copy) return 0;
  memcpy(main_copy, bytes, len);
  struct rawfile mutated = in;
  memset(mutated.files, 0, sizeof mutated.files);
  mutated.files[RAWFILE_MAIN].bytes = main_copy;
  mutated.files[RAWFILE_MAIN].len = len;
  size_t encoded = rawfile_encode(&mutated, out, sizeof out);
  if (!encoded || encoded > max) return 0;
  memcpy(data, out, encoded);
  return encoded;
}
