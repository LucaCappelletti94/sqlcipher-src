/* Usage: seedgen OUTDIR [TESTKEY_DIR]. Writes the hostile_file seed corpus. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"
#include "libstate.h"
#include "memvfs.h"
#include "random.h"
#include "rawfile.h"

extern const struct fuzz_sqlite FUZZ_LIBRARY_TABLE;
static const struct fuzz_sqlite *const lib = &FUZZ_LIBRARY_TABLE;

#define MAX_SEED (3 * 65536)
#define TESTKEY_PREFIX 32768

static const char *out_dir;
static int written;

static void write_seed(const struct rawfile *seed) {
  static uint8_t buffer[MAX_SEED];
  size_t len = rawfile_encode(seed, buffer, sizeof buffer);
  if (!len) return;
  char path[4096];
  snprintf(path, sizeof path, "%s/seed-%04d", out_dir, written++);
  FILE *file = fopen(path, "wb");
  if (!file || fwrite(buffer, 1, len, file) != len) abort();
  fclose(file);
}

static const char *const content =
    "CREATE TABLE t(a INTEGER PRIMARY KEY, b BLOB, c TEXT);"
    "CREATE INDEX t_c ON t(c);"
    "CREATE TABLE w(k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID;"
    "CREATE VIRTUAL TABLE f USING fts5(x);"
    "INSERT INTO t(b, c) VALUES (randomblob(40), 'one'), (randomblob(6000), 'two'), (zeroblob(300), 'three');"
    "INSERT INTO w VALUES ('k1', randomblob(20)), ('k2', randomblob(2500));"
    "INSERT INTO f VALUES ('canary text for the full-text index');";

/* Copies the named file into the seed, or leaves the section empty. */
static void take(struct rawfile *seed, enum rawfile_kind kind, const char *name, uint8_t *copy) {
  size_t len = 0;
  const unsigned char *bytes = memvfs_peek(name, &len);
  if (!bytes || !len || len > 0xffff) return;
  memcpy(copy, bytes, len);
  seed->files[kind].bytes = copy;
  seed->files[kind].len = len;
}

static void generate(enum rawfile_app app, unsigned page, int hmac_off) {
  static uint8_t base_copy[65536], main_copy[65536], side_copy[65536];
  struct rawfile seed = {.app = app, .page = page, .use_hmac_off = hmac_off, .actions = 0xff};
  memvfs_reset();
  fuzz_random_reset();
  lib_reset(lib);
  sqlite3 *db = app_open(lib, "main.db", &seed, NULL);
  if (!db) return;
  int rc = lib_exec(lib, db, content);
  lib->close_v2(db);
  if (rc != SQLITE_OK) return;
  take(&seed, RAWFILE_MAIN, "main.db", base_copy);
  if (!seed.files[RAWFILE_MAIN].bytes) return;
  write_seed(&seed);

  db = app_open(lib, "main.db", &seed, NULL);
  if (db && lib_exec(lib, db, "PRAGMA journal_mode = WAL; INSERT INTO t(b, c) VALUES (randomblob(900), 'wal')") ==
                SQLITE_OK) {
    struct rawfile wal = seed;
    take(&wal, RAWFILE_MAIN, "main.db", main_copy);
    take(&wal, RAWFILE_WAL, "main.db-wal", side_copy);
    if (wal.files[RAWFILE_WAL].bytes) write_seed(&wal);
  }
  if (db) lib->close_v2(db);

  memvfs_reset();
  memvfs_install("main.db", seed.files[RAWFILE_MAIN].bytes, seed.files[RAWFILE_MAIN].len);
  db = app_open(lib, "main.db", &seed, NULL);
  if (db && lib_exec(lib, db,
                     "PRAGMA cache_size = 1; BEGIN; UPDATE t SET b = randomblob(length(b)); "
                     "INSERT INTO w VALUES ('k3', randomblob(4000))") == SQLITE_OK) {
    struct rawfile hot = seed;
    take(&hot, RAWFILE_MAIN, "main.db", main_copy);
    take(&hot, RAWFILE_JOURNAL, "main.db-journal", side_copy);
    if (hot.files[RAWFILE_JOURNAL].bytes) write_seed(&hot);
  }
  if (db) lib->close_v2(db);
}

static void testkey(const char *dir, const char *version, enum rawfile_app app) {
  static uint8_t bytes[TESTKEY_PREFIX];
  char path[4096];
  snprintf(path, sizeof path, "%s/sqlcipher-%s-testkey.db", dir, version);
  FILE *file = fopen(path, "rb");
  if (!file) return;
  size_t len = fread(bytes, 1, sizeof bytes, file);
  fclose(file);
  struct rawfile seed = {.app = app, .actions = 0xff};
  seed.files[RAWFILE_MAIN].bytes = bytes;
  seed.files[RAWFILE_MAIN].len = len;
  write_seed(&seed);
}

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  out_dir = argv[1];
  for (int app = 0; app < APP_COUNT; app++) {
    for (unsigned page = 0; page < 5; page++) {
      generate((enum rawfile_app)app, page, 0);
    }
    generate((enum rawfile_app)app, 0, 1);
  }
  if (argc > 2) {
    testkey(argv[2], "1.1.8", APP_COMPAT_1);
    testkey(argv[2], "2.0-le", APP_COMPAT_2);
    testkey(argv[2], "2.0-be", APP_COMPAT_2_BE);
    testkey(argv[2], "2.0-beta", APP_COMPAT_2_BETA);
    testkey(argv[2], "3.0", APP_COMPAT_3);
    testkey(argv[2], "4.0", APP_COMPAT_4);
  }
  memvfs_reset();
  printf("%d seeds\n", written);
  return 0;
}
