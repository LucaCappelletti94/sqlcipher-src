#include <stdio.h>
#include <string.h>

#include "app.h"
#include "known.h"
#include "libstate.h"
#include "memvfs.h"

/* Progress callbacks, each every 100 VDBE ops, before an input's statements are interrupted. */
#define BUDGET 20000
#define MAX_TABLES 8

static const char *const names[RAWFILE_KINDS] = {"main.db", "main.db-wal", "main.db-journal"};

#define KEY_0 "x'8d3f5a1e0b7c294f6e1d2c3b4a59687706f5e4d3c2b1a09f8e7d6c5b4a392817'"
#define KEY_1 "x'1f2e3d4c5b6a79880706f5e4d3c2b1a0ffeeddccbbaa99887766554433221100'"
#define KEY_0_SALT "x'8d3f5a1e0b7c294f6e1d2c3b4a59687706f5e4d3c2b1a09f8e7d6c5b4a39281700112233445566778899aabbccddeeff'"

/* Each testkey database from sqlcipher-resources opens with the PBKDF2 output of 'testkey' over its own salt, so the
   raw key reaches it without the legacy iteration counts. */
static const struct {
  const char *key;
  const char *settings;
} apps[APP_COUNT] = {
    [APP_RAW_KEY] = {KEY_0, ""},
    [APP_PASSPHRASE] = {"correct horse battery staple", "PRAGMA kdf_iter = 2;"},
    [APP_PLAINTEXT_HEADER] = {KEY_0_SALT, "PRAGMA cipher_plaintext_header_size = 32;"},
    [APP_COMPAT_1] = {"x'1afc9127f390cf1d867653b581f446ba8f5459209cf9625e32a502661437ba7f'",
                      "PRAGMA cipher_compatibility = 1;"},
    [APP_COMPAT_2] = {"x'855b1e6b6c58719c3f60f828e8cbf13580c0be452fd5f69b895e9fc7e5e88886'",
                      "PRAGMA cipher_compatibility = 2;"},
    [APP_COMPAT_2_BE] = {"x'd9d28968a62ba2e42e3bfcde3b1741110b2c5daf3079f1a84038dac45f099555'",
                         "PRAGMA cipher_compatibility = 2; PRAGMA cipher_hmac_pgno = be;"},
    [APP_COMPAT_2_BETA] = {"x'94173b9c74077055e1c671ccda1250fabb58f065da23fb8573c71cb1df8c624c'",
                           "PRAGMA cipher_compatibility = 2; PRAGMA fast_kdf_iter = 4000;"
                           "PRAGMA cipher_hmac_salt_mask = \"x'00'\";"},
    [APP_COMPAT_3] = {"x'3d984e8901f555a3830f2f46a2d5e037bde324259cf05b2fd4dcfd2568ff981a'",
                      "PRAGMA cipher_compatibility = 3;"},
    [APP_COMPAT_4] = {"x'a880be464199392c1a8ea25b02f16a1ceac943f61ac5500213bfe3aaf672fd54'",
                      "PRAGMA cipher_compatibility = 4;"},
};

static const struct fuzz_sqlite *lib;
static int major;
static long budget;

static int progress(void *unused) {
  (void)unused;
  return --budget < 0;
}

static int codec_page_size(sqlite3 *handle) {
  return lib_int(lib, handle, "PRAGMA main.cipher_page_size");
}

sqlite3 *app_open(const struct fuzz_sqlite *api, const char *name, const struct rawfile *in, const char *key) {
  sqlite3 *handle = NULL;
  lib = api;
  major = lib_major(api);
  char sql[96];
  if (lib->open_v2(name, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
    lib->close_v2(handle);
    return NULL;
  }
  lib->progress_handler(handle, 100, progress, NULL);
  lib->limit(handle, SQLITE_LIMIT_LENGTH, 1 << 20);
  lib->limit(handle, SQLITE_LIMIT_VDBE_OP, 25000);
  lib->key_v2(handle, "main", key ? key : apps[in->app].key, (int)strlen(key ? key : apps[in->app].key));
  lib_exec(lib, handle, apps[in->app].settings);
  if (in->page) {
    unsigned size = known_page_size(major, 1024u << (in->page - 1));
    snprintf(sql, sizeof sql, "PRAGMA cipher_page_size = %u", size > 65536 ? 65536 : size);
    lib_exec(lib, handle, sql);
  }
  if (in->use_hmac_off) lib_exec(lib, handle, "PRAGMA cipher_use_hmac = OFF");
  /* memvfs has no shared memory, so SQLite only opens a WAL under exclusive locking. */
  lib_exec(lib, handle, "PRAGMA locking_mode = EXCLUSIVE");
  if (known_header_page_mismatch(major, memvfs_header_page_size(name), codec_page_size(handle))) { /* L8 */
    lib->close_v2(handle);
    return NULL;
  }
  return handle;
}

static void read_all(sqlite3 *handle) {
  char tables[MAX_TABLES][128];
  int count = 0;
  sqlite3_stmt *stmt = NULL;
  if (lib->prepare_v2(handle, "SELECT name FROM sqlite_schema WHERE type = 'table'", -1, &stmt, NULL) != SQLITE_OK) {
    return;
  }
  while (count < MAX_TABLES && lib->step(stmt) == SQLITE_ROW) {
    const unsigned char *name = lib->column_blob(stmt, 0);
    int len = lib->column_bytes(stmt, 0);
    if (!name || len <= 0 || len >= (int)sizeof tables[0] || memchr(name, '"', (size_t)len)) continue;
    memcpy(tables[count], name, (size_t)len);
    tables[count++][len] = 0;
  }
  lib->finalize(stmt);
  for (int i = 0; i < count; i++) {
    char sql[160];
    snprintf(sql, sizeof sql, "SELECT * FROM \"%s\"", tables[i]);
    lib_exec(lib, handle, sql);
  }
}

static void reopen_and_read(const char *name, const struct rawfile *in, const char *key) {
  sqlite3 *handle = app_open(lib, name, in, key);
  if (!handle) return;
  lib_exec(lib, handle, "SELECT count(*) FROM sqlite_schema");
  read_all(handle);
  lib->close_v2(handle);
}

static void backup(sqlite3 *source, const struct rawfile *in) {
  sqlite3 *dest = app_open(lib, "backup.db", in, NULL);
  if (!dest) return;
  if (!known_backup_blocked(major, codec_page_size(source), codec_page_size(dest))) { /* L1 */
    sqlite3_backup *copy = lib->backup_init(dest, "main", source, "main");
    if (copy) {
      lib->backup_step(copy, -1);
      lib->backup_finish(copy);
    }
    read_all(dest);
  }
  lib->close_v2(dest);
}

void app_run(const struct fuzz_sqlite *api, const struct rawfile *in) {
  lib = api;
  major = lib_major(api);
  budget = BUDGET;
  for (int kind = 0; kind < RAWFILE_KINDS; kind++) {
    if (in->files[kind].bytes) memvfs_install(names[kind], in->files[kind].bytes, in->files[kind].len);
  }
  sqlite3 *db = app_open(lib, names[RAWFILE_MAIN], in, NULL);
  if (!db) return;
  lib_exec(lib, db, "SELECT count(*) FROM sqlite_schema");
  if (in->actions & ACT_READ) {
    read_all(db);
    /* A full-text query walks the FTS5 index, which a table scan of the seeds' table f never reads. */
    lib_exec(lib, db, "SELECT rowid, rank FROM f WHERE f MATCH 'canary OR index'");
  }
  if (in->actions & ACT_INTEGRITY) lib_exec(lib, db, "PRAGMA cipher_integrity_check; PRAGMA integrity_check");
  if (in->actions & ACT_WRITE) {
    lib_exec(lib, db,
             "CREATE TABLE IF NOT EXISTS fz(x); INSERT INTO fz VALUES (randomblob(3000)), (zeroblob(5000));"
             "DELETE FROM fz WHERE rowid % 2 = 0");
  }
  /* Migration retries a passphrase at the legacy PBKDF2 counts, far beyond a fuzz iteration's time. */
  if ((in->actions & ACT_MIGRATE) && in->app != APP_PASSPHRASE) lib_exec(lib, db, "PRAGMA cipher_migrate");
  if (in->actions & ACT_EXPORT) {
    lib_exec(lib, db, "ATTACH 'export.db' AS ex KEY \"" KEY_1 "\"; SELECT sqlcipher_export('ex'); DETACH ex");
  }
  if (in->actions & ACT_BACKUP) backup(db, in);
  int rekeyed = 0;
  if (in->actions & ACT_REKEY) rekeyed = lib->rekey_v2(db, "main", KEY_1, (int)strlen(KEY_1)) == SQLITE_OK;
  if (in->actions & ACT_VACUUM) lib_exec(lib, db, "VACUUM");
  lib->close_v2(db);
  if (in->actions & ACT_REKEY) reopen_and_read(names[RAWFILE_MAIN], in, rekeyed ? KEY_1 : NULL);
  if (in->actions & ACT_EXPORT) {
    struct rawfile exported = {.app = APP_RAW_KEY};
    reopen_and_read("export.db", &exported, KEY_1);
  }
}
