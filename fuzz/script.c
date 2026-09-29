/* Interprets fuzzer bytes as SQLCipher operations: keys, codec pragmas, writes, rekeys, exports and file damage. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "known.h"
#include "libstate.h"
#include "memvfs.h"
#include "tamper.h"
#include "script.h"

#define MAX_OPS 64
#define MAX_RECIPE 16
#define MAX_BLOB 20000
#define MAX_RAW_SQL 2048
#define MAX_DUMP (1 << 20)
#define MAX_DUMP_TABLES 8
/* Progress callbacks, each every 100 VDBE ops, before a run or a read-back is interrupted. */
#define SCRIPT_BUDGET 20000
#define DUMP_BUDGET 20000

static const char *const files[SCRIPT_FILES] = {"main.db", "other.db", "third.db"};

enum op {
  OP_OPEN,
  OP_REOPEN,
  OP_CLOSE,
  OP_KEY,
  OP_REKEY,
  OP_SETTING,
  OP_STATEMENT,
  OP_PRAGMA,
  OP_ATTACH,
  OP_BACKUP,
  OP_DAMAGE,
  OP_READ,
  OP_RAW_SQL,
  OP_COUNT,
};

enum step_kind { STEP_KEY, STEP_SETTING };

/* A step is the input slice its operation parsed, so replaying it rebuilds the same key or pragma. */
struct step {
  enum step_kind kind;
  struct input slice;
};

struct recipe {
  struct step steps[MAX_RECIPE];
  int count;
  /* Set once a passphrase key is recorded, since PBKDF2 then runs at the file's kdf_iter. */
  int passphrase;
};

struct key {
  unsigned char bytes[128];
  int len;
  int passphrase;
  int kdf_iter;
};

static const struct fuzz_sqlite *lib;
/* SQLCipher major version of lib, since 5.x drops and adds codec pragmas. */
static int major;
static sqlite3 *db;
static int db_file = -1;
/* Set once the open connection has read or written its file, which ends the window for a first key. */
static int touched;
/* cipher_default_page_size of lib, which a new ATTACH keys its file with. */
static int default_page;
static int trusted;
static long budget;
static struct recipe recipes[SCRIPT_FILES];

static unsigned u8(struct input *in) {
  if (!in->size) return 0;
  in->size--;
  return *in->data++;
}

static unsigned u16(struct input *in) {
  unsigned low = u8(in);
  return low | u8(in) << 8;
}

static unsigned long u32(struct input *in) {
  unsigned long low = u16(in);
  return low | (unsigned long)u16(in) << 16;
}

static struct input take(struct input *in, size_t max) {
  size_t len = u16(in) % (max + 1);
  if (len > in->size) len = in->size;
  struct input out = {in->data, len};
  in->data += len;
  in->size -= len;
  return out;
}

static void hex(char *out, const unsigned char *bytes, int len) {
  static const char digits[] = "0123456789abcdef";
  for (int i = 0; i < len; i++) {
    out[2 * i] = digits[bytes[i] >> 4];
    out[2 * i + 1] = digits[bytes[i] & 15];
  }
  out[2 * len] = 0;
}

static void dump_put(struct dump *out, const void *bytes, size_t len) {
  if (!out || out->len + len > MAX_DUMP) return;
  if (out->len + len > out->cap) {
    size_t cap = out->cap ? out->cap : 4096;
    while (cap < out->len + len) cap *= 2;
    unsigned char *grown = realloc(out->bytes, cap);
    if (!grown) abort();
    out->bytes = grown;
    out->cap = cap;
  }
  memcpy(out->bytes + out->len, bytes, len);
  out->len += len;
}

static void dump_code(struct dump *out, int rc) {
  unsigned char code = (unsigned char)rc;
  dump_put(out, &code, 1);
}

void dump_free(struct dump *out) {
  free(out->bytes);
  memset(out, 0, sizeof *out);
}

/* Pragmas the input may not reach: PBKDF2 cost, disk output, and process-wide state no reset can undo. */
static int authorize(void *unused, int action, const char *name, const char *value, const char *schema,
                     const char *trigger) {
  static const char *const denied[] = {
      "key",          "rekey",          "hexkey",         "hexrekey",
      "textkey",      "textrekey",      "kdf_iter",       "fast_kdf_iter",
      "rekey_kdf_iter", "cipher_default_kdf_iter", "cipher_compatibility",
      "cipher_default_compatibility", "cipher_migrate", "cipher_memory_security",
      "cipher_hmac_salt_mask", "cipher_profile", "cipher_log", "cipher_log_level", "cipher_log_source",
  };
  (void)unused;
  (void)schema;
  (void)trigger;
  if (trusted || !name) return SQLITE_OK;
  /* L8: an attached plaintext-header file read with a page size other than the one its header states. */
  if (action == SQLITE_ATTACH)
    return known_header_page_mismatch(major, memvfs_header_page_size(name), default_page) ? SQLITE_DENY : SQLITE_OK;
  if (action != SQLITE_PRAGMA) return SQLITE_OK;
  for (size_t i = 0; i < sizeof denied / sizeof *denied; i++) {
    if (strcasecmp(name, denied[i]) == 0) return SQLITE_DENY;
  }
  if (known_denied_pragma(major, name, value)) return SQLITE_DENY;
  if (touched && value && known_late_setting(name)) return SQLITE_DENY; /* L6 */
  return SQLITE_OK;
}

static int progress(void *unused) {
  (void)unused;
  return --budget < 0;
}

static sqlite3 *open_file(int file, int create) {
  sqlite3 *handle = NULL;
  int flags = SQLITE_OPEN_READWRITE | (create ? SQLITE_OPEN_CREATE : 0);
  if (lib->open_v2(files[file], &handle, flags, NULL) != SQLITE_OK) {
    lib->close_v2(handle);
    return NULL;
  }
  lib->set_authorizer(handle, authorize, NULL);
  lib->progress_handler(handle, 100, progress, NULL);
  lib->limit(handle, SQLITE_LIMIT_LENGTH, 1 << 20);
  lib->limit(handle, SQLITE_LIMIT_SQL_LENGTH, 1 << 16);
  lib->limit(handle, SQLITE_LIMIT_VDBE_OP, 25000);
  return handle;
}

static void close_db(void) {
  if (db) lib->close_v2(db);
  db = NULL;
  db_file = -1;
  touched = 0;
}

static void dump_row(sqlite3_stmt *stmt, struct dump *out) {
  int columns = lib->column_count(stmt);
  for (int i = 0; i < columns; i++) {
    unsigned char type = (unsigned char)lib->column_type(stmt, i);
    dump_put(out, &type, 1);
    if (type == SQLITE_INTEGER) {
      sqlite3_int64 value = lib->column_int64(stmt, i);
      dump_put(out, &value, sizeof value);
    } else if (type == SQLITE_FLOAT) {
      double value = lib->column_double(stmt, i);
      dump_put(out, &value, sizeof value);
    } else if (type != SQLITE_NULL) {
      const void *bytes = lib->column_blob(stmt, i);
      int len = lib->column_bytes(stmt, i);
      dump_put(out, &len, sizeof len);
      if (bytes) dump_put(out, bytes, (size_t)len);
    }
  }
}

static int drain(sqlite3_stmt *stmt, struct dump *out) {
  int rc;
  while ((rc = lib->step(stmt)) == SQLITE_ROW) dump_row(stmt, out);
  lib->finalize(stmt);
  return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

/* The main database's codec page size, or 0 when it has no codec. */
static int codec_page_size(sqlite3 *handle) {
  return lib_int(lib, handle, "PRAGMA main.cipher_page_size");
}

/* L1: VACUUM INTO, and VACUUM with a file temp store, copy pages into a database keyed with the default page size. */
static int vacuum_blocked(sqlite3 *handle, int vacuum) {
  if (!vacuum || (vacuum == 1 && lib_int(lib, handle, "PRAGMA temp_store") != 1)) return 0;
  return known_backup_blocked(major, codec_page_size(handle), lib_int(lib, handle, "PRAGMA cipher_default_page_size"));
}

/* L8: the handle would read file's plaintext-header database with a different page size than the header states. */
static int header_mismatch(sqlite3 *handle, int file) {
  int header_page = file < 0 ? 0 : memvfs_header_page_size(files[file]);
  return header_page && known_header_page_mismatch(major, header_page, codec_page_size(handle));
}

/* Runs every statement in sql and returns the first failure. */
static int run(sqlite3 *handle, const char *sql, struct dump *out) {
  int result = SQLITE_OK;
  while (sql && *sql) {
    sqlite3_stmt *stmt = NULL;
    const char *tail = NULL;
    int rc = lib->prepare_v2(handle, sql, -1, &stmt, &tail);
    if (rc == SQLITE_OK && stmt && !trusted && vacuum_blocked(handle, known_vacuum(sql, (size_t)(tail - sql)))) {
      lib->finalize(stmt);
      stmt = NULL;
      rc = SQLITE_AUTH;
    }
    if (rc == SQLITE_OK && stmt) rc = drain(stmt, out);
    if (handle == db && !trusted) {
      default_page = lib_int(lib, handle, "PRAGMA cipher_default_page_size");
      touched = 1;
      if (header_mismatch(db, db_file)) break;
    }
    dump_code(out, rc);
    if (result == SQLITE_OK) result = rc;
    if (rc != SQLITE_OK && !stmt) break;
    sql = tail;
  }
  return result;
}

static int run_trusted(sqlite3 *handle, const char *sql, struct dump *out) {
  trusted = 1;
  int rc = run(handle, sql, out);
  trusted = 0;
  return rc;
}

static void read_key(struct input *in, struct key *key) {
  unsigned form = u8(in);
  memset(key, 0, sizeof *key);
  if (form & 1) {
    unsigned char raw[48];
    int len = form & 2 ? 48 : 32;
    for (int i = 0; i < len; i++) raw[i] = (unsigned char)u8(in);
    key->bytes[0] = 'x';
    key->bytes[1] = '\'';
    hex((char *)key->bytes + 2, raw, len);
    key->bytes[2 + 2 * len] = '\'';
    key->len = 3 + 2 * len;
  } else {
    struct input pass = take(in, 64);
    memcpy(key->bytes, pass.data, pass.size);
    key->len = (int)pass.size;
    key->passphrase = key->len > 0;
  }
  key->kdf_iter = (int)(u8(in) % 4) + 1;
}

static int apply_key(sqlite3 *handle, const char *schema, const struct key *key, int rekey, struct dump *out) {
  char sql[96];
  if (rekey) {
    if (major < 5) {
      snprintf(sql, sizeof sql, "PRAGMA \"%s\".rekey_kdf_iter = %d", schema, key->kdf_iter);
      run_trusted(handle, sql, out);
    }
    int rc = lib->rekey_v2(handle, schema, key->bytes, key->len);
    dump_code(out, rc);
    return rc;
  }
  int rc = lib->key_v2(handle, schema, key->bytes, key->len);
  dump_code(out, rc);
  snprintf(sql, sizeof sql, "PRAGMA \"%s\".kdf_iter = %d", schema, key->kdf_iter);
  run_trusted(handle, sql, out);
  return rc;
}

static unsigned page_size(struct input *in) {
  unsigned pick = u8(in);
  return known_page_size(major, pick % 16 < 8 ? 512u << (pick % 8) : u16(in));
}

static const char *pick(struct input *in, const char *const *choices, size_t count) {
  return choices[u8(in) % count];
}
#define PICK(in, choices) pick(in, choices, sizeof choices / sizeof *choices)

enum setting {
  SET_PAGE_SIZE,
  SET_USE_HMAC,
  SET_HMAC_ALGORITHM,
  SET_KDF_ALGORITHM,
  SET_HEADER_SIZE,
  SET_SALT,
  SET_COMPATIBILITY,
  SET_KDF_ITER,
  SET_HMAC_PGNO,
  SET_FAST_KDF_ITER,
  SET_CIPHER,
  SET_AEAD,
  SET_HMAC_FAST_KDF,
};

/* 5.x removes the deprecated pragmas and adds the AEAD switches. */
static const enum setting settings_4[] = {
    SET_PAGE_SIZE, SET_USE_HMAC,  SET_HMAC_ALGORITHM, SET_KDF_ALGORITHM, SET_HEADER_SIZE, SET_SALT,
    SET_COMPATIBILITY, SET_KDF_ITER, SET_HMAC_PGNO, SET_FAST_KDF_ITER, SET_CIPHER,
};
static const enum setting settings_5[] = {
    SET_PAGE_SIZE, SET_USE_HMAC,  SET_HMAC_ALGORITHM, SET_KDF_ALGORITHM, SET_HEADER_SIZE, SET_SALT,
    SET_COMPATIBILITY, SET_KDF_ITER, SET_AEAD, SET_HMAC_FAST_KDF,
};

/* One codec pragma on schema, followed by a cheap kdf_iter wherever the pragma would restore an expensive one. */
static void format_setting(struct input *in, const char *schema, char *sql, size_t cap) {
  static const char *const on_off[] = {"ON", "OFF"};
  static const char *const hmacs[] = {"HMAC_SHA1", "HMAC_SHA256", "HMAC_SHA512", "HMAC_MD5"};
  static const char *const kdfs[] = {"PBKDF2_HMAC_SHA1", "PBKDF2_HMAC_SHA256", "PBKDF2_HMAC_SHA512", "SCRYPT"};
  static const char *const pgnos[] = {"le", "be", "native", "middle"};
  static const char *const ciphers[] = {"aes-256-cbc", "aes-128-cbc", "chacha20"};
  static const unsigned headers[] = {0, 16, 24, 32, 48, 4096};
  unsigned char salt[16];
  char salt_hex[33];
  unsigned choice = u8(in);
  enum setting setting = major < 5 ? settings_4[choice % (sizeof settings_4 / sizeof *settings_4)]
                                   : settings_5[choice % (sizeof settings_5 / sizeof *settings_5)];
  switch (setting) {
  case SET_PAGE_SIZE:
    snprintf(sql, cap, "PRAGMA \"%s\".cipher_page_size = %u", schema, page_size(in));
    break;
  case SET_USE_HMAC:
    snprintf(sql, cap, "PRAGMA \"%s\".cipher_use_hmac = %s", schema, PICK(in, on_off));
    break;
  case SET_HMAC_ALGORITHM:
    snprintf(sql, cap, "PRAGMA \"%s\".cipher_hmac_algorithm = %s", schema, PICK(in, hmacs));
    break;
  case SET_KDF_ALGORITHM:
    snprintf(sql, cap, "PRAGMA \"%s\".cipher_kdf_algorithm = %s", schema, PICK(in, kdfs));
    break;
  case SET_HEADER_SIZE: {
    unsigned index = u8(in);
    unsigned size = index % 8 < 6 ? headers[index % 8] : u8(in);
    snprintf(sql, cap, "PRAGMA \"%s\".cipher_plaintext_header_size = %u", schema, known_header_size(size));
    break;
  }
  case SET_SALT:
    for (int i = 0; i < 16; i++) salt[i] = (unsigned char)u8(in);
    hex(salt_hex, salt, 16);
    snprintf(sql, cap, "PRAGMA \"%s\".cipher_salt = \"x'%s'\"", schema, salt_hex);
    break;
  case SET_COMPATIBILITY:
    snprintf(sql, cap, "PRAGMA \"%s\".cipher_compatibility = %u; PRAGMA \"%s\".kdf_iter = 2", schema, u8(in) % 6,
             schema);
    break;
  case SET_KDF_ITER:
    snprintf(sql, cap, "PRAGMA \"%s\".kdf_iter = %u", schema, u8(in) % 4 + 1);
    break;
  case SET_HMAC_PGNO:
    snprintf(sql, cap, "PRAGMA \"%s\".cipher_hmac_pgno = %s", schema, PICK(in, pgnos));
    break;
  case SET_FAST_KDF_ITER:
    snprintf(sql, cap, "PRAGMA \"%s\".fast_kdf_iter = %u", schema, u8(in) % 4 + 1);
    break;
  case SET_CIPHER:
    snprintf(sql, cap, "PRAGMA \"%s\".cipher = '%s'", schema, PICK(in, ciphers));
    break;
  case SET_AEAD:
    snprintf(sql, cap, "PRAGMA \"%s\".cipher_aead = %s", schema, PICK(in, on_off));
    break;
  case SET_HMAC_FAST_KDF: {
    const char *value = PICK(in, on_off);
    /* L3: cipher_use_hmac redoes the reserve setup that cipher_hmac_fast_kdf skips. */
    snprintf(sql, cap, "PRAGMA \"%s\".cipher_hmac_fast_kdf = %s%s%s%s", schema, value,
             value == on_off[0] ? "; PRAGMA \"" : "", value == on_off[0] ? schema : "",
             value == on_off[0] ? "\".cipher_use_hmac = ON" : "");
    break;
  }
  }
}

static void apply_setting(sqlite3 *handle, const char *schema, struct input *in, struct dump *out) {
  char sql[160];
  format_setting(in, schema, sql, sizeof sql);
  run_trusted(handle, sql, out);
}

static void record(int file, enum step_kind kind, const uint8_t *start, const uint8_t *end) {
  struct recipe *recipe = &recipes[file];
  if (recipe->count == MAX_RECIPE) return;
  recipe->steps[recipe->count].kind = kind;
  recipe->steps[recipe->count].slice.data = start;
  recipe->steps[recipe->count].slice.size = (size_t)(end - start);
  recipe->count++;
}

/* Returns nonzero when the replayed settings disagree with the file's plaintext header (L8). */
static int replay(sqlite3 *handle, int file, struct dump *out) {
  const struct recipe *recipe = &recipes[file];
  for (int i = 0; i < recipe->count; i++) {
    struct input slice = recipe->steps[i].slice;
    if (recipe->steps[i].kind == STEP_KEY) {
      struct key key;
      read_key(&slice, &key);
      apply_key(handle, "main", &key, 0, out);
    } else {
      apply_setting(handle, "main", &slice, out);
    }
  }
  return header_mismatch(handle, file);
}

static void read_all(sqlite3 *handle, struct dump *out) {
  char names[MAX_DUMP_TABLES][128];
  int count = 0;
  sqlite3_stmt *stmt = NULL;
  int rc = lib->prepare_v2(handle, "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name", -1, &stmt,
                           NULL);
  if (rc == SQLITE_OK) {
    while ((rc = lib->step(stmt)) == SQLITE_ROW) {
      dump_row(stmt, out);
      const unsigned char *name = lib->column_blob(stmt, 0);
      int len = lib->column_bytes(stmt, 0);
      if (count < MAX_DUMP_TABLES && name && len < (int)sizeof names[0]) {
        memcpy(names[count], name, (size_t)len);
        names[count++][len] = 0;
      }
    }
    lib->finalize(stmt);
  }
  dump_code(out, rc);
  for (int i = 0; i < count; i++) {
    char sql[300] = "SELECT * FROM \"";
    size_t at = strlen(sql);
    for (const char *c = names[i]; *c; c++) {
      if (*c == '"') sql[at++] = '"';
      sql[at++] = *c;
    }
    sql[at++] = '"';
    sql[at] = 0;
    run(handle, sql, out);
  }
  run_trusted(handle, "PRAGMA cipher_integrity_check; PRAGMA integrity_check", out);
}

static void op_statement(struct input *in) {
  static const char *const statements[] = {
      "CREATE TABLE IF NOT EXISTS t(a INTEGER PRIMARY KEY, b BLOB, c TEXT)",
      "INSERT INTO t(b, c) VALUES (randomblob(?1), ?3)",
      "INSERT INTO t(b, c) SELECT zeroblob(?2), c FROM t LIMIT 16",
      "UPDATE t SET b = randomblob(?1) WHERE a % 3 = ?2 % 3",
      "DELETE FROM t WHERE a % (?2 % 4 + 1) = 0",
      "CREATE INDEX IF NOT EXISTS t_c ON t(c)",
      "CREATE TABLE IF NOT EXISTS w(k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID",
      "INSERT OR REPLACE INTO w VALUES (hex(randomblob(?2 % 32 + 1)), randomblob(?1))",
      "DROP TABLE IF EXISTS w",
      "VACUUM",
      "BEGIN",
      "COMMIT",
      "ROLLBACK",
      "SAVEPOINT s",
      "ROLLBACK TO s",
      "RELEASE s",
      "PRAGMA incremental_vacuum(4)",
      "PRAGMA wal_checkpoint(TRUNCATE)",
      "PRAGMA integrity_check",
      "PRAGMA cipher_integrity_check",
      "SELECT count(*), sum(length(b)) FROM t",
      "CREATE TEMP TABLE IF NOT EXISTS tt AS SELECT * FROM t",
      "PRAGMA cipher_migrate",
  };
  size_t index = u8(in) % (sizeof statements / sizeof *statements);
  unsigned blob = u16(in) % (MAX_BLOB + 1);
  unsigned small = u8(in);
  struct input text = take(in, 256);
  if (!db) return;
  touched = 1;
  /* Migration retries the passphrase at the legacy kdf_iter counts, far beyond a fuzz iteration's time. */
  if (strcmp(statements[index], "PRAGMA cipher_migrate") == 0 && recipes[db_file].passphrase) return;
  if (vacuum_blocked(db, known_vacuum(statements[index], strlen(statements[index])))) return;
  sqlite3_stmt *stmt = NULL;
  if (lib->prepare_v2(db, statements[index], -1, &stmt, NULL) != SQLITE_OK) return;
  lib->bind_int64(stmt, 1, blob);
  lib->bind_int64(stmt, 2, small);
  lib->bind_text(stmt, 3, (const char *)text.data, (int)text.size, SQLITE_TRANSIENT);
  trusted = 1;
  drain(stmt, NULL);
  trusted = 0;
}

static void op_pragma(struct input *in) {
  static const char *const pragmas[] = {"auto_vacuum", "journal_mode", "locking_mode", "cache_size",
                                        "secure_delete", "temp_store",  "synchronous",  "page_size"};
  static const char *const values[][6] = {
      {"NONE", "FULL", "INCREMENTAL"},
      {"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "OFF", "WAL"},
      {"NORMAL", "EXCLUSIVE"},
      {"1", "2", "10", "-2000"},
      {"ON", "OFF", "FAST"},
      {"DEFAULT", "FILE", "MEMORY"},
      {"OFF", "NORMAL", "FULL"},
  };
  static const size_t counts[] = {3, 6, 2, 4, 3, 3, 3};
  size_t index = u8(in) % (sizeof pragmas / sizeof *pragmas);
  char sql[96];
  if (index == 7) {
    snprintf(sql, sizeof sql, "PRAGMA page_size = %u", page_size(in));
  } else {
    snprintf(sql, sizeof sql, "PRAGMA %s = %s", pragmas[index], values[index][u8(in) % counts[index]]);
  }
  /* L6: SQLCipher answers page_size as cipher_page_size, which after first access is the same misuse as a late key. */
  if (!db || (index == 7 && touched)) return;
  touched = 1;
  run_trusted(db, sql, NULL);
  if (header_mismatch(db, db_file)) close_db(); /* L8 */
}

static void op_key(struct input *in, int rekey) {
  const uint8_t *start = in->data;
  struct key key;
  read_key(in, &key);
  /* L6: a key applied after the connection touched the file is position D and corrupts memory. */
  if (!db || (touched && !rekey)) return;
  int rc = apply_key(db, "main", &key, rekey, NULL);
  record(db_file, STEP_KEY, start, in->data);
  if (key.passphrase) recipes[db_file].passphrase = 1;
  if (rekey && rc == SQLITE_OK) tamper_clear(db_file); /* Rekey re-encrypts every page under the new key. */
}

static void op_setting(struct input *in) {
  const uint8_t *start = in->data;
  char sql[160];
  format_setting(in, "main", sql, sizeof sql);
  if (!db || touched) return; /* L6 */
  run_trusted(db, sql, NULL);
  record(db_file, STEP_SETTING, start, in->data);
  if (header_mismatch(db, db_file)) close_db(); /* L8 */
}

static void op_attach(struct input *in) {
  static const char *const moves[] = {
      "SELECT sqlcipher_export('aux')",
      "SELECT sqlcipher_export('main', 'aux')",
      "SELECT count(*) FROM aux.sqlite_schema",
  };
  unsigned target = u8(in);
  const uint8_t *start = in->data;
  struct key key;
  read_key(in, &key);
  const uint8_t *key_end = in->data;
  unsigned settings = u8(in) % 3;
  if (!db) return;
  touched = 1;
  int file = (db_file + 1 + (int)(target % 2)) % SCRIPT_FILES;
  if (known_header_page_mismatch(major, memvfs_header_page_size(files[file]), default_page)) return; /* L8 */
  recipes[file].count = 0;
  recipes[file].passphrase = key.passphrase;
  record(file, STEP_KEY, start, key_end);
  sqlite3_stmt *stmt = NULL;
  if (lib->prepare_v2(db, "ATTACH ?1 AS aux KEY ?2", -1, &stmt, NULL) != SQLITE_OK) return;
  lib->bind_text(stmt, 1, files[file], -1, SQLITE_STATIC);
  lib->bind_blob(stmt, 2, key.bytes, key.len, SQLITE_TRANSIENT);
  trusted = 1;
  int rc = drain(stmt, NULL);
  trusted = 0;
  if (rc != SQLITE_OK) return;
  char sql[96];
  snprintf(sql, sizeof sql, "PRAGMA aux.kdf_iter = %d", key.kdf_iter);
  run_trusted(db, sql, NULL);
  for (unsigned i = 0; i < settings; i++) {
    const uint8_t *setting = in->data;
    apply_setting(db, "aux", in, NULL);
    record(file, STEP_SETTING, setting, in->data);
  }
  run_trusted(db, PICK(in, moves), NULL);
  run_trusted(db, "DETACH aux", NULL);
}

static void op_backup(struct input *in) {
  unsigned target = u8(in);
  const uint8_t *start = in->data;
  struct key key;
  read_key(in, &key);
  if (!db) return;
  touched = 1;
  int file = (db_file + 1 + (int)(target % 2)) % SCRIPT_FILES;
  sqlite3 *dest = open_file(file, 1);
  if (!dest) return;
  recipes[file].count = 0;
  recipes[file].passphrase = key.passphrase;
  apply_key(dest, "main", &key, 0, NULL);
  record(file, STEP_KEY, start, in->data);
  if (known_backup_blocked(major, codec_page_size(db), codec_page_size(dest))) {
    lib->close_v2(dest);
    return;
  }
  sqlite3_backup *backup = lib->backup_init(dest, "main", db, "main");
  if (backup) {
    lib->backup_step(backup, -1);
    lib->backup_finish(backup);
  }
  lib->close_v2(dest);
}

/* The script file index memvfs slot index names, or -1 for a file the script did not create (a temp or super-journal). */
static int file_of_memvfs(int index) {
  const char *name = memvfs_name(index);
  for (int i = 0; i < SCRIPT_FILES; i++) {
    if (strcmp(files[i], name) == 0) return i;
  }
  return -1;
}

static void op_damage(struct input *in) {
  unsigned target = u8(in);
  unsigned kind = u8(in) % 3;
  unsigned long offset = u32(in);
  unsigned mask = u8(in) | 1;
  struct input chunk = kind == 2 ? take(in, 4096) : (struct input){NULL, 0};
  int count = memvfs_count();
  if (!count) return;
  int index = (int)(target % (unsigned)count);
  long long size = memvfs_size(index);
  long long at = kind == 0 && size ? (long long)(offset % (unsigned long long)size)
                                   : (long long)(offset % (unsigned long long)(size + 1));
  long long len = kind == 0 ? 1 : kind == 2 ? (long long)chunk.size : 0;
  if (known_header_edit(major, memvfs_starts_with(index, "SQLite format 3", 16), at, len)) return;
  if (kind == 0) {
    if (size) {
      memvfs_flip(index, at, (unsigned char)mask);
      tamper_flip(file_of_memvfs(index), memvfs_name(index), at, (unsigned char)mask);
    }
  } else if (kind == 1) {
    memvfs_truncate(index, at);
  } else {
    memvfs_overwrite(index, at, chunk.data, chunk.size);
    if (chunk.size) tamper_note(file_of_memvfs(index), memvfs_name(index), at, len);
  }
}

static void op_raw_sql(struct input *in) {
  struct input text = take(in, MAX_RAW_SQL);
  char sql[MAX_RAW_SQL + 1];
  memcpy(sql, text.data, text.size);
  sql[text.size] = 0;
  if (!db) return;
  run(db, sql, NULL);
  if (header_mismatch(db, db_file)) close_db(); /* L8 */
}

static void use(const struct fuzz_sqlite *api) {
  lib = api;
  major = lib_major(api);
}

void script_reset(const struct fuzz_sqlite *api) {
  sqlite3 *handle = NULL;
  lib_reset(api);
  use(api);
  if (api->open_v2(":memory:", &handle, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) abort();
  default_page = lib_int(lib, handle, "PRAGMA cipher_default_page_size");
  api->close_v2(handle);
}

void script_run(const struct fuzz_sqlite *api, struct input *in, enum script_mode mode) {
  unsigned ops = mode == SCRIPT_WITH_RAW_SQL ? OP_COUNT : OP_RAW_SQL;
  use(api);
  budget = SCRIPT_BUDGET;
  memset(recipes, 0, sizeof recipes);
  for (int n = 0; n < MAX_OPS && in->size; n++) {
    unsigned opcode = u8(in) % ops;
    switch ((enum op)opcode) {
    case OP_OPEN: {
      int file = (int)(u8(in) % SCRIPT_FILES);
      close_db();
      db = open_file(file, 1);
      if (db) db_file = file;
      memset(&recipes[file], 0, sizeof recipes[file]);
      break;
    }
    case OP_REOPEN: {
      int file = db_file;
      if (file < 0) break;
      close_db();
      db = open_file(file, 0);
      if (!db) break;
      db_file = file;
      if (replay(db, file, NULL)) close_db(); /* L8 */
      break;
    }
    case OP_CLOSE:
      close_db();
      break;
    case OP_KEY:
      op_key(in, 0);
      break;
    case OP_REKEY:
      op_key(in, 1);
      break;
    case OP_SETTING:
      op_setting(in);
      break;
    case OP_STATEMENT:
      op_statement(in);
      break;
    case OP_PRAGMA:
      op_pragma(in);
      break;
    case OP_ATTACH:
      op_attach(in);
      break;
    case OP_BACKUP:
      op_backup(in);
      break;
    case OP_DAMAGE:
      op_damage(in);
      break;
    case OP_READ:
      if (!db) break;
      touched = 1;
      /* Not checked here: this connection may have cached the page from before a later OP_DAMAGE, which the tamper
         oracle would then read as if it were fresh. OP_REOPEN and script_dump check on a connection that never
         cached anything. */
      read_all(db, NULL);
      break;
    case OP_RAW_SQL:
      op_raw_sql(in);
      break;
    case OP_COUNT:
      abort();
    }
  }
  close_db();
}

void script_dump(const struct fuzz_sqlite *api, int file, struct dump *out) {
  use(api);
  budget = DUMP_BUDGET;
  sqlite3 *handle = open_file(file, 0);
  dump_code(out, handle ? SQLITE_OK : SQLITE_CANTOPEN);
  if (!handle) return;
  if (!replay(handle, file, out)) {
    read_all(handle, out);
    tamper_check(lib, handle, file, files[file]);
  } /* L8 */
  lib->close_v2(handle);
}
