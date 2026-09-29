#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"
#include "libstate.h"
#include "memvfs.h"
#include "plaindiff.h"
#include "random.h"

#define MAX_PAGES 256
#define MAX_PAGE 65536
#define MAX_DUMP (1 << 20)
#define MAX_TABLES 8
#define BUDGET 20000

static const char *const kind_names[RAWFILE_KINDS] = {"main.db", "main.db-wal", "main.db-journal"};

#define MAX_STATEMENTS (MAX_TABLES + 1)

/* A read-back, with where each statement's output starts, so a difference can be named by statement. */
struct dump {
  unsigned char *bytes;
  size_t len;
  int statements;
  size_t starts[MAX_STATEMENTS];
  char sql[MAX_STATEMENTS][160];
  int codes[MAX_STATEMENTS];
};

static long budget;

static int progress(void *unused) {
  (void)unused;
  return --budget < 0;
}

static void put(struct dump *out, const void *bytes, size_t len) {
  if (out->len + len > MAX_DUMP) return;
  memcpy(out->bytes + out->len, bytes, len);
  out->len += len;
}

static void put_statement(const struct fuzz_sqlite *api, sqlite3 *db, const char *sql, struct dump *out) {
  sqlite3_stmt *stmt = NULL;
  int index = out->statements < MAX_STATEMENTS ? out->statements++ : MAX_STATEMENTS - 1;
  out->starts[index] = out->len;
  snprintf(out->sql[index], sizeof out->sql[index], "%s", sql);
  int rc = api->prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc == SQLITE_OK && stmt) {
    while ((rc = api->step(stmt)) == SQLITE_ROW) {
      for (int i = 0; i < api->column_count(stmt); i++) {
        unsigned char type = (unsigned char)api->column_type(stmt, i);
        put(out, &type, 1);
        const void *bytes = api->column_blob(stmt, i);
        int len = api->column_bytes(stmt, i);
        put(out, &len, sizeof len);
        if (bytes && len > 0) put(out, bytes, (size_t)len);
      }
    }
    api->finalize(stmt);
  }
  out->codes[index] = rc;
  unsigned char code = (unsigned char)rc;
  put(out, &code, 1);
}

/* The statement whose output holds byte at. */
static int statement_at(const struct dump *in, size_t at) {
  int found = 0;
  for (int i = 0; i < in->statements; i++) {
    if (in->starts[i] <= at) found = i;
  }
  return found;
}

/* Every table's rows and the integrity check, the same statements for both libraries. */
static void dump(const struct fuzz_sqlite *api, sqlite3 *db, struct dump *out) {
  char tables[MAX_TABLES][128];
  int count = 0;
  sqlite3_stmt *stmt = NULL;
  budget = BUDGET;
  api->progress_handler(db, 100, progress, NULL);
  if (api->prepare_v2(db, "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name", -1, &stmt, NULL) ==
      SQLITE_OK) {
    while (count < MAX_TABLES && api->step(stmt) == SQLITE_ROW) {
      const unsigned char *name = api->column_blob(stmt, 0);
      int len = api->column_bytes(stmt, 0);
      if (!name || len <= 0 || len >= (int)sizeof tables[0] || memchr(name, '"', (size_t)len)) continue;
      memcpy(tables[count], name, (size_t)len);
      tables[count++][len] = 0;
    }
    api->finalize(stmt);
  }
  for (int i = 0; i < count; i++) {
    char sql[160];
    snprintf(sql, sizeof sql, "SELECT * FROM \"%s\"", tables[i]);
    put_statement(api, db, sql, out);
  }
  put_statement(api, db, "PRAGMA integrity_check", out);
}

/* Decodes every page of db through sqlite_dbpage into image and returns the image length, or 0. */
static size_t decode_pages(const struct fuzz_sqlite *api, sqlite3 *db, unsigned char *image, size_t cap) {
  int pages = lib_int(api, db, "PRAGMA page_count");
  size_t at = 0;
  if (pages <= 0 || pages > MAX_PAGES) return 0;
  for (int pgno = 1; pgno <= pages; pgno++) {
    sqlite3_stmt *stmt = NULL;
    int ok = 0;
    if (api->prepare_v2(db, "SELECT data FROM sqlite_dbpage WHERE pgno = ?1", -1, &stmt, NULL) != SQLITE_OK) return 0;
    api->bind_int64(stmt, 1, pgno);
    if (api->step(stmt) == SQLITE_ROW) {
      const void *bytes = api->column_blob(stmt, 0);
      int len = api->column_bytes(stmt, 0);
      if (bytes && len > 0 && len <= MAX_PAGE && at + (size_t)len <= cap) {
        memcpy(image + at, bytes, (size_t)len);
        at += (size_t)len;
        ok = 1;
      }
    }
    api->finalize(stmt);
    if (!ok) return 0;
  }
  return at;
}

/* Whether plain SQLite finds plain.db intact, on its own connection so the comparison starts from a cold cache. */
static int well_formed(const struct fuzz_sqlite *plain) {
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  int ok = 0;
  if (plain->open_v2("plain.db", &db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK) {
    lib_exec(plain, db, "PRAGMA locking_mode = EXCLUSIVE");
    budget = BUDGET;
    plain->progress_handler(db, 100, progress, NULL);
    if (plain->prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, NULL) == SQLITE_OK &&
        plain->step(stmt) == SQLITE_ROW) {
      const unsigned char *text = plain->column_blob(stmt, 0);
      ok = text && plain->column_bytes(stmt, 0) == 2 && memcmp(text, "ok", 2) == 0 && plain->step(stmt) == SQLITE_DONE;
    }
    plain->finalize(stmt);
  }
  plain->close_v2(db);
  return ok;
}

void plaindiff_check(const struct fuzz_sqlite *cipher, const struct fuzz_sqlite *plain, const struct rawfile *in) {
  static unsigned char image[MAX_PAGES * 4096];
  static struct dump by_cipher, by_plain;
  memset(&by_cipher, 0, sizeof by_cipher);
  memset(&by_plain, 0, sizeof by_plain);
  by_cipher.bytes = malloc(MAX_DUMP);
  by_plain.bytes = malloc(MAX_DUMP);
  if (!by_cipher.bytes || !by_plain.bytes) abort();
  memvfs_reset();
  fuzz_random_reset();
  lib_reset(cipher);
  lib_reset(plain);
  for (int kind = 0; kind < RAWFILE_KINDS; kind++) {
    if (in->files[kind].bytes) memvfs_install(kind_names[kind], in->files[kind].bytes, in->files[kind].len);
  }
  sqlite3 *db = app_open(cipher, "main.db", in, NULL);
  size_t len = db ? decode_pages(cipher, db, image, sizeof image) : 0;
  cipher->close_v2(db);
  /* A fresh connection reads the rows, so both sides start from an empty page cache. */
  db = len ? app_open(cipher, "main.db", in, NULL) : NULL;
  if (!db) len = 0;
  if (len) dump(cipher, db, &by_cipher);
  cipher->close_v2(db);
  sqlite3 *reference = NULL;
  /* SQLite reports a corrupt database at points that depend on its page cache, so only well-formed plaintext is
     compared. Corrupt images still run through app_run for memory safety. */
  if (len && (memvfs_install("plain.db", image, len) != SQLITE_OK || !well_formed(plain))) len = 0;
  if (len && plain->open_v2("plain.db", &reference, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK) {
    /* Decoded page 1 keeps its WAL format bytes, which memvfs only serves under exclusive locking, as app_open does. */
    lib_exec(plain, reference, "PRAGMA locking_mode = EXCLUSIVE");
    /* The same limits app_open gives the codec connection, so a size or length limit never reads as a difference. */
    plain->limit(reference, SQLITE_LIMIT_LENGTH, 1 << 20);
    plain->limit(reference, SQLITE_LIMIT_VDBE_OP, 25000);
    dump(plain, reference, &by_plain);
  }
  plain->close_v2(reference);
  if (len && reference) {
    size_t at = 0;
    while (at < by_cipher.len && at < by_plain.len && by_cipher.bytes[at] == by_plain.bytes[at]) at++;
    if (at != by_cipher.len || at != by_plain.len) {
      int a = statement_at(&by_cipher, at), b = statement_at(&by_plain, at);
      for (int i = 0; getenv("PLAINDIFF_VERBOSE") && i < by_cipher.statements; i++) {
        fprintf(stderr, "  codec %d %s | plain %d %s\n", by_cipher.codes[i], by_cipher.sql[i],
                i < by_plain.statements ? by_plain.codes[i] : -1, i < by_plain.statements ? by_plain.sql[i] : "");
      }
      /* Triage aid: the decoded plaintext image, which reproduces the plain side with any SQLite. */
      const char *path = getenv("PLAINDIFF_IMAGE");
      FILE *file = path ? fopen(path, "wb") : NULL;
      if (file) {
        fwrite(image, 1, len, file);
        fclose(file);
      }
      fprintf(stderr,
              "oracle=plaindiff file=main.db page=- reason=%s differs, codec rc %d on '%s', plain rc %d on '%s'\n",
              by_cipher.statements == by_plain.statements ? "rows" : "table list", by_cipher.codes[a], by_cipher.sql[a],
              by_plain.codes[b], by_plain.sql[b]);
      abort();
    }
  }
  free(by_cipher.bytes);
  free(by_plain.bytes);
}
