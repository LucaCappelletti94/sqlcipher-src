#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libstate.h"
#include "memvfs.h"
#include "uniqueness.h"

#define UNIQUENESS_FILES 3
#define MAX_PAGE_CHECK 512
#define MAX_IV_SEEN 2048
#define MAX_SALT_SEEN 64
#define IV_LEN 16

struct file_state {
  /* An unchanged file is skipped, since a page size pragma changed since would misread old bytes as new IVs. */
  unsigned long long last_bytes_hash;
  int has_bytes_hash;
  /* Each page's IV when last looked at, so a page nobody rewrote is not a new draw. */
  unsigned long long last_iv[MAX_PAGE_CHECK];
  int iv_pages;
  /* Every distinct IV fingerprint this file has ever drawn this run, growing monotonically. */
  unsigned long long seen_iv[MAX_IV_SEEN];
  int seen_iv_count;
  unsigned long long last_salt;
  int has_salt;
  int damaged;
  int explicit_salt;
};

static struct file_state files_state[UNIQUENESS_FILES];
/* Salts are compared across files, since two databases must never draw the same one. */
static unsigned long long seen_salt[MAX_SALT_SEEN];
static int seen_salt_count;

void uniqueness_reset(void) {
  memset(files_state, 0, sizeof files_state);
  seen_salt_count = 0;
}

void uniqueness_note_damage(int file) {
  if (file < 0 || file >= UNIQUENESS_FILES) return;
  files_state[file].damaged = 1;
}

void uniqueness_note_explicit_salt(int file) {
  if (file < 0 || file >= UNIQUENESS_FILES) return;
  files_state[file].explicit_salt = 1;
}

static int pragma_int(const struct fuzz_sqlite *api, sqlite3 *db, const char *schema, const char *name, int *out) {
  char sql[96];
  snprintf(sql, sizeof sql, "PRAGMA \"%s\".%s", schema, name);
  sqlite3_stmt *stmt = NULL;
  if (api->prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
  int have = api->step(stmt) == SQLITE_ROW;
  if (have) *out = (int)api->column_int64(stmt, 0);
  api->finalize(stmt);
  return have;
}

static int pragma_text_is(const struct fuzz_sqlite *api, sqlite3 *db, const char *schema, const char *name,
                           const char *value) {
  char sql[96];
  snprintf(sql, sizeof sql, "PRAGMA \"%s\".%s", schema, name);
  sqlite3_stmt *stmt = NULL;
  if (api->prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
  int match = 0;
  if (api->step(stmt) == SQLITE_ROW) {
    const unsigned char *text = api->column_blob(stmt, 0);
    if (text) match = strcmp((const char *)text, value) == 0;
  }
  api->finalize(stmt);
  return match;
}

static int hmac_tag_size(const struct fuzz_sqlite *api, sqlite3 *db, const char *schema) {
  char sql[96];
  snprintf(sql, sizeof sql, "PRAGMA \"%s\".cipher_hmac_algorithm", schema);
  sqlite3_stmt *stmt = NULL;
  int size = 0;
  if (api->prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
  if (api->step(stmt) == SQLITE_ROW) {
    const unsigned char *alg = api->column_blob(stmt, 0);
    if (alg) {
      if (strstr((const char *)alg, "SHA512")) size = 64;
      else if (strstr((const char *)alg, "SHA256")) size = 32;
      else if (strstr((const char *)alg, "SHA1")) size = 20;
    }
  }
  api->finalize(stmt);
  return size;
}

static void check_ivs(int file, const char *file_name, int page_size, int reserve_sz, int unit_len) {
  size_t have = 0;
  const unsigned char *bytes = memvfs_peek(file_name, &have);
  if (!bytes || (size_t)page_size > have) return;
  if (have % (size_t)page_size != 0) return; /* A length this page size cannot produce, so the layout is stale. */
  struct file_state *st = &files_state[file];
  unsigned long long whole_hash = fuzz_fnv1a(bytes, have);
  if (st->has_bytes_hash && st->last_bytes_hash == whole_hash) return;
  st->last_bytes_hash = whole_hash;
  st->has_bytes_hash = 1;
  int pages = (int)(have / (size_t)page_size);
  for (int pgno = 1; pgno <= pages; pgno++) {
    long long page_start = (long long)(pgno - 1) * page_size;
    long long unit_start = page_start + page_size - reserve_sz;
    if (unit_start + unit_len > (long long)have) continue;
    int all_zero = 1;
    for (int b = 0; b < unit_len && all_zero; b++) all_zero = bytes[unit_start + b] == 0;
    if (all_zero) continue; /* Never actually written through the codec, not a real draw: ledger L4's exemption. */
    unsigned long long hash = fuzz_fnv1a(bytes + unit_start, (size_t)unit_len);
    /* Pages past MAX_PAGE_CHECK still meet seen_iv, without the unchanged-since-last-look skip. */
    if (pgno < MAX_PAGE_CHECK && pgno <= st->iv_pages && st->last_iv[pgno - 1] == hash) continue;
    for (int i = 0; i < st->seen_iv_count; i++) {
      if (st->seen_iv[i] == hash) {
        fprintf(stderr, "oracle=uniqueness file=%s page=%d reason=page IV repeats under the same key within this run\n",
                file_name, pgno);
        abort();
      }
    }
    if (st->seen_iv_count < MAX_IV_SEEN) st->seen_iv[st->seen_iv_count++] = hash;
    if (pgno < MAX_PAGE_CHECK) {
      if (pgno > st->iv_pages) st->iv_pages = pgno;
      st->last_iv[pgno - 1] = hash;
    }
  }
}

static void check_salt(int file, const char *file_name) {
  size_t have = 0;
  const unsigned char *bytes = memvfs_peek(file_name, &have);
  if (!bytes || have < IV_LEN) return;
  unsigned long long hash = fuzz_fnv1a(bytes, IV_LEN);
  struct file_state *st = &files_state[file];
  if (st->has_salt && st->last_salt == hash) return;
  for (int i = 0; i < seen_salt_count; i++) {
    if (seen_salt[i] == hash) {
      fprintf(stderr, "oracle=uniqueness file=%s reason=database salt reused across databases in this run\n",
              file_name);
      abort();
    }
  }
  if (seen_salt_count < MAX_SALT_SEEN) seen_salt[seen_salt_count++] = hash;
  st->last_salt = hash;
  st->has_salt = 1;
}

void uniqueness_check(const struct fuzz_sqlite *api, sqlite3 *db, const char *schema, int file,
                       const char *file_name) {
  if (!db || file < 0 || file >= UNIQUENESS_FILES || files_state[file].damaged) return;
  int page_size = 0;
  if (!pragma_int(api, db, schema, "cipher_page_size", &page_size) || page_size <= 0) return;
  int header = 0;
  pragma_int(api, db, schema, "cipher_plaintext_header_size", &header);
  if (header == 0) {
    size_t have = 0;
    const unsigned char *bytes = memvfs_peek(file_name, &have);
    /* A file still opening on the SQLite magic was never written through the codec, whatever the pragma says. */
    if (bytes && have >= 16 && memcmp(bytes, "SQLite format 3\0", 16) == 0) return;
  }
  int aead = 0;
  pragma_int(api, db, schema, "cipher_aead", &aead);

  int reserve_sz = 0, unit_len = 0;
  if (aead) {
    /* The KBKDF context and the GCM IV together pick the page's subkey and nonce, so both are fingerprinted. */
    reserve_sz = 48;
    unit_len = 24;
  } else if (pragma_text_is(api, db, schema, "cipher", "aes-256-cbc") ||
             pragma_text_is(api, db, schema, "cipher", "aes-128-cbc")) {
    int hmac_on = 0;
    pragma_int(api, db, schema, "cipher_use_hmac", &hmac_on);
    int raw = IV_LEN + (hmac_on ? hmac_tag_size(api, db, schema) : 0);
    reserve_sz = raw % 16 == 0 ? raw : (raw / 16 + 1) * 16;
    unit_len = IV_LEN;
  } /* chacha20's reserve padding is not modeled here, so its files get the salt check below but not the IV one. */

  if (reserve_sz > 0 && reserve_sz < page_size) check_ivs(file, file_name, page_size, reserve_sz, unit_len);
  if (header == 0 && !files_state[file].explicit_salt) check_salt(file, file_name);
}
