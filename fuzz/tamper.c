#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libstate.h"
#include "memvfs.h"
#include "tamper.h"

#define TAMPER_FILES 3
#define MAX_REGIONS 32
#define MAX_PAGE_CHECK 512
/* The cipher block, so a page rewritten under a new IV changes every window with near certainty. */
#define BLOCK 16

struct region {
  long long offset;
  long long len;
  /* The block-aligned window around the range, whose hash tells a heal from the damage itself. */
  long long lo;
  long long hi;
  /* Running XOR of a one-byte flip region, which drops the region when it cancels to 0. */
  unsigned char mask;
  unsigned long long hash;
};

static struct region regions[TAMPER_FILES][MAX_REGIONS];
static int region_count[TAMPER_FILES];

void tamper_reset_all(void) {
  memset(regions, 0, sizeof regions);
  memset(region_count, 0, sizeof region_count);
}

static void drop(int file, int index) { regions[file][index] = regions[file][--region_count[file]]; }

static unsigned long long window_hash(const struct region *r, const unsigned char *bytes, size_t have) {
  long long hi = r->hi < (long long)have ? r->hi : (long long)have;
  return hi > r->lo ? fuzz_fnv1a(bytes + r->lo, (size_t)(hi - r->lo)) : 0;
}

/* Takes the current window hash of every region of file overlapping [lo, hi), after damage there. */
static void refresh(int file, const unsigned char *bytes, size_t have, long long lo, long long hi) {
  for (int i = 0; i < region_count[file]; i++) {
    struct region *r = &regions[file][i];
    if (r->lo < hi && lo < r->hi) r->hash = window_hash(r, bytes, have);
  }
}

static struct region *add(int file, long long offset, long long len, unsigned char mask) {
  if (region_count[file] >= MAX_REGIONS) return NULL;
  struct region *r = &regions[file][region_count[file]++];
  r->offset = offset;
  r->len = len;
  r->lo = offset / BLOCK * BLOCK;
  r->hi = (offset + len + BLOCK - 1) / BLOCK * BLOCK;
  r->mask = mask;
  return r;
}

void tamper_prune(int file, const char *file_name) {
  if (file < 0 || file >= TAMPER_FILES) return;
  size_t have = 0;
  const unsigned char *bytes = memvfs_peek(file_name, &have);
  for (int i = region_count[file] - 1; i >= 0; i--) {
    if (!bytes || window_hash(&regions[file][i], bytes, have) != regions[file][i].hash) drop(file, i);
  }
}

void tamper_note(int file, const char *file_name, long long offset, long long len) {
  if (file < 0 || file >= TAMPER_FILES || len <= 0) return;
  size_t have = 0;
  const unsigned char *bytes = memvfs_peek(file_name, &have);
  if (!bytes || offset < 0 || offset + len > (long long)have) return;
  struct region *r = add(file, offset, len, 0);
  if (r) refresh(file, bytes, have, r->lo, r->hi);
}

void tamper_flip(int file, const char *file_name, long long offset, unsigned char mask) {
  if (file < 0 || file >= TAMPER_FILES) return;
  size_t have = 0;
  const unsigned char *bytes = memvfs_peek(file_name, &have);
  if (!bytes || offset < 0 || offset >= (long long)have) return;
  long long lo = offset / BLOCK * BLOCK, hi = lo + BLOCK;
  for (int i = 0; i < region_count[file]; i++) {
    if (regions[file][i].len == 1 && regions[file][i].offset == offset) {
      regions[file][i].mask ^= mask;
      if (regions[file][i].mask == 0) drop(file, i);
      refresh(file, bytes, have, lo, hi);
      return;
    }
  }
  if (add(file, offset, 1, mask)) refresh(file, bytes, have, lo, hi);
}

static int page_of(long long offset, int page_size) {
  return (int)(offset / page_size) + 1;
}

/* Aborts when pgno reads back through sqlite_dbpage with SQLITE_OK and non-zero data in [lo, hi) of the page. */
/* Free b-tree space decodes to zeros either way, which is why only the tampered slice is checked. */
static void check_page(const struct fuzz_sqlite *api, sqlite3 *db, const char *file_name, int pgno, long long lo,
                        long long hi) {
  sqlite3_stmt *stmt = NULL;
  if (api->prepare_v2(db, "SELECT data FROM sqlite_dbpage WHERE pgno = ?1", -1, &stmt, NULL) != SQLITE_OK) return;
  api->bind_int64(stmt, 1, pgno);
  if (api->step(stmt) == SQLITE_ROW) {
    const unsigned char *bytes = api->column_blob(stmt, 0);
    int len = api->column_bytes(stmt, 0);
    long long from = lo < 0 ? 0 : lo, to = hi > len ? len : hi;
    int zero = 1;
    for (long long i = from; bytes && zero && i < to; i++) zero = bytes[i] == 0;
    if (bytes && to > from && !zero) {
      api->finalize(stmt);
      fprintf(stderr, "oracle=tamper file=%s page=%d reason=read-back returned non-zero data in the tampered range "
                       "with SQLITE_OK\n",
              file_name, pgno);
      abort();
    }
  }
  api->finalize(stmt);
}

void tamper_check(const struct fuzz_sqlite *api, sqlite3 *db, int file, const char *file_name) {
  if (file < 0 || file >= TAMPER_FILES || !region_count[file] || !db) return;
  size_t have = 0;
  const unsigned char *bytes = memvfs_peek(file_name, &have);
  if (!bytes) return;
  sqlite3_stmt *stmt = NULL;
  int hmac_on = 0;
  if (api->prepare_v2(db, "PRAGMA cipher_use_hmac", -1, &stmt, NULL) == SQLITE_OK) {
    if (api->step(stmt) == SQLITE_ROW) hmac_on = (int)api->column_int64(stmt, 0);
    api->finalize(stmt);
  }
  if (!hmac_on) return; /* No page authentication configured, so a flipped bit is expected to decrypt to garbage. */
  int page_size = 0, header = 0, aead = 0;
  if (api->prepare_v2(db, "PRAGMA main.cipher_page_size", -1, &stmt, NULL) == SQLITE_OK) {
    if (api->step(stmt) == SQLITE_ROW) page_size = (int)api->column_int64(stmt, 0);
    api->finalize(stmt);
  }
  if (page_size <= 0) return;
  if (api->prepare_v2(db, "PRAGMA cipher_plaintext_header_size", -1, &stmt, NULL) == SQLITE_OK) {
    if (api->step(stmt) == SQLITE_ROW) header = (int)api->column_int64(stmt, 0);
    api->finalize(stmt);
  }
  if (api->prepare_v2(db, "PRAGMA cipher_aead", -1, &stmt, NULL) == SQLITE_OK) {
    if (api->step(stmt) == SQLITE_ROW) aead = (int)api->column_int64(stmt, 0);
    api->finalize(stmt);
  }
  /* Page 1 always stores the salt in clear, and the plaintext header extends that unauthenticated prefix. */
  int unauthenticated = header > 16 ? header : 16;
  /* Decryption returns only the IV of the reserve, so the HMAC tag and its padding are skipped, except under AEAD. */
  int reserve_sz = 0;
  if (!aead) {
    int hmac_sz = 0;
    if (api->prepare_v2(db, "PRAGMA cipher_hmac_algorithm", -1, &stmt, NULL) == SQLITE_OK) {
      if (api->step(stmt) == SQLITE_ROW) {
        const unsigned char *alg = api->column_blob(stmt, 0);
        if (alg) {
          if (strstr((const char *)alg, "SHA512")) hmac_sz = 64;
          else if (strstr((const char *)alg, "SHA256")) hmac_sz = 32;
          else if (strstr((const char *)alg, "SHA1")) hmac_sz = 20;
        }
      }
      api->finalize(stmt);
    }
    if (hmac_sz > 0) {
      int raw = 16 + hmac_sz;
      reserve_sz = raw % 16 == 0 ? raw : (raw / 16 + 1) * 16;
    }
  }
  for (int i = 0; i < region_count[file]; i++) {
    long long start = regions[file][i].offset, end = start + regions[file][i].len;
    if (end > (long long)have) continue; /* The file shrank since; nothing to compare against. */
    if (window_hash(&regions[file][i], bytes, have) != regions[file][i].hash) continue; /* Rewritten since. */
    for (int pgno = page_of(start, page_size); (long long)(pgno - 1) * page_size < end; pgno++) {
      long long page_start = (long long)(pgno - 1) * page_size;
      long long populated_end =
          page_start + (reserve_sz > 0 && reserve_sz < page_size ? page_size - reserve_sz : page_size);
      long long lo = start > page_start ? start : page_start;
      if (pgno == 1 && lo < unauthenticated) lo = unauthenticated;
      long long hi = end < populated_end ? end : populated_end;
      if (lo >= hi) continue; /* Entirely inside the unauthenticated header or the reserve's unpopulated tail. */
      if (pgno < 1 || pgno >= MAX_PAGE_CHECK) continue;
      check_page(api, db, file_name, pgno, lo - page_start, hi - page_start);
    }
  }
}

unsigned long long tamper_hash_file(const char *file_name) {
  size_t len = 0;
  const unsigned char *bytes = memvfs_peek(file_name, &len);
  return bytes ? fuzz_fnv1a(bytes, len) : 0;
}

void tamper_check_wrong_key(int rc, unsigned long long before_hash, const char *file_name) {
  if (rc == SQLITE_ROW || rc == SQLITE_DONE) return;
  /* An allocation or I/O failure can return any code, so only the bytes are checked. */
  if (tamper_hash_file(file_name) != before_hash) {
    fprintf(stderr, "oracle=wrongkey file=%s reason=raw bytes changed after a key mismatch\n", file_name);
    abort();
  }
}
