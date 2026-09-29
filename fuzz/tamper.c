#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memvfs.h"
#include "tamper.h"

#define TAMPER_FILES 3
#define MAX_REGIONS 32
#define MAX_PAGE_CHECK 512

struct region {
  long long offset;
  long long len;
  unsigned char mask; /* Cumulative XOR since this region was created, for a len == 1 flip region only. A repeat
                          flip at the same offset that cancels it back to 0 drops the region: op_damage undid its
                          own damage. Unused for a longer, overwritten region. */
  unsigned long long hash; /* Of the file's bytes at [offset, offset + len) right after the last update, so a later
                               check can tell whether a write since then, of any kind, rewrote the range and healed
                               it: the mask alone only catches op_damage cancelling itself. */
};

static struct region regions[TAMPER_FILES][MAX_REGIONS];
static int region_count[TAMPER_FILES];

void tamper_reset_all(void) {
  memset(regions, 0, sizeof regions);
  memset(region_count, 0, sizeof region_count);
}

/* Drops every recorded tamper for file. A rekey re-encrypts every page under a new key, so tracking that survives
   one is definitely stale regardless of hash timing: rekey reads each page through the pager like any other
   access, and if that read raced a flip and still validated, the rekey's own re-encrypt overwrites the flipped
   byte with fresh, valid ciphertext before this call ever gets a chance to compare hashes against it. */
void tamper_clear(int file) {
  if (file < 0 || file >= TAMPER_FILES) return;
  region_count[file] = 0;
}

static unsigned long long fnv1a(const unsigned char *bytes, long long len) {
  unsigned long long hash = 1469598103934665603ULL;
  for (long long i = 0; i < len; i++) {
    hash ^= bytes[i];
    hash *= 1099511628211ULL;
  }
  return hash;
}

static void drop(int file, int index) { regions[file][index] = regions[file][--region_count[file]]; }

void tamper_note(int file, const char *file_name, long long offset, long long len) {
  if (file < 0 || file >= TAMPER_FILES || len <= 0) return;
  size_t have = 0;
  const unsigned char *bytes = memvfs_peek(file_name, &have);
  if (!bytes || offset < 0 || offset + len > (long long)have) return;
  int count = region_count[file];
  if (count >= MAX_REGIONS) return;
  regions[file][count].offset = offset;
  regions[file][count].len = len;
  regions[file][count].mask = 0;
  regions[file][count].hash = fnv1a(bytes + offset, len);
  region_count[file] = count + 1;
}

void tamper_flip(int file, const char *file_name, long long offset, unsigned char mask) {
  if (file < 0 || file >= TAMPER_FILES) return;
  size_t have = 0;
  const unsigned char *bytes = memvfs_peek(file_name, &have);
  if (!bytes || offset < 0 || offset >= (long long)have) return;
  unsigned char current = bytes[offset]; /* Already reflects this flip: memvfs_flip ran before this call. */
  unsigned char before = (unsigned char)(current ^ mask); /* What the byte was immediately before this flip. */
  for (int i = 0; i < region_count[file]; i++) {
    if (regions[file][i].len == 1 && regions[file][i].offset == offset) {
      if (regions[file][i].hash == fnv1a(&before, 1)) {
        /* Nothing rewrote this byte since the region was last updated: chain onto the running mask. */
        regions[file][i].mask ^= mask;
        if (regions[file][i].mask == 0) {
          drop(file, i); /* This exact flip history at this offset now cancels to nothing. */
        } else {
          regions[file][i].hash = fnv1a(&current, 1);
        }
      } else {
        /* Something else rewrote this byte since: the old region is stale, start fresh from this flip alone. */
        regions[file][i].mask = mask;
        regions[file][i].hash = fnv1a(&current, 1);
      }
      return;
    }
  }
  int count = region_count[file];
  if (count >= MAX_REGIONS) return;
  regions[file][count].offset = offset;
  regions[file][count].len = 1;
  regions[file][count].mask = mask;
  regions[file][count].hash = fnv1a(&current, 1);
  region_count[file] = count + 1;
}

static int page_of(long long offset, int page_size) {
  return (int)(offset / page_size) + 1;
}

/* Whether a read of pgno through sqlite_dbpage returns non-zero data with SQLITE_OK, in which case it aborts. */
static void check_page(const struct fuzz_sqlite *api, sqlite3 *db, const char *file_name, int pgno) {
  sqlite3_stmt *stmt = NULL;
  if (api->prepare_v2(db, "SELECT data FROM sqlite_dbpage WHERE pgno = ?1", -1, &stmt, NULL) != SQLITE_OK) return;
  api->bind_int64(stmt, 1, pgno);
  if (api->step(stmt) == SQLITE_ROW) {
    const unsigned char *bytes = api->column_blob(stmt, 0);
    int len = api->column_bytes(stmt, 0);
    int zero = 1;
    for (int i = 0; bytes && zero && i < len; i++) zero = bytes[i] == 0;
    if (bytes && len > 0 && !zero) {
      api->finalize(stmt);
      fprintf(stderr, "oracle=tamper file=%s page=%d reason=read-back returned %d non-zero bytes with SQLITE_OK\n",
              file_name, pgno, len);
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
  /* The codec always stores the salt as the first FILE_HEADER_SZ bytes of page 1 in clear, whatever
     cipher_plaintext_header_size is, and only encrypts and authenticates the rest of the page. */
  int unauthenticated = header > 16 ? header : 16;
  /* Every page's reserve holds a 16-byte IV, then, in non-AEAD HMAC mode, an HMAC tag padded up to a block-size
     multiple; sqlcipher_page_cipher's decrypt only ever memcpy's the IV portion into the output buffer, so a byte
     inside the HMAC tag or its padding never reaches what sqlite_dbpage returns and is never checked by it either.
     Skip that unpopulated tail; leave the whole reserve unexempted under AEAD, whose layout this doesn't model. */
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
  unsigned char seen[MAX_PAGE_CHECK] = {0};
  for (int i = 0; i < region_count[file]; i++) {
    long long start = regions[file][i].offset, end = start + regions[file][i].len;
    if (end > (long long)have) continue; /* The file shrank since; nothing to compare against. */
    if (fnv1a(bytes + start, regions[file][i].len) != regions[file][i].hash) continue; /* Since rewritten, healed. */
    for (int pgno = page_of(start, page_size); (long long)(pgno - 1) * page_size < end; pgno++) {
      long long page_start = (long long)(pgno - 1) * page_size;
      long long populated_end =
          page_start + (reserve_sz > 0 && reserve_sz < page_size ? page_size - reserve_sz : page_size);
      long long lo = start > page_start ? start : page_start;
      if (pgno == 1 && lo < unauthenticated) lo = unauthenticated;
      long long hi = end < populated_end ? end : populated_end;
      if (lo >= hi) continue; /* Entirely inside the unauthenticated header or the reserve's unpopulated tail. */
      if (pgno < 1 || pgno >= MAX_PAGE_CHECK || seen[pgno]) continue;
      seen[pgno] = 1;
      check_page(api, db, file_name, pgno);
    }
  }
}
