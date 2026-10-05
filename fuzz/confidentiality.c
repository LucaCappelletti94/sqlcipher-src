#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "confidentiality.h"
#include "libstate.h"
#include "memvfs.h"
#include "script.h"

#define MAX_MARKERS 256
#define MARKER_LEN 16

/* Nothing else the harness writes starts with this: op_statement's randomblob and bound text, and a passphrase or
   raw key read straight off the fuzzer input, could each in principle collide with any fixed value, but only by
   chance on the full 16 bytes below, the same odds a real ciphertext leak would need to beat to look like a
   coincidence instead of a bug. */
static const unsigned char MAGIC[8] = {0xC0, 0xFF, 0xEE, 0x15, 0xC0, 0xDE, 0xAB, 0xBA};

struct marker {
  unsigned char bytes[MARKER_LEN];
};

static struct marker markers[MAX_MARKERS];
static int marker_count;
/* Process-wide and never reset, seeded once, lazily, from real time rather than from anything the fuzzer input
   or the deterministic per-input streams influence, so no execution's first marker is ever predictable or
   reproducible by choice of input. */
static unsigned long long seq;
static int seq_seeded;
static int expect_encrypted[SCRIPT_FILES];

static unsigned long long next_seq(void) {
  if (!seq_seeded) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    seq = ((unsigned long long)ts.tv_nsec << 32) ^ (unsigned long long)ts.tv_sec ^ (unsigned long long)getpid();
    seq_seeded = 1;
  }
  return seq++;
}

void confidentiality_reset(void) {
  marker_count = 0;
  memset(expect_encrypted, 0, sizeof expect_encrypted);
}

void confidentiality_forget_file(int file) {
  if (file < 0 || file >= SCRIPT_FILES) return;
  expect_encrypted[file] = 0;
}

void confidentiality_mark_keyed(int file) {
  if (file < 0 || file >= SCRIPT_FILES) return;
  expect_encrypted[file] = 1;
}

void confidentiality_plant(const struct fuzz_sqlite *api, sqlite3 *db) {
  if (!db || marker_count >= MAX_MARKERS) return;
  unsigned char marker[MARKER_LEN];
  memcpy(marker, MAGIC, sizeof MAGIC);
  unsigned long long value = next_seq();
  for (int i = 0; i < 8; i++) marker[8 + i] = (unsigned char)(value >> (8 * i));
  char hex[2 * MARKER_LEN + 1];
  fuzz_hex(hex, marker, MARKER_LEN);
  char sql[256];
  snprintf(sql, sizeof sql, "CREATE TABLE canary_%s(v_%s BLOB, t_%s TEXT)", hex, hex, hex);
  sqlite3_stmt *stmt = NULL;
  if (api->prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return;
  api->step(stmt);
  api->finalize(stmt);
  snprintf(sql, sizeof sql, "INSERT INTO canary_%s(v_%s, t_%s) VALUES (?1, ?2)", hex, hex, hex);
  stmt = NULL;
  if (api->prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return;
  api->bind_blob(stmt, 1, marker, MARKER_LEN, SQLITE_TRANSIENT);
  api->bind_text(stmt, 2, (const char *)marker, MARKER_LEN, SQLITE_TRANSIENT);
  api->step(stmt);
  api->finalize(stmt);
  if (marker_count < MAX_MARKERS) memcpy(markers[marker_count++].bytes, marker, MARKER_LEN);
}

static int contains(const unsigned char *hay, size_t hay_len, const unsigned char *needle, int needle_len) {
  if (needle_len <= 0 || (size_t)needle_len > hay_len) return 0;
  for (size_t i = 0; i + (size_t)needle_len <= hay_len; i++) {
    if (memcmp(hay + i, needle, (size_t)needle_len) == 0) return 1;
  }
  return 0;
}

void confidentiality_check(const char *const *files, int count) {
  for (int file = 0; file < count && file < SCRIPT_FILES; file++) {
    if (!expect_encrypted[file]) continue;
    size_t len = 0;
    const unsigned char *bytes = memvfs_peek(files[file], &len);
    if (!bytes) continue;
    for (int i = 0; i < marker_count; i++) {
      if (contains(bytes, len, markers[i].bytes, MARKER_LEN)) {
        fprintf(stderr,
                "oracle=confidentiality file=%s reason=canary material found unencrypted in a keyed file's raw "
                "bytes\n",
                files[file]);
        abort();
      }
    }
  }
}
