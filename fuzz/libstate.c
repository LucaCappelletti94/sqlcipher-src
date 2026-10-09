#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "confidentiality.h"
#include "fault.h"
#include "libstate.h"
#include "memvfs.h"
#include "model.h"
#include "random.h"
#include "script.h"
#include "tamper.h"
#include "uniqueness.h"

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
    if (major && major < 4) abort();
    seen[slot].api = api;
    seen[slot].major = major;
  }
  int major = seen[slot].major;
  if (!major) {
    api->close_v2(handle);
    return;
  }
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

int fuzz_codec_page_size(const struct fuzz_sqlite *api, sqlite3 *handle) {
  return lib_int(api, handle, "PRAGMA main.cipher_page_size");
}

void fuzz_reset_all(void) {
  memvfs_reset();
  tamper_reset_all();
  confidentiality_reset();
  uniqueness_reset();
  model_reset();
  fault_reset();
  fuzz_random_reset();
}

unsigned long long fuzz_fnv1a(const unsigned char *bytes, size_t len) {
  unsigned long long hash = 1469598103934665603ULL;
  for (size_t i = 0; i < len; i++) {
    hash ^= bytes[i];
    hash *= 1099511628211ULL;
  }
  return hash;
}

void fuzz_grow_append(unsigned char **bytes, size_t *len, size_t *cap, size_t max, const void *data,
                      size_t add_len) {
  if (*len + add_len > max) return;
  if (*len + add_len > *cap) {
    size_t new_cap = *cap ? *cap : 4096;
    while (new_cap < *len + add_len) new_cap *= 2;
    unsigned char *grown = realloc(*bytes, new_cap);
    if (!grown) abort();
    *bytes = grown;
    *cap = new_cap;
  }
  memcpy(*bytes + *len, data, add_len);
  *len += add_len;
}

void fuzz_hex(char *out, const unsigned char *bytes, int len) {
  static const char digits[] = "0123456789abcdef";
  for (int i = 0; i < len; i++) {
    out[2 * i] = digits[bytes[i] >> 4];
    out[2 * i + 1] = digits[bytes[i] & 15];
  }
  out[2 * len] = 0;
}

void fuzz_report_first_difference(int file, const char *writer_name, const struct dump *writer,
                                  const char *reader_name, const struct dump *reader) {
  size_t at = 0;
  while (at < writer->len && at < reader->len && writer->bytes[at] == reader->bytes[at]) at++;
  fprintf(stderr, "file %d: %s read %zu bytes, %s read %zu, first difference at %zu\n", file, writer_name,
          writer->len, reader_name, reader->len, at);
}
