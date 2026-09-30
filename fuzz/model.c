#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "model.h"

#define MAX_TABLES 64
#define MAX_ROW_BYTES (1 << 20)

struct buf {
  unsigned char *bytes;
  size_t len, cap;
};

struct table_hash {
  unsigned long long name_hash;
  unsigned long long content_hash;
};

/* A schema's table list reduced to one hash per table: the name, then every row of that table, typed and
   length-prefixed the same way script.c's own read-back dump already does. schema_rc is the table-listing
   query's own final result code, kept for a trace on a mismatch but never itself compared: a wrong code from an
   allocation or I/O hiccup with the data otherwise consistent is trivial per the plan's own triage bar, so only
   the tables actually listed and their actual rows are ever what this module compares. */
struct snapshot {
  struct table_hash tables[MAX_TABLES];
  int count;
  int schema_rc;
};

/* Whether the table-listing query itself actually finished, rather than breaking off partway through an
   allocation or I/O failure: only then does an empty or short table list mean anything, rather than "could not
   find out". */
static int listing_ok(int rc) { return rc == SQLITE_OK || rc == SQLITE_DONE; }

/* One shared scratch snapshot: every checkpoint's snapshot-then-check pair happens inside a single script.c op,
   back to back, with nothing else able to run in between, so nothing here needs to persist across ops. */
static struct snapshot scratch;
static int scratch_valid;

#define MODEL_FILES 3
static int damaged[MODEL_FILES];

void model_reset(void) {
  scratch_valid = 0;
  memset(damaged, 0, sizeof damaged);
}

void model_note_damage(int file) {
  if (file < 0 || file >= MODEL_FILES) return;
  damaged[file] = 1;
}

void model_discard(void) { scratch_valid = 0; }

static unsigned long long fnv1a(const unsigned char *bytes, size_t len) {
  unsigned long long hash = 1469598103934665603ULL;
  for (size_t i = 0; i < len; i++) {
    hash ^= bytes[i];
    hash *= 1099511628211ULL;
  }
  return hash;
}

static void put(struct buf *b, const void *bytes, size_t len) {
  if (b->len + len > MAX_ROW_BYTES) return; /* A budget guard, not a correctness gate: silently caps how much of a
                                                pathologically large table's rows feed the hash, the same way
                                                script.c's own MAX_DUMP does for its read-back dump. */
  if (b->len + len > b->cap) {
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < b->len + len) cap *= 2;
    unsigned char *grown = realloc(b->bytes, cap);
    if (!grown) abort();
    b->bytes = grown;
    b->cap = cap;
  }
  memcpy(b->bytes + b->len, bytes, len);
  b->len += len;
}

static void put_row(const struct fuzz_sqlite *api, sqlite3_stmt *stmt, struct buf *b) {
  int columns = api->column_count(stmt);
  for (int i = 0; i < columns; i++) {
    unsigned char type = (unsigned char)api->column_type(stmt, i);
    put(b, &type, 1);
    if (type == SQLITE_INTEGER) {
      sqlite3_int64 value = api->column_int64(stmt, i);
      put(b, &value, sizeof value);
    } else if (type == SQLITE_FLOAT) {
      double value = api->column_double(stmt, i);
      put(b, &value, sizeof value);
    } else if (type != SQLITE_NULL) {
      const void *bytes = api->column_blob(stmt, i);
      int len = api->column_bytes(stmt, i);
      put(b, &len, sizeof len);
      if (bytes) put(b, bytes, (size_t)len);
    }
  }
}

/* Every table in schema, reduced to one name/content hash pair each, in schema order: stable across a
   snapshot-check pair as long as nothing in between reorders a b-tree, which none of this module's six
   checkpoint operations does on their own. */
static void take_snapshot(const struct fuzz_sqlite *api, sqlite3 *handle, const char *schema, struct snapshot *out) {
  char names[MAX_TABLES][128];
  int count = 0;
  char sql[160];
  snprintf(sql, sizeof sql, "SELECT name FROM \"%s\".sqlite_schema WHERE type = 'table' ORDER BY name", schema);
  sqlite3_stmt *stmt = NULL;
  int rc = api->prepare_v2(handle, sql, -1, &stmt, NULL);
  if (rc == SQLITE_OK) {
    while ((rc = api->step(stmt)) == SQLITE_ROW) {
      const unsigned char *name = api->column_blob(stmt, 0);
      int len = api->column_bytes(stmt, 0);
      if (count < MAX_TABLES && name && len > 0 && len < (int)sizeof names[0]) {
        memcpy(names[count], name, (size_t)len);
        names[count++][len] = 0;
      }
    }
    api->finalize(stmt);
  }
  out->schema_rc = rc;
  out->count = count;
  for (int i = 0; i < count; i++) {
    out->tables[i].name_hash = fnv1a((const unsigned char *)names[i], strlen(names[i]));
    char select[300];
    size_t at = (size_t)snprintf(select, sizeof select, "SELECT * FROM \"%s\".\"", schema);
    for (const char *c = names[i]; *c && at + 2 < sizeof select; c++) {
      if (*c == '\"') select[at++] = '\"';
      select[at++] = *c;
    }
    if (at + 1 < sizeof select) select[at++] = '\"';
    select[at] = 0;
    struct buf rows = {0};
    stmt = NULL;
    int row_rc = api->prepare_v2(handle, select, -1, &stmt, NULL);
    if (row_rc == SQLITE_OK) {
      while (api->step(stmt) == SQLITE_ROW) put_row(api, stmt, &rows);
      api->finalize(stmt);
    }
    out->tables[i].content_hash = fnv1a(rows.bytes, rows.len);
    free(rows.bytes);
  }
}

static int find_table(const struct snapshot *s, unsigned long long name_hash) {
  for (int i = 0; i < s->count; i++) {
    if (s->tables[i].name_hash == name_hash) return i;
  }
  return -1;
}

void model_snapshot(const struct fuzz_sqlite *api, sqlite3 *handle, const char *schema, int file) {
  if (!handle || file < 0 || file >= MODEL_FILES || damaged[file]) {
    scratch_valid = 0;
    return;
  }
  take_snapshot(api, handle, schema, &scratch);
  scratch_valid = listing_ok(scratch.schema_rc);
}

void model_check(const struct fuzz_sqlite *api, sqlite3 *handle, const char *schema, int file,
                  const char *file_name, const char *op) {
  if (!scratch_valid || !handle || file < 0 || file >= MODEL_FILES || damaged[file]) {
    scratch_valid = 0;
    return;
  }
  struct snapshot after;
  take_snapshot(api, handle, schema, &after);
  scratch_valid = 0;
  if (!listing_ok(after.schema_rc)) return; /* Could not even find out what is there now: not a finding. */
  int same = after.count == scratch.count;
  for (int i = 0; same && i < scratch.count; i++) {
    int j = find_table(&after, scratch.tables[i].name_hash);
    same = j >= 0 && after.tables[j].content_hash == scratch.tables[i].content_hash;
  }
  if (!same) {
    fprintf(stderr, "oracle=model file=%s reason=%s changed logical content it should have preserved\n", file_name,
            op);
    abort();
  }
}

void model_check_contains(const struct fuzz_sqlite *api, sqlite3 *handle, const char *schema, int file,
                           const char *file_name, const char *op) {
  if (!scratch_valid || !handle || file < 0 || file >= MODEL_FILES || damaged[file]) {
    scratch_valid = 0;
    return;
  }
  struct snapshot after;
  take_snapshot(api, handle, schema, &after);
  scratch_valid = 0;
  if (!listing_ok(after.schema_rc)) return; /* Could not even find out what is there now: not a finding. */
  int same = 1;
  for (int i = 0; same && i < scratch.count; i++) {
    int j = find_table(&after, scratch.tables[i].name_hash);
    same = j >= 0 && after.tables[j].content_hash == scratch.tables[i].content_hash;
  }
  if (!same) {
    fprintf(stderr, "oracle=model file=%s reason=%s changed logical content it should have preserved\n", file_name,
            op);
    abort();
  }
}
