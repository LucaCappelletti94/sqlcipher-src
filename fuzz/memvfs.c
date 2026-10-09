/* In-memory VFS standing in for sqlite-wasm-rs's under SQLITE_OS_OTHER, so no input touches the disk. */
#include <stdlib.h>
#include <string.h>

#include "../sqlcipher/sqlite3.h"
#include "memvfs.h"

#define MAX_FILES 16
#define MAX_NAME 64
#define MAX_FILE_SIZE (16LL << 20)

struct mem_data {
  int used;
  /* Empty for anonymous temp files and for files deleted while open, so lookups skip them. */
  char name[MAX_NAME + 1];
  unsigned char *bytes;
  long long size;
  long long cap;
  int refs;
};

struct mem_file {
  sqlite3_file base;
  struct mem_data *data;
};

static struct mem_data files[MAX_FILES];

static struct mem_data *lookup(const char *name) {
  for (int i = 0; i < MAX_FILES; i++) {
    if (files[i].used && files[i].name[0] && strcmp(files[i].name, name) == 0) return &files[i];
  }
  return NULL;
}

static struct mem_data *named(int index) {
  for (int i = 0; i < MAX_FILES; i++) {
    if (files[i].used && files[i].name[0] && index-- == 0) return &files[i];
  }
  return NULL;
}

static void release(struct mem_data *data) {
  free(data->bytes);
  memset(data, 0, sizeof *data);
}

static int grow(struct mem_data *data, long long size) {
  if (size > MAX_FILE_SIZE) return SQLITE_FULL;
  if (size > data->cap) {
    long long cap = data->cap ? data->cap : 4096;
    while (cap < size) cap *= 2;
    unsigned char *bytes = realloc(data->bytes, (size_t)cap);
    if (!bytes) return SQLITE_NOMEM;
    data->bytes = bytes;
    data->cap = cap;
  }
  if (size > data->size) {
    memset(data->bytes + data->size, 0, (size_t)(size - data->size));
    data->size = size;
  }
  return SQLITE_OK;
}

static int mem_close(sqlite3_file *file) {
  struct mem_data *data = ((struct mem_file *)file)->data;
  if (--data->refs == 0 && !data->name[0]) release(data);
  return SQLITE_OK;
}

static int mem_read(sqlite3_file *file, void *out, int amount, sqlite3_int64 offset) {
  struct mem_data *data = ((struct mem_file *)file)->data;
  long long have = offset < data->size ? data->size - offset : 0;
  if (have >= amount) {
    memcpy(out, data->bytes + offset, (size_t)amount);
    return SQLITE_OK;
  }
  if (have > 0) memcpy(out, data->bytes + offset, (size_t)have);
  memset((unsigned char *)out + have, 0, (size_t)(amount - have));
  return SQLITE_IOERR_SHORT_READ;
}

static int mem_write(sqlite3_file *file, const void *in, int amount, sqlite3_int64 offset) {
  struct mem_data *data = ((struct mem_file *)file)->data;
  long long end = offset + amount;
  int rc = grow(data, end);
  if (rc != SQLITE_OK) return rc;
  memcpy(data->bytes + offset, in, (size_t)amount);
  return SQLITE_OK;
}

static int mem_truncate(sqlite3_file *file, sqlite3_int64 size) {
  struct mem_data *data = ((struct mem_file *)file)->data;
  if (size < data->size) data->size = size;
  return SQLITE_OK;
}

static int mem_sync(sqlite3_file *file, int flags) {
  (void)file;
  (void)flags;
  return SQLITE_OK;
}

static int mem_file_size(sqlite3_file *file, sqlite3_int64 *size) {
  *size = ((struct mem_file *)file)->data->size;
  return SQLITE_OK;
}

static int mem_lock(sqlite3_file *file, int level) {
  (void)file;
  (void)level;
  return SQLITE_OK;
}

static int mem_check_reserved_lock(sqlite3_file *file, int *out) {
  (void)file;
  *out = 0;
  return SQLITE_OK;
}

static int mem_file_control(sqlite3_file *file, int op, void *arg) {
  (void)file;
  (void)op;
  (void)arg;
  return SQLITE_NOTFOUND;
}

static int mem_sector_size(sqlite3_file *file) {
  (void)file;
  return 512;
}

static int mem_device_characteristics(sqlite3_file *file) {
  (void)file;
  return 0;
}

/* Version 1 has no xShmMap, so SQLite allows WAL only under exclusive locking. */
static const sqlite3_io_methods mem_methods = {
    .iVersion = 1,
    .xClose = mem_close,
    .xRead = mem_read,
    .xWrite = mem_write,
    .xTruncate = mem_truncate,
    .xSync = mem_sync,
    .xFileSize = mem_file_size,
    .xLock = mem_lock,
    .xUnlock = mem_lock,
    .xCheckReservedLock = mem_check_reserved_lock,
    .xFileControl = mem_file_control,
    .xSectorSize = mem_sector_size,
    .xDeviceCharacteristics = mem_device_characteristics,
};

static int mem_open(sqlite3_vfs *vfs, const char *name, sqlite3_file *file, int flags, int *out_flags) {
  (void)vfs;
  struct mem_file *handle = (struct mem_file *)file;
  handle->base.pMethods = NULL;
  if (name && strlen(name) > MAX_NAME) return SQLITE_CANTOPEN;
  struct mem_data *data = name ? lookup(name) : NULL;
  if (!data) {
    if (!(flags & SQLITE_OPEN_CREATE) && name) return SQLITE_CANTOPEN;
    for (int i = 0; i < MAX_FILES && !data; i++) {
      if (!files[i].used) data = &files[i];
    }
    if (!data) return SQLITE_CANTOPEN;
    data->used = 1;
    if (name && !(flags & SQLITE_OPEN_DELETEONCLOSE)) strcpy(data->name, name);
  }
  data->refs++;
  handle->data = data;
  handle->base.pMethods = &mem_methods;
  if (out_flags) *out_flags = flags;
  return SQLITE_OK;
}

static int mem_delete(sqlite3_vfs *vfs, const char *name, int sync) {
  (void)vfs;
  (void)sync;
  struct mem_data *data = lookup(name);
  if (!data) return SQLITE_IOERR_DELETE_NOENT;
  if (data->refs) {
    data->name[0] = 0;
  } else {
    release(data);
  }
  return SQLITE_OK;
}

static int mem_access(sqlite3_vfs *vfs, const char *name, int flags, int *out) {
  (void)vfs;
  (void)flags;
  *out = lookup(name) != NULL;
  return SQLITE_OK;
}

static int mem_full_pathname(sqlite3_vfs *vfs, const char *name, int len, char *out) {
  (void)vfs;
  if ((int)strlen(name) >= len) return SQLITE_CANTOPEN;
  strcpy(out, name);
  return SQLITE_OK;
}

/* A fixed stream, so SQLite's PRNG replays the same values for the same input. */
static int mem_randomness(sqlite3_vfs *vfs, int len, char *out) {
  (void)vfs;
  for (int i = 0; i < len; i++) out[i] = (char)(i * 131 + 7);
  return len;
}

static int mem_sleep(sqlite3_vfs *vfs, int micros) {
  (void)vfs;
  return micros;
}

static int mem_current_time(sqlite3_vfs *vfs, double *now) {
  (void)vfs;
  *now = 2461000.5;
  return SQLITE_OK;
}

static int mem_get_last_error(sqlite3_vfs *vfs, int len, char *out) {
  (void)vfs;
  (void)len;
  (void)out;
  return 0;
}

static int mem_current_time_int64(sqlite3_vfs *vfs, sqlite3_int64 *now) {
  (void)vfs;
  *now = 212630400000000LL;
  return SQLITE_OK;
}

struct sqlite3_vfs *memvfs_create(void) {
  static const sqlite3_vfs template = {
      .iVersion = 2,
      .szOsFile = sizeof(struct mem_file),
      .mxPathname = MAX_NAME,
      .zName = "memvfs",
      .xOpen = mem_open,
      .xDelete = mem_delete,
      .xAccess = mem_access,
      .xFullPathname = mem_full_pathname,
      .xRandomness = mem_randomness,
      .xSleep = mem_sleep,
      .xCurrentTime = mem_current_time,
      .xGetLastError = mem_get_last_error,
      .xCurrentTimeInt64 = mem_current_time_int64,
  };
  sqlite3_vfs *vfs = malloc(sizeof *vfs);
  if (vfs) *vfs = template;
  return vfs;
}

static void drop_all(struct mem_data *store) {
  for (int i = 0; i < MAX_FILES; i++) {
    if (store[i].refs) abort();
    if (store[i].used) release(&store[i]);
  }
}

static void copy_all(struct mem_data *to, const struct mem_data *from) {
  drop_all(to);
  for (int i = 0; i < MAX_FILES; i++) {
    if (from[i].refs) abort();
    if (!from[i].used) continue;
    to[i] = from[i];
    to[i].bytes = NULL;
    to[i].cap = 0;
    to[i].size = 0;
    if (grow(&to[i], from[i].size) != SQLITE_OK) abort();
    if (from[i].size) memcpy(to[i].bytes, from[i].bytes, (size_t)from[i].size);
  }
}

static struct mem_data saved[MAX_FILES];

void memvfs_reset(void) {
  drop_all(files);
  drop_all(saved);
}

void memvfs_snapshot(void) {
  copy_all(saved, files);
}

void memvfs_restore(void) {
  copy_all(files, saved);
}

int memvfs_count(void) {
  int count = 0;
  while (named(count)) count++;
  return count;
}

const char *memvfs_name(int index) {
  return named(index)->name;
}

long long memvfs_size(int index) {
  return named(index)->size;
}

int memvfs_starts_with(int index, const void *prefix, size_t len) {
  struct mem_data *data = named(index);
  return data->size >= (long long)len && memcmp(data->bytes, prefix, len) == 0;
}

int memvfs_header_page_size(const char *name) {
  struct mem_data *data = lookup(name);
  if (!data || data->size < 18 || memcmp(data->bytes, "SQLite format 3", 16) != 0) return 0;
  int size = data->bytes[16] << 8 | data->bytes[17];
  return size == 1 ? 65536 : size;
}

void memvfs_flip(int index, long long offset, unsigned char mask) {
  struct mem_data *data = named(index);
  if (offset < data->size) data->bytes[offset] ^= mask;
}

void memvfs_truncate(int index, long long size) {
  struct mem_data *data = named(index);
  if (size < data->size) data->size = size;
}

void memvfs_overwrite(int index, long long offset, const unsigned char *bytes, size_t len) {
  struct mem_data *data = named(index);
  if (!len || offset > data->size || grow(data, offset + (long long)len) != SQLITE_OK) return;
  memcpy(data->bytes + offset, bytes, len);
}
