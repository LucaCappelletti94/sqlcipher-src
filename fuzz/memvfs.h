#ifndef FUZZ_MEMVFS_H
#define FUZZ_MEMVFS_H

#include <stddef.h>

struct sqlite3_vfs;

/* A fresh VFS object per library, since registration links it into that library's list, over one shared file store. */
struct sqlite3_vfs *memvfs_create(void);

/* Drops every file, and aborts if a connection still holds one open. */
void memvfs_reset(void);

/* Copies the store aside and puts it back, so each build reads the same bytes. Both abort while a file is open. */
void memvfs_snapshot(void);
void memvfs_restore(void);

/* Named files, indexed in slot order. */
int memvfs_count(void);
const char *memvfs_name(int index);
long long memvfs_size(int index);
int memvfs_starts_with(int index, const void *prefix, size_t len);
/* The page size a plaintext SQLite header in the named file declares, or 0 when the file has none. */
int memvfs_header_page_size(const char *name);
void memvfs_flip(int index, long long offset, unsigned char mask);
void memvfs_truncate(int index, long long size);
void memvfs_overwrite(int index, long long offset, const unsigned char *bytes, size_t len);

#endif
