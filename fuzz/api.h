#ifndef FUZZ_API_H
#define FUZZ_API_H

#ifndef SQLITE_HAS_CODEC
#define SQLITE_HAS_CODEC 1
#endif
#include "../sqlcipher/sqlite3.h"

/* The SQLite entry points the harness calls, reached through a table so two SQLCipher builds can share one binary. */
struct fuzz_sqlite {
  const char *name;
  int (*open_v2)(const char *, sqlite3 **, int, const char *);
  int (*close_v2)(sqlite3 *);
  int (*get_autocommit)(sqlite3 *);
  int (*prepare_v2)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
  int (*step)(sqlite3_stmt *);
  int (*finalize)(sqlite3_stmt *);
  int (*column_count)(sqlite3_stmt *);
  int (*column_type)(sqlite3_stmt *, int);
  sqlite3_int64 (*column_int64)(sqlite3_stmt *, int);
  double (*column_double)(sqlite3_stmt *, int);
  const void *(*column_blob)(sqlite3_stmt *, int);
  int (*column_bytes)(sqlite3_stmt *, int);
  int (*bind_int64)(sqlite3_stmt *, int, sqlite3_int64);
  int (*bind_blob)(sqlite3_stmt *, int, const void *, int, void (*)(void *));
  int (*bind_text)(sqlite3_stmt *, int, const char *, int, void (*)(void *));
  int (*key_v2)(sqlite3 *, const char *, const void *, int);
  int (*rekey_v2)(sqlite3 *, const char *, const void *, int);
  int (*set_authorizer)(sqlite3 *, int (*)(void *, int, const char *, const char *, const char *, const char *), void *);
  void (*progress_handler)(sqlite3 *, int, int (*)(void *), void *);
  int (*limit)(sqlite3 *, int, int);
  sqlite3_int64 (*hard_heap_limit64)(sqlite3_int64);
  sqlite3_int64 (*soft_heap_limit64)(sqlite3_int64);
  void (*randomness)(int, void *);
  sqlite3_backup *(*backup_init)(sqlite3 *, const char *, sqlite3 *, const char *);
  int (*backup_step)(sqlite3_backup *, int);
  int (*backup_finish)(sqlite3_backup *);
  int (*config)(int, ...);
};

#endif
