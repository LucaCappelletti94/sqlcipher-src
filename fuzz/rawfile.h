#ifndef FUZZ_RAWFILE_H
#define FUZZ_RAWFILE_H

#include <stddef.h>
#include <stdint.h>

/* Input format of the file-image targets: a version byte, a fixed 4-byte application header, then sections that each
   carry a 4-byte header (kind, flags, 16-bit little-endian length) and that many bytes of one file. */

#define RAWFILE_VERSION 1
#define RAWFILE_SECTIONS 3

enum rawfile_kind { RAWFILE_MAIN, RAWFILE_WAL, RAWFILE_JOURNAL, RAWFILE_KINDS };

/* The settings an application opens its database with. The input picks one, it never supplies key bytes itself. */
enum rawfile_app {
  APP_RAW_KEY,
  APP_PASSPHRASE,
  APP_PLAINTEXT_HEADER,
  APP_COMPAT_1,
  APP_COMPAT_2,
  APP_COMPAT_2_BE,
  APP_COMPAT_2_BETA,
  APP_COMPAT_3,
  APP_COMPAT_4,
  APP_COUNT,
};

/* Operations after the open, run in bit order. */
enum rawfile_action {
  ACT_READ = 1 << 0,
  ACT_INTEGRITY = 1 << 1,
  ACT_WRITE = 1 << 2,
  ACT_MIGRATE = 1 << 3,
  ACT_EXPORT = 1 << 4,
  ACT_BACKUP = 1 << 5,
  ACT_REKEY = 1 << 6,
  ACT_VACUUM = 1 << 7,
};

struct rawfile_section {
  const uint8_t *bytes;
  size_t len;
};

struct rawfile {
  enum rawfile_app app;
  /* 0 for the application's page size, otherwise 1024 << (page - 1), capped at 65536. */
  unsigned page;
  int use_hmac_off;
  unsigned actions;
  struct rawfile_section files[RAWFILE_KINDS];
};

/* Returns 0 when the input is not this version, so stale corpora are skipped instead of misread. */
int rawfile_decode(const uint8_t *data, size_t size, struct rawfile *out);

/* Writes the encoding of in to out and returns its length, or 0 when cap is too small. */
size_t rawfile_encode(const struct rawfile *in, uint8_t *out, size_t cap);

#endif
