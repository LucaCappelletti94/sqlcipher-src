#ifndef FUZZ_SCRIPT_H
#define FUZZ_SCRIPT_H

#include <stddef.h>
#include <stdint.h>

#include "api.h"

struct input {
  const uint8_t *data;
  size_t size;
};

/* Everything a read-back observed, result codes included, so two builds can be compared byte for byte. */
struct dump {
  unsigned char *bytes;
  size_t len;
  size_t cap;
};

enum script_mode {
  SCRIPT_STRUCTURED,
  /* Adds statements taken verbatim from the input, which only the single-build target can afford. */
  SCRIPT_WITH_RAW_SQL,
};

#define SCRIPT_FILES 3

/* Puts the library's process-wide settings back to the same state before every input. */
void script_reset(const struct fuzz_sqlite *api);

/* Runs the operations the input encodes and closes every connection it opened. */
void script_run(const struct fuzz_sqlite *api, struct input *in, enum script_mode mode);

/* Opens a file with the key and settings the last run left recorded for it, and reads all of it back. */
void script_dump(const struct fuzz_sqlite *api, int file, struct dump *out);

void dump_free(struct dump *out);

#endif
