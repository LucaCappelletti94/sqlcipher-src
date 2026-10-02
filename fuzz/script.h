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

/* Whether sqlcipher_export ever copied content into or out of file during the last script_run call: the
   function has no equivalent on a provider with no codec at all, so content it moved is not comparable against
   plain SQLite running the same script, whatever the two sides otherwise agree on. Queried right after
   script_run, before the next script_run call (on either side) resets it. */
int script_export_touched(int file);

/* Whether OP_FAULT_TXN ever ran against file during the last script_run call: the same countdown lands at a
   wildly different logical I/O moment on a codec connection than on one with no codec at all, so a fault armed
   there can make the two sides diverge in ways that are not a cipher-vs-plain behavioural difference. */
int script_fault_touched(int file);

/* Opens a file with the key and settings the last run left recorded for it, and reads all of it back. */
void script_dump(const struct fuzz_sqlite *api, int file, struct dump *out);

/* Like script_dump, but only the actual table content and a plain integrity_check, none of the result codes a
   codec connection and one with no codec at all structurally differ on regardless of matching content: for
   comparing a keyed connection against plain SQLite running the same script with keys stripped. */
void script_dump_content(const struct fuzz_sqlite *api, int file, struct dump *out);

void dump_free(struct dump *out);

#endif
