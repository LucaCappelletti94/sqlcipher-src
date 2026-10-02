/* Runs the same script twice, once against SQLCipher (keyed) and once against plain SQLite (the same input bytes,
   with every key, rekey and cipher-specific pragma either skipped or silently ignored), then compares the two
   independently written databases' logical content. build.sh names the two builds' tables in FUZZ_LIBTOMCRYPT and
   FUZZ_PLAIN; FUZZ_PLAIN is always the shared release build, since the comparison is about the codec layer, which
   plain SQLite has none of, not about which SQLCipher commit is under test. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "confidentiality.h"
#include "fault.h"
#include "memvfs.h"
#include "model.h"
#include "random.h"
#include "script.h"
#include "tamper.h"
#include "uniqueness.h"

extern const struct fuzz_sqlite FUZZ_LIBTOMCRYPT;
extern const struct fuzz_sqlite FUZZ_PLAIN;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  fault_install(&FUZZ_LIBTOMCRYPT);
  return 0;
}

static void report(int file, const struct dump *cipher, const struct dump *plain) {
  size_t at = 0;
  while (at < cipher->len && at < plain->len && cipher->bytes[at] == plain->bytes[at]) at++;
  fprintf(stderr, "file %d: cipher read %zu bytes, plain read %zu, first difference at %zu\n", file, cipher->len,
          plain->len, at);
}

static void reset_all(void) {
  memvfs_reset();
  tamper_reset_all();
  confidentiality_reset();
  uniqueness_reset();
  model_reset();
  fault_reset();
  fuzz_random_reset();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct input cipher_in = {data, size};
  struct input plain_in = {data, size};

  reset_all();
  script_reset(&FUZZ_LIBTOMCRYPT);
  script_run(&FUZZ_LIBTOMCRYPT, &cipher_in, SCRIPT_STRUCTURED);
  int exempt[SCRIPT_FILES];
  for (int file = 0; file < SCRIPT_FILES; file++)
    exempt[file] = script_export_touched(file) || script_fault_touched(file);
  struct dump cipher_dump[SCRIPT_FILES] = {{0}};
  for (int file = 0; file < SCRIPT_FILES; file++) script_dump_content(&FUZZ_LIBTOMCRYPT, file, &cipher_dump[file]);

  reset_all();
  script_reset(&FUZZ_PLAIN);
  script_run(&FUZZ_PLAIN, &plain_in, SCRIPT_STRUCTURED);
  for (int file = 0; file < SCRIPT_FILES; file++) {
    struct dump plain_dump = {0};
    script_dump_content(&FUZZ_PLAIN, file, &plain_dump);
    if (!exempt[file]) {
      int same = cipher_dump[file].len == plain_dump.len &&
                 (cipher_dump[file].len == 0 ||
                  memcmp(cipher_dump[file].bytes, plain_dump.bytes, cipher_dump[file].len) == 0);
      if (!same) {
        report(file, &cipher_dump[file], &plain_dump);
        abort();
      }
    }
    dump_free(&plain_dump);
  }
  for (int file = 0; file < SCRIPT_FILES; file++) dump_free(&cipher_dump[file]);
  return 0;
}
