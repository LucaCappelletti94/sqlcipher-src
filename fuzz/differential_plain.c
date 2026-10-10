/* Runs one script on SQLCipher and on plain SQLite, which skips every key, and compares the content each wrote. */
#include <stdlib.h>
#include <string.h>

#include "fault.h"
#include "libstate.h"
#include "script.h"

extern const struct fuzz_sqlite FUZZ_LIBTOMCRYPT;
extern const struct fuzz_sqlite FUZZ_PLAIN;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  fault_install(&FUZZ_LIBTOMCRYPT);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct input cipher_in = {data, size};
  struct input plain_in = {data, size};
  fuzz_reset_all();
  script_reset(&FUZZ_LIBTOMCRYPT);
  script_run(&FUZZ_LIBTOMCRYPT, &cipher_in, SCRIPT_STRUCTURED);
  int exempt[SCRIPT_FILES];
  struct dump cipher_dump[SCRIPT_FILES] = {{0}};
  for (int file = 0; file < SCRIPT_FILES; file++) {
    script_dump_content(&FUZZ_LIBTOMCRYPT, file, &cipher_dump[file]);
    exempt[file] = script_plain_exempt(file);
  }

  fuzz_reset_all();
  script_reset(&FUZZ_PLAIN);
  script_run(&FUZZ_PLAIN, &plain_in, SCRIPT_STRUCTURED);
  for (int file = 0; file < SCRIPT_FILES; file++) {
    struct dump plain_dump = {0};
    script_dump_content(&FUZZ_PLAIN, file, &plain_dump);
    int same = cipher_dump[file].len == plain_dump.len &&
               (plain_dump.len == 0 || memcmp(cipher_dump[file].bytes, plain_dump.bytes, plain_dump.len) == 0);
    if (!exempt[file] && !same) {
      fuzz_report_first_difference(file, "cipher", &cipher_dump[file], "plain", &plain_dump);
      abort();
    }
    dump_free(&plain_dump);
    dump_free(&cipher_dump[file]);
  }
  return 0;
}
