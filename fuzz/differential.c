/* One build writes, both read the bytes back, and any libtomcrypt and OpenSSL disagreement aborts. */
#include <stdlib.h>
#include <string.h>

#include "fault.h"
#include "libstate.h"
#include "memvfs.h"
#include "script.h"

extern const struct fuzz_sqlite FUZZ_LIBTOMCRYPT;
extern const struct fuzz_sqlite FUZZ_OPENSSL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  fault_install(&FUZZ_LIBTOMCRYPT);
  fault_install(&FUZZ_OPENSSL);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!size) return 0;
  struct input in = {data + 1, size - 1};
  const struct fuzz_sqlite *writer = data[0] & 1 ? &FUZZ_OPENSSL : &FUZZ_LIBTOMCRYPT;
  const struct fuzz_sqlite *reader = data[0] & 1 ? &FUZZ_LIBTOMCRYPT : &FUZZ_OPENSSL;
  fuzz_reset_all();
  script_reset(writer);
  script_reset(reader);
  script_run(writer, &in, SCRIPT_STRUCTURED);
  memvfs_snapshot();
  for (int file = 0; file < SCRIPT_FILES; file++) {
    struct dump by_writer = {0};
    struct dump by_reader = {0};
    script_dump(writer, file, &by_writer);
    memvfs_restore();
    script_dump(reader, file, &by_reader);
    memvfs_restore();
    int same = by_writer.len == by_reader.len &&
               (by_writer.len == 0 || memcmp(by_writer.bytes, by_reader.bytes, by_writer.len) == 0);
    if (!same) {
      fuzz_report_first_difference(file, writer->name, &by_writer, reader->name, &by_reader);
      abort();
    }
    dump_free(&by_writer);
    dump_free(&by_reader);
  }
  return 0;
}
