/* One build writes, then both read the same bytes back, and any disagreement between libtomcrypt and OpenSSL aborts.
   build.sh names the two builds' tables in FUZZ_LIBTOMCRYPT and FUZZ_OPENSSL. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memvfs.h"
#include "random.h"
#include "script.h"

extern const struct fuzz_sqlite FUZZ_LIBTOMCRYPT;
extern const struct fuzz_sqlite FUZZ_OPENSSL;

static void report(int file, const struct dump *writer, const struct dump *reader, const char *writer_name,
                   const char *reader_name) {
  size_t at = 0;
  while (at < writer->len && at < reader->len && writer->bytes[at] == reader->bytes[at]) at++;
  fprintf(stderr, "file %d: %s read %zu bytes, %s read %zu, first difference at %zu\n", file, writer_name,
          writer->len, reader_name, reader->len, at);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!size) return 0;
  struct input in = {data + 1, size - 1};
  const struct fuzz_sqlite *writer = data[0] & 1 ? &FUZZ_OPENSSL : &FUZZ_LIBTOMCRYPT;
  const struct fuzz_sqlite *reader = data[0] & 1 ? &FUZZ_LIBTOMCRYPT : &FUZZ_OPENSSL;
  memvfs_reset();
  fuzz_random_reset();
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
      report(file, &by_writer, &by_reader, writer->name, reader->name);
      abort();
    }
    dump_free(&by_writer);
    dump_free(&by_reader);
  }
  return 0;
}
