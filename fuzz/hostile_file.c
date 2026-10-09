/* Position A: an application opens attacker-supplied database, WAL and journal bytes with its own key. */
#include "app.h"
#include "libstate.h"
#include "memvfs.h"
#include "random.h"
#include "rawfile.h"

extern const struct fuzz_sqlite FUZZ_LIBRARY_TABLE;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct rawfile in;
  if (!rawfile_decode(data, size, &in)) return -1;
  memvfs_reset();
  fuzz_random_reset();
  lib_reset(&FUZZ_LIBRARY_TABLE);
  app_run(&FUZZ_LIBRARY_TABLE, &in);
  return 0;
}
