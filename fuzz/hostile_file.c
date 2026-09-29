/* Position A: the input is the database, WAL and journal bytes an attacker handed over, and the application opens them
   with its own key and settings. build.sh names the build's table in FUZZ_LIBRARY_TABLE. */
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
