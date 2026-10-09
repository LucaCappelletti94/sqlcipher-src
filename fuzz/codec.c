/* The shipped libtomcrypt build under the sanitizers, which see memory errors Wasm memory hides. */
#include "libstate.h"
#include "script.h"

extern const struct fuzz_sqlite FUZZ_LIBTOMCRYPT;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct input in = {data, size};
  fuzz_reset_all();
  script_reset(&FUZZ_LIBTOMCRYPT);
  script_run(&FUZZ_LIBTOMCRYPT, &in, SCRIPT_WITH_RAW_SQL);
  return 0;
}
