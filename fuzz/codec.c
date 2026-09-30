/* One libtomcrypt build under the sanitizers, where a memory error surfaces instead of silently corrupting Wasm memory.
   build.sh names the build's table in FUZZ_LIBTOMCRYPT. */
#include "confidentiality.h"
#include "memvfs.h"
#include "random.h"
#include "script.h"
#include "tamper.h"

extern const struct fuzz_sqlite FUZZ_LIBTOMCRYPT;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct input in = {data, size};
  memvfs_reset();
  tamper_reset_all();
  confidentiality_reset();
  fuzz_random_reset();
  script_reset(&FUZZ_LIBTOMCRYPT);
  script_run(&FUZZ_LIBTOMCRYPT, &in, SCRIPT_WITH_RAW_SQL);
  return 0;
}
