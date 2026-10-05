/* One libtomcrypt build under the sanitizers, where a memory error surfaces instead of silently corrupting Wasm memory.
   build.sh names the build's table in FUZZ_LIBTOMCRYPT. */
#include "confidentiality.h"
#include "fault.h"
#include "libstate.h"
#include "memvfs.h"
#include "model.h"
#include "random.h"
#include "script.h"
#include "tamper.h"
#include "uniqueness.h"

extern const struct fuzz_sqlite FUZZ_LIBTOMCRYPT;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  fault_install(&FUZZ_LIBTOMCRYPT);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct input in = {data, size};
  fuzz_reset_all();
  script_reset(&FUZZ_LIBTOMCRYPT);
  script_run(&FUZZ_LIBTOMCRYPT, &in, SCRIPT_WITH_RAW_SQL);
  return 0;
}
