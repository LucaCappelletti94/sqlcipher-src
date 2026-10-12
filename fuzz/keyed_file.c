/* Position B: the attacker knows the key, and SQLCipher must read the result exactly as plain SQLite reads it. */
#include "app.h"
#include "libstate.h"
#include "memvfs.h"
#include "pagemut.h"
#include "plaindiff.h"
#include "random.h"
#include "rawfile.h"

extern const struct fuzz_sqlite FUZZ_LIBRARY_TABLE;
extern const struct fuzz_sqlite FUZZ_PLAIN_TABLE;

size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max);

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max, unsigned int seed) {
  /* One mutation in four stays a raw byte edit, which keeps the unauthenticated parse paths in reach. */
  if (seed % 4) {
    size_t mutated = pagemut_mutate(&FUZZ_LIBRARY_TABLE, data, size, max, seed / 4, LLVMFuzzerMutate);
    if (mutated) return mutated;
  }
  return LLVMFuzzerMutate(data, size, max);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct rawfile in;
  if (!rawfile_decode(data, size, &in)) return -1;
  plaindiff_check(&FUZZ_LIBRARY_TABLE, &FUZZ_PLAIN_TABLE, &in);
  memvfs_reset();
  fuzz_random_reset();
  lib_reset(&FUZZ_LIBRARY_TABLE);
  app_run(&FUZZ_LIBRARY_TABLE, &in);
  return 0;
}
