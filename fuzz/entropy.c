/* The sqlite-wasm-rs entropy hook, drawing from the replayable stream. */
#include "random.h"
#define getentropy fuzz_getentropy

#include "sqlcipher-entropy.c"
