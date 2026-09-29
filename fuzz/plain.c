/* Plain SQLite from the release amalgamation, without the codec, as the reference keyed_file compares SQLCipher to.
   5.x compiles SQLCipher in unconditionally, so this one build is the reference for every line while they share a
   SQLite core. */
#define FUZZ_PLAIN 1

#include "sqlcipher.c"

#include "library.h"
