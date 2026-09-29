/* The shipped Wasm translation unit, with the VFS and entropy source SQLITE_OS_OTHER leaves to the host replaced by replayable fuzz ones. */
/* sqlite-wasm-rs's libc shim declares getentropy, which under SQLITE_OS_OTHER glibc only does through unistd.h. */
#include <unistd.h>

#include "random.h"
#define getentropy fuzz_getentropy

#include "../sqlcipher/sqlite3.c"

#include "library.h"
