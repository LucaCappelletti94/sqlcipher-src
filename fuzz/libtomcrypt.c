/* The shipped Wasm translation unit, unchanged apart from the VFS that SQLITE_OS_OTHER leaves to the host. */
/* sqlite-wasm-rs's libc shim declares getentropy, which under SQLITE_OS_OTHER glibc only does through unistd.h. */
#include <unistd.h>

#include "../sqlcipher/sqlite3.c"

#include "library.h"
