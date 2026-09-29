/* SQLCipher with OpenSSL and the SQLite-level switches of sqlcipher/sqlite3.c, so it differs from the libtomcrypt
   build only in the provider. build.sh puts the amalgamation's directory on the quote include path. */
#define SQLITE_HAS_CODEC 1
#define SQLCIPHER_CRYPTO_OPENSSL 1
#define SQLITE_EXTRA_INIT sqlcipher_extra_init
#define SQLITE_EXTRA_SHUTDOWN sqlcipher_extra_shutdown
#define SQLCIPHER_OMIT_LOG 1
#define SQLCIPHER_OMIT_LOG_DEVICE 1
#define OMIT_MEMLOCK 1
#undef SQLITE_THREADSAFE
#define SQLITE_THREADSAFE 1
#define SQLITE_MUTEX_NOOP 1

#include "random.h"
#define RAND_bytes fuzz_rand_bytes
#define RAND_add fuzz_rand_add

#include "sqlcipher.c"

#include "library.h"
