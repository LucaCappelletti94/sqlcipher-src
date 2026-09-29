/* A fetched SQLCipher amalgamation with libtomcrypt, switched as sqlcipher/sqlite3.c switches the shipped one.
   build.sh puts the amalgamation's directory on the quote include path. */
#include <unistd.h>

#define SQLITE_HAS_CODEC 1
#define SQLCIPHER_CRYPTO_LIBTOMCRYPT 1
#define SQLITE_EXTRA_INIT fuzz_fetched_extra_init
#define SQLITE_EXTRA_SHUTDOWN sqlcipher_extra_shutdown
#define SQLCIPHER_OMIT_LOG 1
#define SQLCIPHER_OMIT_LOG_DEVICE 1
#define OMIT_MEMLOCK 1
#undef SQLITE_THREADSAFE
#define SQLITE_THREADSAFE 1
#define SQLITE_MUTEX_NOOP 1

#define LTC_NOTHING
#define LTC_RIJNDAEL
#define LTC_CBC_MODE
/* 5.x encrypts with AES-GCM and derives per-page keys with OMAC. */
#define LTC_GCM_MODE
#define LTC_OMAC
#define LTC_SHA1
#define LTC_SHA256
#define LTC_SHA512
#define LTC_HASH_HELPERS
#define LTC_HMAC
#define LTC_FORTUNA
#define LTC_PKCS_5
#define LTC_RNG_GET_BYTES
#define LTC_PRNG_ENABLE_LTC_RNG
#define LTC_NO_TEST
#define LTC_NO_FILE
#define LTC_NO_ASM
#define LTC_NO_MATH
#define LTC_CLEAN_STACK
#define ARGTYPE 4
#define LTC_SOURCE
#define XCLOCK fuzz_fetched_no_clock
#define XCLOCKS_PER_SEC 1
long fuzz_fetched_no_clock(void);

#include "sqlcipher.c"
#include "../sqlcipher/libtomcrypt.c"

long fuzz_fetched_no_clock(void) { abort(); }

static unsigned long fuzz_fetched_rng(unsigned char *out, unsigned long len, void (*callback)(void)) {
  (void)callback;
  if (getentropy(out, len) != 0) abort();
  return len;
}

int fuzz_fetched_extra_init(const char *arg) {
  ltc_rng = fuzz_fetched_rng;
  return sqlcipher_extra_init(arg);
}

#include "library.h"
