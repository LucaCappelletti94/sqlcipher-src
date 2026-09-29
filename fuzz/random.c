#include <stdint.h>

#include "random.h"

static uint64_t state;

void fuzz_random_reset(void) {
  state = 0x5eed5eed5eed5eedULL;
}

/* splitmix64 over a counter, a bijection, so no 8-byte block repeats within an input. */
static void fill(unsigned char *out, size_t len) {
  while (len) {
    uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    z ^= z >> 31;
    for (int i = 0; i < 8 && len; i++, len--) {
      *out++ = (unsigned char)z;
      z >>= 8;
    }
  }
}

int fuzz_getentropy(void *out, size_t len) {
  fill(out, len);
  return 0;
}

int fuzz_rand_bytes(unsigned char *out, int len) {
  if (len < 0) return 0;
  fill(out, (size_t)len);
  return 1;
}

void fuzz_rand_add(const void *in, int len, double entropy) {
  (void)in;
  (void)len;
  (void)entropy;
}
