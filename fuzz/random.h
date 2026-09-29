#ifndef FUZZ_RANDOM_H
#define FUZZ_RANDOM_H

#include <stddef.h>

/* Replayable stand-ins for the providers' entropy sources, so one input always produces the same salts and IVs. The
   library units map getentropy, RAND_bytes and RAND_add onto these before including the amalgamation. */

/* Restarts the stream, before every input. */
void fuzz_random_reset(void);

int fuzz_getentropy(void *out, size_t len);
int fuzz_rand_bytes(unsigned char *out, int len);
void fuzz_rand_add(const void *in, int len, double entropy);

#endif
