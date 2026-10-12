#include <string.h>

#include "rawfile.h"

int rawfile_decode(const uint8_t *data, size_t size, struct rawfile *out) {
  memset(out, 0, sizeof *out);
  if (size < 5 || data[0] != RAWFILE_VERSION) return 0;
  out->app = (enum rawfile_app)(data[1] % APP_COUNT);
  out->page = data[2] & 7;
  out->use_hmac_off = (data[2] >> 3) & 1;
  out->actions = data[3];
  /* data[4] is reserved, so the application header keeps its 4-byte shape when a field is added. */
  size_t at = 5;
  for (int i = 0; i < RAWFILE_SECTIONS && at + 4 <= size; i++) {
    unsigned kind = data[at] % RAWFILE_KINDS;
    size_t len = (size_t)data[at + 2] | (size_t)data[at + 3] << 8;
    at += 4;
    if (len > size - at) len = size - at;
    if (!out->files[kind].bytes) {
      out->files[kind].bytes = data + at;
      out->files[kind].len = len;
    }
    at += len;
  }
  return 1;
}

size_t rawfile_encode(const struct rawfile *in, uint8_t *out, size_t cap) {
  size_t need = 5;
  for (int kind = 0; kind < RAWFILE_KINDS; kind++) {
    if (in->files[kind].bytes) need += 4 + in->files[kind].len;
    if (in->files[kind].len > 0xffff) return 0;
  }
  if (need > cap) return 0;
  out[0] = RAWFILE_VERSION;
  out[1] = (uint8_t)in->app;
  out[2] = (uint8_t)((in->page & 7) | (in->use_hmac_off ? 8 : 0));
  out[3] = (uint8_t)in->actions;
  out[4] = 0;
  size_t at = 5;
  for (int kind = 0; kind < RAWFILE_KINDS; kind++) {
    if (!in->files[kind].bytes) continue;
    out[at] = (uint8_t)kind;
    out[at + 1] = 0;
    out[at + 2] = (uint8_t)in->files[kind].len;
    out[at + 3] = (uint8_t)(in->files[kind].len >> 8);
    memcpy(out + at + 4, in->files[kind].bytes, in->files[kind].len);
    at += 4 + in->files[kind].len;
  }
  return at;
}
