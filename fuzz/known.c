#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "known.h"

/* 512 bytes less the largest reserve (16-byte IV and SHA-512 HMAC), rounded down to the AES block. */
#define SAFE_HEADER 416

int known_backup_blocked(int major, int source_page, int dest_page) {
  return major < 5 && source_page && dest_page && source_page != dest_page;
}

int known_vacuum(const char *sql, size_t len) {
  const char *end = sql + len;
  while (sql < end) {
    if (isspace((unsigned char)*sql)) {
      sql++;
    } else if (end - sql >= 2 && sql[0] == '-' && sql[1] == '-') {
      while (sql < end && *sql != '\n') sql++;
    } else if (end - sql >= 2 && sql[0] == '/' && sql[1] == '*') {
      const char *close = sql + 2;
      while (close + 1 < end && !(close[0] == '*' && close[1] == '/')) close++;
      sql = close + 2;
    } else {
      break;
    }
  }
  if (end - sql < 6 || strncasecmp(sql, "VACUUM", 6) != 0) return 0;
  for (const char *at = sql + 6; at + 4 <= end; at++) {
    if (strncasecmp(at, "INTO", 4) == 0) return 2;
  }
  return 1;
}

unsigned known_page_size(int major, unsigned size) {
  return major < 5 && size == 512 ? 1024 : size;
}

unsigned known_header_size(unsigned size) {
  return size > SAFE_HEADER ? SAFE_HEADER : size;
}

int known_header_edit(int major, int plaintext_header, long long offset, long long len) {
  return major < 5 && plaintext_header && offset < 18 && offset + len > 16;
}

int known_header_page_mismatch(int major, int header_page, int codec_page) {
  return major < 5 && header_page && codec_page && header_page != codec_page;
}

/* The integer SQLite reads from a pragma value: decimal, or hexadecimal after 0x. */
static long number(const char *value) {
  if (!value) return -1;
  while (*value == '\'' || *value == '"' || *value == '+' || isspace((unsigned char)*value)) value++;
  int hex = value[0] == '0' && (value[1] == 'x' || value[1] == 'X');
  return strtol(value, NULL, hex ? 16 : 10);
}

int known_denied_pragma(int major, const char *name, const char *value) {
  if (major < 5 && (strcasecmp(name, "cipher_page_size") == 0 || strcasecmp(name, "page_size") == 0 ||
                    strcasecmp(name, "cipher_default_page_size") == 0)) {
    return number(value) == 512; /* L2 */
  }
  if (major >= 5 && strcasecmp(name, "cipher_hmac_fast_kdf") == 0) return 1; /* L3 */
  if (strcasecmp(name, "cipher_plaintext_header_size") == 0 ||
      strcasecmp(name, "cipher_default_plaintext_header_size") == 0) {
    return number(value) > SAFE_HEADER; /* L5 */
  }
  return 0;
}

int known_late_setting(const char *name) {
  return strcasecmp(name, "page_size") == 0 ||
         (strncasecmp(name, "cipher_", 7) == 0 && strncasecmp(name, "cipher_default_", 15) != 0);
}

/* L7: sqlcipherCodecGetKey copies a zero-length pass that its callers never free. */
const char *__lsan_default_suppressions(void);
const char *__lsan_default_suppressions(void) {
  return "leak:sqlcipherCodecGetKey\n";
}
