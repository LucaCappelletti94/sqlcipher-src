#ifndef FUZZ_KNOWN_H
#define FUZZ_KNOWN_H

#include <stddef.h>

/* Steering away from reported upstream defects, one ledger id each. Delete an entry once upstream ships its fix. */

/* L1: 4.x backup between keyed databases whose cipher_page_size differs. */
int known_backup_blocked(int major, int source_page, int dest_page);

/* L1 through VACUUM, which copies pages to a target keyed with the default settings. 2 for VACUUM INTO, 1 in place. */
int known_vacuum(const char *sql, size_t len);

/* L2: 4.x cipher_page_size = 512 after the key. Returns the page size to use instead. */
unsigned known_page_size(int major, unsigned size);

/* L5: a plaintext header larger than the smallest usable page. Returns the header size to use instead. */
unsigned known_header_size(unsigned size);

/* L2, L3, L5 for statements the input writes verbatim. */
int known_denied_pragma(int major, const char *name, const char *value);

/* L8: 4.x trusts the page-size field of an unauthenticated plaintext header. */
int known_header_edit(int major, int plaintext_header, long long offset, long long len);
int known_header_page_mismatch(int major, int header_page, int codec_page);

/* L6: a codec setting applied after the connection touched its file. */
int known_late_setting(const char *name);

/* L11: PRAGMA cipher_migrate poisons the connection (SQLITE_MISUSE on the call itself, then SQLITE_NOTADB on every
   later read) whenever it runs after the connection was otherwise already touched, which has already derived the
   key and discarded the underived material cipher_migrate needs to retry legacy KDF schemes with. This holds for
   every key form, raw or passphrase alike; migrate run as the connection's first operation, before anything else
   touches it, succeeds instead. */
int known_migrate_poisons(int already_touched);

#endif
