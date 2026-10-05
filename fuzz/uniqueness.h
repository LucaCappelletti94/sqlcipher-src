#ifndef FUZZ_UNIQUENESS_H
#define FUZZ_UNIQUENESS_H

#include "api.h"

/* Checks that a keyed database never draws the same per-page IV twice and that no two databases this run ever
   draw the same salt: both come straight off the deterministic RNG (fuzz/random.c), so a page IV or a salt
   repeating is exactly what a frozen or truncated stream looks like from the outside. The salt, and every
   page's IV, sit unencrypted in the file (the codec authenticates and encrypts everything around them, never
   them), so both are readable straight out of memvfs bytes once the file's page size and reserve layout are
   known. That layout, together with a per-page fingerprint of the current IV and a whole-file fingerprint of the
   current salt, is captured fresh, from live pragmas on the connection that is about to close, at every point a
   file's connection goes away: script.c's own close_db, and the self-contained ATTACH and backup destination
   connections, right before each detaches or closes. Comparing only a fingerprint that has actually changed since
   that file was last looked at against every fingerprint ever seen there catches a real second draw landing on an
   old value without also flagging a page nobody rewrote between two looks, which would otherwise still be
   reporting its first draw. A file with cipher_plaintext_header_size > 0 has no salt in the file at all (the
   plaintext SQLite header sits there instead), so only the IV check runs for it; a file whose active cipher is
   chacha20 has a reserve whose block-padded size this module cannot compute (the 16-byte AES padding constant
   only holds for aes-256-cbc and aes-128-cbc), so only the salt check runs for it. A file never keyed, or keyed
   but never verified to decode, has nothing recorded for it and is skipped entirely, the same gating op_key,
   op_attach and op_backup already use before confidentiality_mark_keyed. op_damage writes bytes taken straight
   off the fuzzer input, the same input a mutator routinely duplicates a chunk of (InsertRepeatedBytes, CopyPart,
   CrossOver), so a flip or an overwrite landing on a reserve or a salt can make two files agree on bytes neither
   the RNG nor the codec ever put there. A file op_damage ever touches is marked and skipped entirely from
   here on, the same call sites and file index tamper_flip and tamper_note already use. PRAGMA cipher_salt lets
   a script set an arbitrary, fuzzer-chosen salt explicitly (SET_SALT in script.c's own setting list), a real,
   documented feature applications use precisely to make two databases share one salt on purpose, so a file
   SET_SALT ever reaches has its salt check dropped for the rest of this run too, the same way: its IV check
   keeps running exactly as before, since an explicit salt says nothing about how its pages' IVs are drawn. */

/* Clears every recorded layout, fingerprint and seen-value table, before each input. */
void uniqueness_reset(void);
/* Marks file (a script.c file index) as damaged, once op_damage writes fuzzer-input bytes into it directly:
   every later uniqueness_check call for that file is a no-op for the rest of this run. Call this at the same
   call sites and with the same file index as tamper_flip and tamper_note. */
void uniqueness_note_damage(int file);
/* Marks file as having had an explicit PRAGMA cipher_salt applied to it (SET_SALT), once script.c's own
   format_setting confirms that pragma actually ran: every later uniqueness_check call skips only the salt check
   for that file, for the rest of this run, leaving its IV check untouched. */
void uniqueness_note_explicit_salt(int file);

/* Samples db's current IV and salt fingerprints for file (a script.c file index) under schema, reading the layout
   straight off db's own pragmas, and aborts on a real second draw of either. Call this on every connection to a
   keyed file right before it closes or detaches, whether or not a key was ever confirmed on this particular
   connection: an unkeyed schema, or one none of this module's supported ciphers, is silently skipped. */
void uniqueness_check(const struct fuzz_sqlite *api, sqlite3 *db, const char *schema, int file,
                       const char *file_name);

#endif
