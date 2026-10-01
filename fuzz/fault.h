#ifndef FUZZ_FAULT_H
#define FUZZ_FAULT_H

#include "api.h"

/* memvfs and the SQLite allocator, made to fail deterministically on command: a short read or write, running out
   of space on write, a failed fsync, or a failed allocation, each fired exactly once, on the Nth matching event
   after arming, then automatically disarmed. script.c uses this to test that reopening after a fault shows
   exactly the pre-transaction state (everything after the fault rolled back) or exactly the post-transaction
   state (everything committed despite it), never a partial page, per the plan's own property for this oracle. */
enum fault_kind {
  FAULT_NONE = 0,
  FAULT_SHORT_READ,
  FAULT_SHORT_WRITE,
  FAULT_ENOSPC,
  FAULT_FSYNC,
  FAULT_ALLOC,
};

/* Disarms whatever was armed, before each input. */
void fault_reset(void);

/* Arms kind to fire once it has seen countdown matching events without firing, the next one after that. countdown
   0 fires on the very next matching event. A kind that gets no matching event before fault_disarm or the next
   fault_arm just never fires. */
void fault_arm(enum fault_kind kind, unsigned countdown);

/* Clears whatever is armed without it ever firing, whether or not its countdown ran out. Call this once an op's
   own fault-injected sequence is done, so an unconsumed countdown never reaches across into a later, unrelated
   op's own I/O or allocations. */
void fault_disarm(void);

/* Called by memvfs.c on every read; returns non-zero exactly once, on the matching event, if FAULT_SHORT_READ is
   armed and its countdown has run out on this call specifically. */
int fault_fire_read(void);

/* Called by memvfs.c on every write; returns FAULT_SHORT_WRITE or FAULT_ENOSPC exactly once, matching whichever
   of the two is armed, on the matching event, or FAULT_NONE otherwise. */
enum fault_kind fault_fire_write(void);

/* Called by memvfs.c on every fsync; returns non-zero exactly once, the same way fault_fire_read does. */
int fault_fire_sync(void);

/* Called by the allocator wrapper fault_install installs; returns non-zero exactly once, the same way
   fault_fire_read does. */
int fault_fire_alloc(void);

/* Wraps handle with a fault-aware sqlite3_mem_methods and installs it via config (the provider's own
   sqlite3_config, routed through struct fuzz_sqlite so two providers in one binary each get their own install),
   capturing the provider's real allocator with SQLITE_CONFIG_GETMALLOC first and delegating every non-faulted
   call straight through to it. Safe to call once per provider, before that provider's first sqlite3_open ever,
   never after: SQLite only accepts SQLITE_CONFIG_MALLOC before it initializes itself on first use. */
void fault_install(const struct fuzz_sqlite *api);

#endif
