#ifndef FUZZ_FAULT_H
#define FUZZ_FAULT_H

#include "api.h"

/* One armed fault in memvfs or the SQLite allocator, fired once on the Nth matching event and then disarmed. */
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

/* Arms kind to fire on the matching event after countdown others, 0 meaning the next one. */
void fault_arm(enum fault_kind kind, unsigned countdown);

/* Disarms an unfired fault, so it never reaches a later op. */
void fault_disarm(void);

/* Whether memvfs's current read, write or fsync, or the allocator's current call, is the armed fault. */
int fault_fire_read(void);
enum fault_kind fault_fire_write(void);
int fault_fire_sync(void);
int fault_fire_alloc(void);

/* Installs the fault-aware allocator through api's own sqlite3_config, before api's first open. */
void fault_install(const struct fuzz_sqlite *api);

#endif
