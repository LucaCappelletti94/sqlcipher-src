#include <stddef.h>

#include "fault.h"

static enum fault_kind armed_kind;
static unsigned armed_countdown;

void fault_reset(void) {
  armed_kind = FAULT_NONE;
  armed_countdown = 0;
}

void fault_arm(enum fault_kind kind, unsigned countdown) {
  armed_kind = kind;
  armed_countdown = countdown;
}

void fault_disarm(void) {
  armed_kind = FAULT_NONE;
  armed_countdown = 0;
}

/* Consumes one matching event toward kind's countdown, firing (and disarming) exactly once the countdown runs
   out, never again until the next fault_arm. */
static int consume(enum fault_kind kind) {
  if (armed_kind != kind) return 0;
  if (armed_countdown > 0) {
    armed_countdown--;
    return 0;
  }
  armed_kind = FAULT_NONE;
  return 1;
}

int fault_fire_read(void) { return consume(FAULT_SHORT_READ); }

enum fault_kind fault_fire_write(void) {
  if (consume(FAULT_SHORT_WRITE)) return FAULT_SHORT_WRITE;
  if (consume(FAULT_ENOSPC)) return FAULT_ENOSPC;
  return FAULT_NONE;
}

int fault_fire_sync(void) { return consume(FAULT_FSYNC); }

int fault_fire_alloc(void) { return consume(FAULT_ALLOC); }

/* The real allocator underneath, captured once per provider via SQLITE_CONFIG_GETMALLOC before the wrapper
   below replaces it: every provider's default allocator just calls the process's one libc malloc/free/realloc
   under the hood, so capturing it once and reusing it for whichever provider calls in is safe, the two never
   actually diverge in what they do. */
static sqlite3_mem_methods real_methods;
static int real_methods_captured;

static void *fault_xmalloc(int n) {
  if (fault_fire_alloc()) return NULL;
  return real_methods.xMalloc(n);
}

static void fault_xfree(void *p) { real_methods.xFree(p); }

static void *fault_xrealloc(void *p, int n) {
  if (fault_fire_alloc()) return NULL;
  return real_methods.xRealloc(p, n);
}

static int fault_xsize(void *p) { return real_methods.xSize(p); }

static int fault_xroundup(int n) { return real_methods.xRoundup(n); }

static int fault_xinit(void *arg) {
  return real_methods.xInit ? real_methods.xInit(arg) : SQLITE_OK;
}

static void fault_xshutdown(void *arg) {
  if (real_methods.xShutdown) real_methods.xShutdown(arg);
}

static const sqlite3_mem_methods fault_methods = {
    fault_xmalloc, fault_xfree, fault_xrealloc, fault_xsize, fault_xroundup, fault_xinit, fault_xshutdown, NULL,
};

void fault_install(const struct fuzz_sqlite *api) {
  if (!real_methods_captured) {
    api->config(SQLITE_CONFIG_GETMALLOC, &real_methods);
    real_methods_captured = 1;
  }
  api->config(SQLITE_CONFIG_MALLOC, &fault_methods);
}
