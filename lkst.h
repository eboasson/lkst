/* Copyright (c) 2011 to 2017 Erik Boasson

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. */
#ifndef LKST_H
#define LKST_H

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

/* Time stamps are in some arbitrary (to lockstat) units with are
   arbitrary reference point, are assumed to be monotonically
   increasing at a fixed rate, and are represented as an unsigned 64
   bit integer. (I.e., gethrtime() on Solaris, mach_absolute_time() on
   Mac OS X, &c.)

   If time stamps behave differently, lkst won't mind, but the timing
   data it tracks will be meaningless. */
typedef uint64_t lkst_monotime_t;

#if defined __APPLE__
#include <mach/mach_time.h>
#define lkst_monotime() ((lkst_monotime_t) mach_absolute_time ())
#elif defined __sun
#include <time.h>
#define lkst_monotime() ((lkst_monotime_t) gethrtime ())
#elif __linux
#include <time.h>
#define lkst_monotime() ({                                      \
      struct timespec ts;                                       \
      clock_gettime (CLOCK_MONOTONIC, &ts);                     \
      (lkst_monotime_t) ts.tv_sec * 1000000000 + ts.tv_nsec; })
#else
#error "no definition for lkst_monotime on this platform"
#endif

/* Lock id is address -- of mutex, but I couldn't care less about the
   type. Void *'ll do fine regardless of the underlying mutex
   implementation */
typedef void *lkst_lockid_t;

typedef struct {
  uintptr_t id;
  pid_t pid;
  unsigned generation;
} lkst_full_lockid_t;

typedef void (*lkst_prstack_fun_t) (FILE *fp, pid_t pid, const void *stack, int depth, void *arg);

enum lkst_op {
  LKST_LOCK,
  LKST_UNLOCK
};

#define LKST_DF_SHORT 0
#define LKST_DF_INITSTACK 1
#define LKST_DF_LOCKSTACK 2

typedef struct lkst_trace {
  enum lkst_op op;
  const void *info;
} lkst_trace_t;

/* Flags for lkst_track_init(). LKST_MF_SHARED: lock is shared among
   processes. */
#define LKST_MF_SHARED 1

/* lkst_init(): initialize everything. Returns 0 if lkst not enabled,
   1 if it is.

   - strip_count: the number of levels to strip off the stack trace,
     either 0 or 1 (lkst attempts to increase the strip count such
     that the lkst functions aren't on the traces either).

   lkst_init() creates a service thread for creating symbolic
   stack. This thread has the default thread attributes, has all
   signals blocked and is blocked in read() except when "lkst"
   requests a stack trace.

   lkst_fini() cleans up. */
int lkst_init (int strip_count);
void lkst_fini (void);

/* lkst_track_init() informs lockstat of the existence of a lock, at
   address ((char *) id - lockid_offset). A unique positive lock
   identifier is stored in *id if lockstat is enabled; 0 is stored in
   *id if lockstat is disabled.

   lkst_track_destroy() informs lockstat that the specified lock is no more.

   lkst_track_op() may only be called for locks with a lock id != 0
   and only in between the lkst_track_init() and lkst_track_destroy()
   calls for that lock. */
void lkst_track_init (lkst_lockid_t id, unsigned flags);
void lkst_track_destroy (lkst_lockid_t id);

/* lkst_track_op() informs lockstat of lock and unlock operations on
   the lock with the specified id. ID must be != 0. It may only be
   called with the lock held (ensuring single threaded access to the
   data describing the lock, so no locking is needed in lockstat).

   - id: the id of the lock

   - op: operation. LKST_LOCK for lock and (successful) trylock;
     LKST_UNLOCK for (imminent, because the lock must be held) unlock

   - t: start time of the operation

   - dt: duration of the operation, for lock(), should be 0
     otherwise. For op = LKST_LOCK, dt is interpreted as follows:

     dt = 0: uncontended lock operation, that is, the lock was free at
     the time of calling lock (or trylock).

     dt > 0: contended lock, that is, the lock was held by some other
     thread at the time of calling lock.

   If it cannot be guaranteed that timestamps pre-lock and post-lock
   are different for a contended lock, increase it by 1 to make sure
   contended lock attempts are tracked as such.

   Possible use for wrapping pthreads:

     t = <monotime>
     if (pthread_mutex_trylock (&lk->mutex) == success)
       lkst_track_op (&lk->id, LKST_LOCK, t, 0)
     else
       pthread_mutex_lock (&lk->mutex)
       lkst_track_op (&lk->id, LKST_LOCK, t, 1 | (<monotime> - t));

   Trylock is used to disambiguate between contended and uncontended
   lock operations, and or'ing in 1 ensures a non-zero dt.

   Don't forget cond_wait(), it does an implicit unlock and lock. */
void lkst_track_op (lkst_lockid_t id, enum lkst_op op, lkst_monotime_t t, lkst_monotime_t dt);

void lkst_dump_all_locks (FILE *fp, unsigned format, int justlocked, lkst_prstack_fun_t prstack, void *prstack_arg);
int lkst_dump_lock (FILE *fp, lkst_full_lockid_t lockid, unsigned format, lkst_prstack_fun_t prstack, void *prstack_arg);
void lkst_dump_trace (FILE *fp, const struct lkst_trace *lkt, int abbrev, lkst_prstack_fun_t prstack, void *prstack_arg);
int lkst_hottest_locks (lkst_full_lockid_t locks[], int max);
int lkst_hottest_traces_of_lock (lkst_trace_t traces[], int max, int resv_unlock, lkst_full_lockid_t lockid);

#endif /* LKST_H */
