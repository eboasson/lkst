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
#ifndef LKST_IMPL_H
#define LKST_IMPL_H

#include "lkst.h"

/* Maximum stack depth, if (much) larger than the average actual stack
   trace depth this is an absolute waste of memory with the stack
   traces embedded in lktrace ... But for OpenSplice with its very
   deep stack traces, it'll do. */
#define MAX_STACK_DEPTH 16

#define MAX_STACK_STRIP_COUNT 3

#define PRIuMONOTIME PRIu64

/* Nothing is ever removed from the lock statistics administration */

/* A lock starts out in no-stack-trace mode, and may switch to
   stack-tracing mode. Never back, and only during
   lkst_track_unlock(). (Not Yet Implemented.) */

/* We do the hash table updates while the lock is held, so we never
   have one lock going into the hash tables twice because of
   concurrent lock operations. */

#define LKI_TRACE 1
#define LKI_REQUEST_TRACE 2
#define LKI_SHARED 4
#define LKI_DEAD 8

struct lkinfo {                      /* LP32   LP64 / L32P64 */
  uintptr_t id;                      /* @0     @0 */
  /* Hash chaining */
  unsigned next_offset;              /* @16    @20 */
  unsigned locked_by_offset;         /* @20    @24 */
  unsigned generation;               /* @24    @28 */
  /* Time of last lock() operation */
  lkst_monotime_t locked_at;         /* @4     @8 */
  /* Whether to track operations in detail, head of a linked list of
     traces for this lock */
  unsigned flags;                    /* @28    @32 */
  unsigned traces_offset;            /* @32    @36 */
  /* Total counts (independent of stack traces, and independent of the
     value of lkinfo::track) are always tracked */
  long contended_count;              /* @36    @40 */
  long uncontended_count;            /* @44    @48 / @44 */
  /* Creator process */
  pid_t pid;                         /*        @56 / @48 */
  /* Stack traces of init & destroy */
  int init_stack_depth;              /* @48    @60 / @52 */
  void *init_stack[MAX_STACK_DEPTH]; /* @52    @64 / @56 */
};

struct lktrace_head {
  /* Hash chaining -- not among the significant bit. It is first so
     that stack is always aligned to a multiple of 64 bits (assuming
     32 bit ints/unsigneds) and no padding is required for 64-bits
     machines. */
  unsigned next_offset;
  /* The lkinfo struct for a lock is unique; when searching for the
     right stack trace entry, a memcmp of LKI, STACK_DEPTH and STACK
     upto STACK_DEPTH will do. There is no padding (we're only doing
     32-bits pointers!)  so no need to worry that either. */
  unsigned lki_offset;
  pid_t pid;
  int stack_depth;
  /* Stack could be stretchy, but given that it is meant for
     OpenSplice with its umpteen levels deep stack traces, that
     complexity doesn't seem worth the bother. */
  void *stack[MAX_STACK_DEPTH];
};
#define LKTRACE_HEAD_SIGPTR(h) ((char *) &((h)->lki_offset))
#define LKTRACE_HEAD_SIGSTART(h) offsetof (struct lktrace_head, lki_offset)
#define LKTRACE_HEAD_SIGLENGTH(h) (offsetof (struct lktrace_head, stack) + (h)->stack_depth * sizeof ((h)->stack[0]) - LKTRACE_HEAD_SIGSTART (h))

struct lktrace {
  struct lktrace_head head;
  unsigned samelock_next_offset;
  enum lkst_op op;
  lkst_monotime_t total_time;
  long hist[8 * sizeof (unsigned) + 1];
};

struct lkadmin {
  /* Whenever we need memory, we use [next_offset, next_offset + size
     - 1] and use C-A-S to claim it atomically */
  unsigned next_offset;

  int lkinfo_hash_size;
  unsigned lkinfo_hash_offset;

  int lktrace_hash_size;
  unsigned lktrace_hash_offset;

  int random_delay;
  unsigned init_lock_flags;
};

#define LKST_SOCKET_NAME "/tmp/lkst-socket"

struct backtrace_request {
  int depth;
  void *stack[MAX_STACK_DEPTH];
};

struct map_info {
  int len;
};

int lkst_init_internal (int strip_count, struct lkadmin *lkadmin_in);
struct lkinfo *lkst_lkinfo_lookup (uintptr_t id, pid_t pid);
struct lkinfo *lkst_lkinfo_lookup_full (lkst_full_lockid_t id);
void lkst_setclear_lkinfo_flag (struct lkinfo *lki, unsigned set, unsigned clear);

#endif /* LKST_IMPL_H */
