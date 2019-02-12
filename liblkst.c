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
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <execinfo.h>
#include <pthread.h>

#include "lkst.h"
#include "lkst_impl.h"

#include "lkst_cas.h"

/* This messy stuff is because I want to get a valid struct
   lktrace_head for hash table lookup without any extra
   memcpy'ing. (Long live C, that it allows this sort of trickery!).
   Sizing dummy as MAX_STACK_STRIP_COUNT is overkill, lktrace_head has
   a few bytes preceding the stack trace, but this will work
   regardless of other settings.

   Cause of the problem is that we don't care about os_mutexInit(),
   lkst_track_init() and backtrace(), or os_mutexLock(),
   lkst_track_(un)?contended() and backtrace() &c. in the stack traces
   we collect. Hence the +3.

   Except that Mac OS does it slightly differently than Linux ... so
   instead of 3 we do stack_strip_count, which is always >= 0 && <=
   3. */
struct messy {
  void *dummy[MAX_STACK_STRIP_COUNT];
  struct lktrace_head head;
};

/* I despise dynamic typing for this kind of stuff. But let us please
   let the compiler do as much as possible, and do some at runtime
   when NDEBUG is not defined. (Easy, since offsets are smallish,
   compared to a 32-bit int, and we have very few types.) */
#ifndef NDEBUG
#define OFFTAG(off) ((off) & 3u)
#define OFFTAG_STRIP(off) ((off) >> 2)
#define OFFTAG_ADD(off, tag) (((off) << 2) | (tag))
#define OFFTAG_LKINFO 1
#define OFFTAG_LKTRACE 2
#else
#define OFFTAG(off) 0
#define OFFTAG_STRIP(off) (off)
#define OFFTAG_ADD(off) (off)
#define OFFTAG_LKINFO 0
#define OFFTAG_LKTRACE 0
#endif

static int am_server;
static int enabled;
static pid_t selfpid;
static int sock_fd;
static pthread_t backtrace_tid;
static int stack_strip_count;
static struct map_info map_info;
static struct lkadmin *lkadmin;
static int lkinfo_hash_size;
static int lktrace_hash_size;
static unsigned *lkinfo_hash;
static unsigned *lktrace_hash;

static int do_maprequest (int sock, struct map_info *data)
{
  struct msghdr xmsg, msg;
  struct iovec iov[1];
  struct {
    struct cmsghdr hdr;
    int fd;
  } cmsg_buf;
  struct cmsghdr *cmsg;
  int ret;
  /* Send request (= own pid) for information & file descriptor */
  xmsg.msg_name = NULL;
  xmsg.msg_namelen = 0;
  iov[0].iov_base = &selfpid;
  iov[0].iov_len = sizeof (selfpid);
  xmsg.msg_iov = iov;
  xmsg.msg_iovlen = 1;
  xmsg.msg_control = NULL;
  xmsg.msg_controllen = 0;
  xmsg.msg_flags = 0;
  if (sendmsg (sock, &xmsg, 0) != (int) iov[0].iov_len)
  {
    perror ("sendmsg");
    goto err;
  }
  /* Get the reply */
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  iov[0].iov_base = data;
  iov[0].iov_len = sizeof (*data);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_control = &cmsg_buf;
  msg.msg_controllen = sizeof (cmsg_buf);
  if (recvmsg (sock, &msg, 0) != sizeof (*data))
  {
    perror ("recvmsg");
    goto err;
  }
  if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
  {
    fprintf (stderr, "flags %d %d: truncated message\n", (msg.msg_flags & MSG_TRUNC) ? 1 : 0, (msg.msg_flags & MSG_CTRUNC) ? 1 : 0);
    goto err;
  }
  /* Expect exactly 1 SOL_SOCKET/SCM_RIGHTS message containing exactly
     one file descriptor */
  if ((cmsg = CMSG_FIRSTHDR (&msg)) == NULL)
  {
    fprintf (stderr, "no cmsg\n");
    goto err;
  }
  if (CMSG_NXTHDR (&msg, cmsg) != NULL)
  {
    fprintf (stderr, "multiple cmsg\n");
    goto err;
  }
  if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
  {
    fprintf (stderr, "not a socket+rights cmsg\n");
    goto err;
  }
  if ((char *) cmsg + cmsg->cmsg_len - (char *) CMSG_DATA (cmsg) < (ptrdiff_t) sizeof (int))
  {
    fprintf (stderr, "cmsg %p cmsg_len %u CMSG_DATA %p\n", cmsg, (unsigned) cmsg->cmsg_len, (char *) CMSG_DATA (cmsg));
    goto err;
  }
  memcpy (&ret, CMSG_DATA (cmsg), sizeof (int));
  return ret;
 err:
  return -1;
}

static int blwrite (int fd, const void *buf, size_t sz)
{
  /* "Block write", will write all bytes of buf even in the presence
     of signals and partial writes. */
  size_t pos = 0;
  int n;
  while ((n = write (fd, (const char *) buf + pos, sz - pos)) > 0 || (n == -1 && errno == EINTR))
  {
    if (n > 0)
    {
      pos += n;
      if (pos == sz)
        return sz;
    }
  }
  return (n <= 0) ? n : (int) pos;
}

static int blread (int fd, void *buf, size_t sz)
{
  /* Same as blwrite(), really */
  size_t pos = 0;
  int n;
  while ((n = read (fd, (char *) buf + pos, sz - pos)) > 0 || (n == -1 && errno == EINTR))
  {
    if (n > 0)
    {
      pos += n;
      if (pos == sz)
        return sz;
    }
  }
  return (n <= 0) ? n : (int) pos;
}

static void *backtrace_server (void *arg __attribute__ ((unused)))
{
  struct backtrace_request req;
  pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
  while (blread (sock_fd, &req, sizeof (req)) == sizeof (req))
  {
    char **strs;
    int i;
    pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL);
    strs = backtrace_symbols (req.stack, req.depth);
    for (i = 0; i < req.depth; i++)
      blwrite (sock_fd, strs[i], strlen (strs[i]) + 1);
    free (strs);
    pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
  }
  pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL);
  return 0;
}

static int connect_to_server_and_map_lkadmin (void)
{
  struct sockaddr_un address;
  int lkadmin_fd = -1;
  address.sun_family = AF_UNIX;
  strcpy (address.sun_path, LKST_SOCKET_NAME);
  if ((sock_fd = socket (PF_LOCAL, SOCK_STREAM, 0)) == -1)
  {
    perror ("socket");
    return -1;
  }
  fcntl (sock_fd, F_SETFD, FD_CLOEXEC);
  if (connect (sock_fd, (struct sockaddr *) &address, sizeof (address)) == -1)
  {
    if (errno != ENOENT && errno != ECONNREFUSED)
      perror ("connect");
    goto err;
  }
  if ((lkadmin_fd = do_maprequest (sock_fd, &map_info)) == -1)
    goto err;
  if ((lkadmin = mmap (NULL, map_info.len, PROT_READ | PROT_WRITE, MAP_SHARED, lkadmin_fd, 0)) == (void *) -1)
  {
    perror ("mmap");
    goto err;
  }
  /* The memory mapped region stays around even if we close the file
     descriptor, so close it immediately. */
  close (lkadmin_fd);
  return 0;
 err:
  if (lkadmin_fd >= 0)
    close (lkadmin_fd);
  close (sock_fd);
  return -1;
}

int lkst_init_internal (int strip_count, struct lkadmin *lkadmin_in)
{
  if (offsetof (struct lktrace_head, stack) + offsetof (struct messy, head) < MAX_STACK_STRIP_COUNT * (int) sizeof (void *))
  {
    fprintf (stderr, "offset of lktrace_head::stack in messy too small\n");
    abort ();
  }

  if (strip_count < 0 || strip_count > 1)
  {
    fprintf (stderr, "caller may not request stripping %d levels off the stack traces\n", strip_count);
    abort ();
  }

  selfpid = getpid ();
#if __APPLE__
  stack_strip_count = strip_count + 1;
#elif __linux__
  stack_strip_count = strip_count + 2;
#else
  stack_strip_count = strip_count;
#endif
  assert (stack_strip_count >= 0 && stack_strip_count <= MAX_STACK_STRIP_COUNT);

  if (lkadmin_in)
  {
    am_server = 1;
    lkadmin = lkadmin_in;
    enabled = 1;
  }
  else if (connect_to_server_and_map_lkadmin () == 0)
  {
    sigset_t all, old;
    am_server = 0;
    enabled = 1;
    sigfillset (&all);
    sigdelset (&all, SIGPROF);
    pthread_sigmask (SIG_BLOCK, &all, &old);
    pthread_create (&backtrace_tid, NULL, backtrace_server, NULL);
    pthread_sigmask (SIG_SETMASK, &old, NULL);
  }
  else
  {
    //fprintf (stderr, "lkst: disabled\n");
    enabled = 0;
    lkadmin = NULL;
  }
  if (enabled)
  {
    lkinfo_hash_size = lkadmin->lkinfo_hash_size;
    lktrace_hash_size = lkadmin->lktrace_hash_size;
    lkinfo_hash = (unsigned *) ((char *) lkadmin + lkadmin->lkinfo_hash_offset);
    lktrace_hash = (unsigned *) ((char *) lkadmin + lkadmin->lktrace_hash_offset);
    if (lkadmin->random_delay)
      enabled = 2;
  }
  return enabled;
}

int lkst_init (int strip_count)
{
  return lkst_init_internal (strip_count, NULL);
}

void lkst_fini (void)
{
  if (enabled)
  {
    if (!am_server)
    {
      munmap (lkadmin, map_info.len);
      close (sock_fd);
      pthread_cancel (backtrace_tid);
      pthread_join (backtrace_tid, NULL);
    }
  }
}

#ifndef __APPLE__ /* should prob. be ! bsd, but it'll do for now */
static int fls (int x)
{
  /* fls() on BSD/MacOS is int -> int (following the pattern set by
     ffs()), but the nature of the beast is such that unsigned -> int
     is more practical. A decent compiler will optimise this away.

     tab: 0000 0001 001x(*2) 01xy(*4) 1xyz(*8), so: 0 1 2(*2) 3(*4) 4(*8)
  */
  static const int tab[16] = { 0,  1,  2, 2,  3, 3, 3, 3,  4, 4, 4, 4, 4, 4, 4, 4 };
  unsigned xu = (unsigned) x;
  int p;
  if (xu & 0xffff0000) { p = 16; xu >>= 16; } else { p = 0; }
  if (xu & 0xff00) { p += 8; xu >>= 8; }
  if (xu & 0xf0) { p += 4; xu >>= 4; }
  assert (xu < sizeof (tab) / sizeof (*tab));
  return p + tab[xu];
}
#endif

static int bindelta (uint64_t d)
{
  if (d == 0)
    return 0;
  else if (d == (uint32_t) d)
    return fls ((int) d);
  else
    return 32 + fls ((int) (d >> 32));
}

static int drop_backtrace_junk_at_end (void *stack[], int depth)
{
  /* Mac OS X tends to have 0x1's at the bottom of the stack in 64 bit
     mode ... Assume anything below 4KB to be junk */
  while (depth > 0 && (uintptr_t) stack[depth-1] < 0x1000)
    depth--;
  return depth;
}

static char *ptr_from_off (unsigned off)
{
  return ((char *) lkadmin + off);
}

static unsigned ptr_to_off (const char *ptr)
{
  return ptr - (const char *) lkadmin;
}

static struct lkinfo *lkinfo_from_off (unsigned off)
{
  assert (OFFTAG (off) == OFFTAG_LKINFO);
  return (struct lkinfo *) ptr_from_off (OFFTAG_STRIP (off));
}

static struct lktrace *lktrace_from_off (unsigned off)
{
  assert (OFFTAG (off) == OFFTAG_LKTRACE);
  return (struct lktrace *) ptr_from_off (OFFTAG_STRIP (off));
}

static unsigned lkinfo_to_off (const struct lkinfo *lkinfo)
{
  return OFFTAG_ADD (ptr_to_off ((const char *) lkinfo), OFFTAG_LKINFO);
}

static unsigned lktrace_to_off (const struct lktrace *lktrace)
{
  return OFFTAG_ADD (ptr_to_off ((const char *) lktrace), OFFTAG_LKTRACE);
}

static void *claim_memory (int sz)
{
  /* Note: contents of returned memory is always zero: we mmap zeros
     and never reuse memory. */
  unsigned offset, new_next_offset;
  do {
    offset = lkadmin->next_offset;
    new_next_offset = offset + sz;
  } while (!cas_u (offset, new_next_offset, &lkadmin->next_offset));
  if (new_next_offset >= (unsigned) map_info.len)
  {
    fprintf (stderr, "lkst: out of memory\n");
    abort ();
  }
  return (void *) ptr_from_off (offset);
}

static void lkinfo_hashchain_add (unsigned *bin, struct lkinfo *lki)
{
  unsigned oldhead, newhead = lkinfo_to_off (lki);
  do {
    oldhead = *bin;
    lki->next_offset = oldhead;
  } while (!cas_u (oldhead, newhead, bin));
}

static void lktrace_hashchain_add (unsigned *bin, struct lktrace *lkt)
{
  unsigned oldhead, newhead = lktrace_to_off (lkt);
  do {
    oldhead = *bin;
    lkt->head.next_offset = oldhead;
  } while (!cas_u (oldhead, newhead, bin));
}

static unsigned hash_lockid (uintptr_t id)
{
  /* Stolen from the web, don't know how well it works :) Fixed-up for
     64-bit pointers by dropping the most significant 32 bits.

     2654435761 is the golden ratio of 2^32. The right shift of 3 bits
     assumes that all objects are aligned on the 8 byte boundary. If a
     system aligns on the 4 byte boundary, then a right shift of 2
     bits should be done. */
  unsigned key = (unsigned) (id >> 3);
  return (key * 2654435761u) % lkinfo_hash_size;
}

static unsigned hash_lktrace (const struct lktrace_head *head)
{
  extern unsigned hashword (const unsigned *k, size_t length, unsigned initval);
  const int nb = LKTRACE_HEAD_SIGLENGTH (head);
  assert ((((uintptr_t) LKTRACE_HEAD_SIGPTR (head)) % sizeof (unsigned)) == 0);
  assert ((nb % sizeof (unsigned)) == 0);
  return hashword ((unsigned *) LKTRACE_HEAD_SIGPTR (head), nb / sizeof (unsigned), 0x2b04612b) % lktrace_hash_size;
}

static int lktrace_head_eq (const struct lktrace_head *a, const struct lktrace_head *b)
{
  return memcmp (LKTRACE_HEAD_SIGPTR (a), LKTRACE_HEAD_SIGPTR (b), LKTRACE_HEAD_SIGLENGTH (b)) == 0;
}

static struct lktrace *lktrace_get (const struct lktrace_head *head, struct lkinfo *lki, enum lkst_op op)
{
  unsigned *bin = &lktrace_hash[hash_lktrace (head)];
  unsigned off = *bin;
  struct lktrace *lkt;
  while (off)
  {
    lkt = lktrace_from_off (off);
    if (lktrace_head_eq (&lkt->head, head))
      return lkt;
    off = lkt->head.next_offset;
  }
  lkt = claim_memory (sizeof (*lkt));
  memcpy (&lkt->head, head, sizeof (lkt->head));
  lkt->op = op;
  lkt->samelock_next_offset = lki->traces_offset;
  lki->traces_offset = lktrace_to_off (lkt);
  lktrace_hashchain_add (bin, lkt);
  return lkt;
}

struct lkinfo *lkst_lkinfo_lookup (uintptr_t id, pid_t pid)
{
  unsigned off = lkinfo_hash[hash_lockid (id)];
  while (off)
  {
    struct lkinfo *lki = lkinfo_from_off (off);
    if (lki->id == id && ((lki->flags & LKI_SHARED) || lki->pid == pid))
      return lki;
    off = lki->next_offset;
  }
  return NULL;
}

struct lkinfo *lkst_lkinfo_lookup_full (lkst_full_lockid_t fid)
{
  if (fid.generation == 0)
    return lkst_lkinfo_lookup (fid.id, fid.pid);
  else
  {
    unsigned off = lkinfo_hash[hash_lockid (fid.id)];
    while (off)
    {
      struct lkinfo *lki = lkinfo_from_off (off);
      if (lki->id == fid.id &&
          lki->generation == fid.generation &&
          ((lki->flags & LKI_SHARED) || lki->pid == fid.pid))
        return lki;
      off = lki->next_offset;
    }
    return NULL;
  }
}

static struct lkinfo *lkinfo_new (uintptr_t id, unsigned flags)
{
  unsigned *bin = &lkinfo_hash[hash_lockid (id)];
  unsigned generation;
  struct lkinfo *lki;
  if ((lki = lkst_lkinfo_lookup (id, selfpid)) == NULL)
    generation = 1;
  else
  {
    generation = lki->generation + 1;
    if (generation == 0)
    {
      fprintf (stderr, "lkst: generation limit hit\n");
      abort ();
    }
    if (!(lki->flags & LKI_DEAD))
    {
      fprintf (stderr, "lkst_track_init: lock %ld:%"PRIxPTR"-%u %s already exists\n", (long) selfpid, id, lki->generation, (lki->flags & LKI_SHARED) ? "[sh] " : "");
      lkst_setclear_lkinfo_flag (lki, LKI_DEAD, 0);
    }
  }
  lki = claim_memory (sizeof (*lki));
  lki->id = id;
  lki->generation = generation;
  lki->pid = selfpid;
  lki->flags = flags;
  lkinfo_hashchain_add (bin, lki);
  return lki;
}

void lkst_track_init (lkst_lockid_t id, unsigned flags)
{
  if (flags & ~(LKST_MF_SHARED))
    abort ();
  if (enabled)
  {
    void *stack[MAX_STACK_DEPTH + MAX_STACK_STRIP_COUNT];
    int depth = backtrace (stack, MAX_STACK_DEPTH + stack_strip_count);
    unsigned xflags = lkadmin->init_lock_flags;
    struct lkinfo *lki;
    if (flags & LKST_MF_SHARED)
      xflags |= LKI_SHARED;
    depth = drop_backtrace_junk_at_end (stack, depth);
    depth = (depth < stack_strip_count) ? 0 : (depth - stack_strip_count);
    lki = lkinfo_new ((uintptr_t) id, xflags);
    lki->init_stack_depth = depth;
    memcpy (lki->init_stack, stack + stack_strip_count, depth * sizeof (lki->init_stack[0]));
  }
}

static void warn_lock_op (const char *opstr, const lkst_lockid_t id, const char *problem)
{
  fprintf (stderr, "%s: lock %ld:%"PRIxPTR" %s\n", opstr, (long) selfpid, (uintptr_t) id, problem);
#if 1
  {
    void *callstack[128];
    int i, frames = backtrace (callstack, (int) (sizeof (callstack) / sizeof (*callstack)));
    char **strs = backtrace_symbols (callstack, frames);
    for (i = 0; i < frames; ++i) {
      fprintf (stderr, "%s\n", strs[i]);
    }
    free(strs);
  }
#endif
}

static void warn_lock_unknown (const char *opstr, const lkst_lockid_t id)
{
  warn_lock_op (opstr, id, "unknown");
}

static void warn_lock_locked (const char *opstr, const lkst_lockid_t id)
{
  warn_lock_op (opstr, id, "locked");
}

void lkst_track_destroy (const lkst_lockid_t id)
{
  if (enabled)
  {
    struct lkinfo *lki;
    if ((lki = lkst_lkinfo_lookup ((uintptr_t) id, selfpid)) == NULL)
      warn_lock_unknown ("lkst_track_destroy", id);
    else if (lki->flags & LKI_DEAD)
      fprintf (stderr, "lkst_track_destroy: lock %ld:%"PRIxPTR"-%u already dead\n", (long) selfpid, (uintptr_t) id, lki->generation);
    else
    {
      if (lki->locked_at)
        warn_lock_locked ("lkst_track_destroy", id);
      lkst_setclear_lkinfo_flag (lki, LKI_DEAD, 0);
    }
  }
}

void lkst_setclear_lkinfo_flag (struct lkinfo *lki, unsigned set, unsigned clear)
{
  unsigned old, new;
  do {
    old = lki->flags;
    new = (old & ~clear) | set;
  } while (!cas_u (old, new, &lki->flags));
}

void lkst_track_op (const lkst_lockid_t id, enum lkst_op op, lkst_monotime_t t, lkst_monotime_t dt)
{
  struct lkinfo *lki = lkst_lkinfo_lookup ((uintptr_t) id, selfpid);
  struct lktrace *lkt = NULL;
  unsigned flags;
  if (lki == NULL)
  {
    warn_lock_unknown ("lkst_track_op", id);
    return;
  }

  flags = lki->flags;
  if (flags & LKI_DEAD)
  {
    fprintf (stderr, "lkst_track_op: lock %ld:%"PRIxPTR"-%u: already dead\n", (long) selfpid, (uintptr_t) id, lki->generation);
    return;
  }

  if (flags & LKI_TRACE)
  {
    struct messy m;
    int depth, bin;
    depth = backtrace (&m.head.stack[-stack_strip_count], MAX_STACK_DEPTH + stack_strip_count);
    depth = drop_backtrace_junk_at_end (&m.head.stack[-stack_strip_count], depth);
    m.head.lki_offset = lkinfo_to_off (lki);
    m.head.pid = selfpid;
    m.head.stack_depth = (depth < stack_strip_count) ? 0 : (depth - stack_strip_count);
    lkt = lktrace_get (&m.head, lki, op);
    if (op == LKST_UNLOCK)
      dt = t - lki->locked_at;
    lkt->total_time += dt;
    bin = bindelta (dt);
    lkt->hist[bin]++;
  }
  switch (op)
  {
    case LKST_LOCK:
      lki->locked_at = t;
      lki->locked_by_offset = lkt ? lktrace_to_off (lkt) : 1;
      if (dt == 0)
        lki->uncontended_count++;
      else
        lki->contended_count++;
      break;
    case LKST_UNLOCK:
      /* Atomically set "trace" if "request trace" is set. Atomically
         so we can safely add more flags that get changed
         concurrently. The "request trace" flag exists to guarantee we
         only enable tracing at unlock. */
      lki->locked_at = 0;
      lki->locked_by_offset = 0;
      if (flags & LKI_REQUEST_TRACE)
        lkst_setclear_lkinfo_flag (lki, LKI_TRACE, LKI_REQUEST_TRACE);
      break;
  }
}

void lkst_dump_trace (FILE *fp, const struct lkst_trace *trace, int abbrev, lkst_prstack_fun_t prstack, void *prstack_arg)
{
  const struct lktrace *lkt = trace->info;
  int is_current;
  int l, minbin = (int) (sizeof (lkt->hist) / sizeof (*lkt->hist)) - 1, maxbin = 0;
  uint64_t n;
  is_current = (lktrace_to_off (lkt) == lkinfo_from_off (lkt->head.lki_offset)->locked_by_offset);
  n = 0;
  for (l = 0; l < (int) (sizeof (lkt->hist) / sizeof (*lkt->hist)); l++)
  {
    n += lkt->hist[l];
    if (lkt->hist[l] && l < minbin)
      minbin = l;
    if (lkt->hist[l] && l > maxbin)
      maxbin = l;
  }
  if (lkt->op == LKST_LOCK)
    fprintf (fp, " %clock[%x] c %"PRIu64" uc %lu t %"PRIuMONOTIME" pid %ld st", is_current ? '*' : ' ', lktrace_to_off (lkt), n - lkt->hist[0], lkt->hist[0], lkt->total_time, (long) lkt->head.pid);
  else
    fprintf (fp, "  unlock[%x] n %"PRIu64" t %"PRIuMONOTIME" pid %ld st", lktrace_to_off (lkt), n, lkt->total_time, (long) lkt->head.pid);
  for (l = 0; l < lkt->head.stack_depth; l++)
    fprintf (fp, " %p", lkt->head.stack[l]);
  fprintf (fp, "\n");

  if (!abbrev)
  {
    if (maxbin > minbin)
    {
      for (l = minbin; l <= maxbin; l++)
      {
        static const char ats[] = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
        double pct = 100.0 * (double) lkt->hist[l] / n;
        int nats = (int) ((pct / 100.0) * (sizeof (ats) - 1));
        if (lkt->op == LKST_LOCK && l == 0)
          printf ("  | UN: %6.2f%% %*.*s\n", pct, nats, nats, ats);
        else
          printf ("  | %2d: %6.2f%% %*.*s\n", l, pct, nats, nats, ats);
      }
    }
    if (prstack)
      prstack (fp, lkt->head.pid, lkt->head.stack, lkt->head.stack_depth, prstack_arg);
  }
}

int lkst_dump_lock (FILE *fp, lkst_full_lockid_t lockid, unsigned format, lkst_prstack_fun_t prstack, void *prstack_arg)
{
  const struct lkinfo *lki;
  if (!enabled)
    return 0;
  lki = lkst_lkinfo_lookup_full (lockid);
  if (lki == NULL)
  {
    fprintf (fp, "lock %ld:%"PRIxPTR"-%u unknown\n", (long) lockid.pid, lockid.id, lockid.generation);
    return 0;
  }
  else
  {
    static const char *flagstrtab[] = {"X", "tr", "Rtr", "sh", "dead" };
    char flagstr[128];
    unsigned flags = lki->flags;
    char state_info[128];
    unsigned lboff;
    int i;
    flagstr[0] = 0;
    i = 0;
    while (flags && i < (int) sizeof (flagstr)) {
      int idx = ffs (flags), n;
      flags ^= 1 << (idx-1);
      if (idx < (int) (sizeof (flagstrtab) / sizeof (*flagstrtab)))
        n = snprintf (flagstr + i, sizeof (flagstr) - i, "%s,", flagstrtab[idx]);
      else
        n = snprintf (flagstr + i, sizeof (flagstr) - i, "%d,", idx-1);
      if (n > 0)
        i += n;
    }
    if (i > 0)
      flagstr[i-1] = 0;
    lboff = lki->locked_by_offset;
    if (lboff == 0)
      strcpy (state_info, "");
    else if (lboff == 1)
      snprintf (state_info, sizeof (state_info), " lock @%"PRIuMONOTIME, lki->locked_at);
    else
      snprintf (state_info, sizeof (state_info), " lock[%x] @%"PRIuMONOTIME, lboff, lki->locked_at);
    fprintf (fp, "LOCK %ld:%"PRIxPTR"-%u%s [%s] c %lu uc %lu st", (long) lki->pid, lki->id, lki->generation, state_info, flagstr, lki->contended_count, lki->uncontended_count);
    for (i = 0; i < lki->init_stack_depth; i++)
      fprintf (fp, " %p", lki->init_stack[i]);
    fprintf (fp, "\n");
    if (format != LKST_DF_SHORT)
    {
      if ((format & LKST_DF_INITSTACK) && prstack)
        prstack (fp, lki->pid, lki->init_stack, lki->init_stack_depth, prstack_arg);
      if ((format & LKST_DF_LOCKSTACK) && lboff > 1)
      {
        struct lkst_trace lt;
        lt.op = LKST_LOCK;
        lt.info = lktrace_from_off (lboff);
        lkst_dump_trace (fp, &lt, 0, prstack, prstack_arg);
      }
    }
    return 1;
  }
}

void lkst_dump_all_locks (FILE *fp, unsigned format, int justlocked, lkst_prstack_fun_t prstack, void *prstack_arg)
{
  int i, n = 0;
  for (i = 0; i < lkinfo_hash_size; i++)
  {
    unsigned off = lkinfo_hash[i];
    while (off)
    {
      const struct lkinfo *lki = lkinfo_from_off (off);
      lkst_full_lockid_t lockid;
      if (!justlocked || lki->locked_by_offset)
      {
        lockid.pid = lki->pid;
        lockid.generation = lki->generation;
        lockid.id = lki->id;
        lkst_dump_lock (fp, lockid, format, prstack, prstack_arg);
      }
      off = lki->next_offset;
      n++;
    }
  }
  fprintf (fp, "[%d locks]\n", n);
}

struct hot_heap_entry {
  const struct lkinfo *lki;
  uint64_t val;
};

struct hottrace_heap_entry {
  const struct lktrace *lkt;
  uint64_t val;
};

struct heap {
  int n;
  int max;
  int elemsz;
  char *heap;
  int (*cmp) (const void *a, const void *b);
};

static void heap_init (struct heap *h, int max, int elemsz, int (*cmp) (const void *a, const void *b))
{
  h->n = 0;
  h->max = max;
  h->elemsz = elemsz;
  /* allocate 1 extra as temp for swapping */
  h->heap = malloc ((max + 1) * elemsz);
  h->cmp = cmp;
}

static void heap_fini (struct heap *h)
{
  free (h->heap);
}

static void heap_heapify (struct heap *h, int j)
{
  int k;
  for (k = 2 * j + 1; k < h->n; j = k, k += k + 1)
  {
    if (k+1 < h->n && h->cmp (h->heap + h->elemsz * k, h->heap + h->elemsz * (k+1)) > 0)
      k++;
    if (h->cmp (h->heap + h->elemsz * j, h->heap + h->elemsz * k) > 0)
    {
      char *tmp = h->heap + h->elemsz * h->max;
      memcpy (tmp, h->heap + h->elemsz * j, h->elemsz);
      memcpy (h->heap + h->elemsz * j, h->heap + h->elemsz * k, h->elemsz);
      memcpy (h->heap + h->elemsz * k, tmp, h->elemsz);
    }
  }
}

static int heap_extract_min (struct heap *h, void *dst)
{
  if (!(h->n > 0))
    return -1;
  memcpy (dst, h->heap, h->elemsz);
  h->n--;
  if (h->n > 0)
  {
    memcpy (h->heap, h->heap + h->elemsz * h->n, h->elemsz);
    heap_heapify (h, 0);
  }
  return 0;
}

static int heap_insert (struct heap *h, const void *e)
{
  int i;
  if (!(h->n < h->max))
    return -1;
  i = h->n;
  h->n++;
  while (i > 0 && h->cmp (h->heap + h->elemsz * ((i-1)/2), e) > 0)
  {
    memcpy (h->heap + h->elemsz * i, h->heap + h->elemsz * ((i-1)/2), h->elemsz);
    i = (i-1)/2;
  }
  memcpy (h->heap + h->elemsz * i, e, h->elemsz);
  return 0;
}

static void heap_increased_key (struct heap *h, int i)
{
  heap_heapify (h, i);
}

static int heap_size (struct heap *h)
{
  return h->n;
}

static int cmp_hottrace_heap_entry (const void *va, const void *vb)
{
  const struct hottrace_heap_entry *a = va;
  const struct hottrace_heap_entry *b = vb;
  return (a->val == b->val) ? 0 : (a->val < b->val) ? -1 : 1;
}

static int cmp_hot_heap_entry (const void *va, const void *vb)
{
  const struct hot_heap_entry *a = va;
  const struct hot_heap_entry *b = vb;
  return (a->val == b->val) ? 0 : (a->val < b->val) ? -1 : 1;
}

static void hh_fill_entry (struct hot_heap_entry *k, const struct lkinfo *lki)
{
  k->lki = lki;
  k->val = lki->contended_count;
}

static void hth_fill_entry (struct hottrace_heap_entry *k, const struct lktrace *lkt)
{
  k->lkt = lkt;
  switch (lkt->op)
  {
    case LKST_LOCK:
      /* Contended count (uncontended has dt = 0, so bin 0 is
         uncontended count and the sum of all other bins is contended
         count) */
      {
        uint64_t n = 0;
        int i;
        for (i = 1; i < (int) (sizeof (lkt->hist) / sizeof (*lkt->hist)); i++)
          n += lkt->hist[i];
        k->val = n;
      }
      break;
    case LKST_UNLOCK:
      /* Average lock time (which need not be precise, but we don't care :) */
      {
        uint64_t n = 0;
        int i;
        for (i = 0; i < (int) (sizeof (lkt->hist) / sizeof (*lkt->hist)); i++)
          n += lkt->hist[i];
        k->val = n ? (lkt->total_time / n) : 0;
      }
      break;
  }
}

int lkst_hottest_traces_of_lock (lkst_trace_t traces[], int max, int resv_unlock, lkst_full_lockid_t lockid)
{
  struct heap heap_lock, heap_unlock;
  int i, nfound_lock, nfound_unlock, nfound;
  unsigned lkt_offset;
  const struct lkinfo *lki;
  if (!enabled)
    return 0;
  lki = lkst_lkinfo_lookup_full (lockid);
  if (lki == NULL)
    return -1;
  heap_init (&heap_lock, max, sizeof (struct hottrace_heap_entry), cmp_hottrace_heap_entry);
  heap_init (&heap_unlock, max, sizeof (struct hottrace_heap_entry), cmp_hottrace_heap_entry);
  lkt_offset = lki->traces_offset;
  while (lkt_offset)
  {
    const struct lktrace *lkt = lktrace_from_off (lkt_offset);
    struct hottrace_heap_entry k;
    struct heap *h = NULL;
    lkt_offset = lkt->samelock_next_offset;
    hth_fill_entry (&k, lkt);
    switch (lkt->op)
    {
      case LKST_LOCK: h = &heap_lock; break;
      case LKST_UNLOCK: h = &heap_unlock; break;
    }
    if (heap_insert (h, &k) != 0 && h->cmp (&k, h->heap) > 0)
    {
      memcpy (h->heap, &k, h->elemsz);
      heap_increased_key (h, 0);
    }
  }
  /* Extract traces from heaps:
     - #L + #U <= max          => both in their entirety
     - #U <= resv_unlock       => all U's
     - #L <= max - resv_unlock => as many U's as fit
     - otherwise               => resv_unlock U's
  */
  nfound_lock = heap_size (&heap_lock);
  nfound_unlock = heap_size (&heap_unlock);
  //printf ("NFOUND %d NFOUND_UNLOCK %d\n", nfound_lock, nfound_unlock);
  assert (nfound_lock <= max);
  for (i = nfound_lock - 1; i >= 0; i--)
  {
    struct hottrace_heap_entry e;
    heap_extract_min (&heap_lock, &e);
    traces[i].op = e.lkt->op;
    traces[i].info = e.lkt;
  }
  if (nfound_lock + nfound_unlock <= max)
    nfound = nfound_lock + nfound_unlock;
  else if (nfound_unlock <= resv_unlock)
    nfound = max;
  else if (nfound_lock <= max - resv_unlock)
  {
    nfound = max;
    assert (max - nfound_lock <= nfound_unlock);
    nfound_unlock = max - nfound_lock;
  }
  else
  {
    nfound = max;
    nfound_unlock = resv_unlock;
  }
  assert (nfound <= max);
  assert (nfound - nfound_unlock >= 0);
  for (i = nfound - 1; i >= nfound - nfound_unlock; i--)
  {
    struct hottrace_heap_entry e;
    heap_extract_min (&heap_unlock, &e);
    traces[i].op = e.lkt->op;
    traces[i].info = e.lkt;
  }
  heap_fini (&heap_unlock);
  heap_fini (&heap_lock);
  return nfound;
}

int lkst_hottest_locks (lkst_full_lockid_t locks[], int max)
{
  /* Returning the MAX locks with the highest contention counts. Ties
     are broken arbitrarily.

     Builds a heap of at most MAX locks with the root the smallest in
     the specified ordering. Scans the locks, ignoring those with that
     are smaller than the root of the heap. For those that are greater
     than the root, the root is replaced by the new entry (increasing
     the value at the root) and the heap conditions is restored. */
  struct heap heap;
  int i, nfound;
  if (!enabled)
    return 0;
  heap_init (&heap, max, sizeof (struct hot_heap_entry), cmp_hot_heap_entry);
  for (i = 0; i < lkinfo_hash_size; i++)
  {
    unsigned off = lkinfo_hash[i];
    while (off)
    {
      const struct lkinfo *lki = lkinfo_from_off (off);
      struct hot_heap_entry k;
      hh_fill_entry (&k, lki);
      if (heap_insert (&heap, &k) != 0 && heap.cmp (&k, heap.heap) > 0)
      {
        memcpy (heap.heap, &k, heap.elemsz);
        heap_increased_key (&heap, 0);
      }
      off = lki->next_offset;
    }
  }
  nfound = heap_size (&heap);
  for (i = nfound - 1; i >= 0; i--)
  {
    struct hot_heap_entry e;
    heap_extract_min (&heap, &e);
    locks[i].pid = e.lki->pid;
    locks[i].generation = e.lki->generation;
    locks[i].id = e.lki->id;
  }
  heap_fini (&heap);
  return nfound;
}
