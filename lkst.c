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
#if __APPLE__
#define _DARWIN_FEATURE_64_BIT_INODE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <poll.h>
#include <execinfo.h>
#include <inttypes.h>

#include "lkst.h"
#include "lkst_impl.h"

#if __APPLE__
#include "mach/mach_time.h"
#endif

#define LOCKFILE_NAME "/tmp/lkst-lock"

#define MAX_CLIENTS 126

void backtrace_by_pid (FILE *fp, pid_t pid, const void *stack, int depth, void *arg);

sig_atomic_t terminate = 0;
int nclients = 0;
struct pollfd pollfds[2 + MAX_CLIENTS];
pid_t clientpids[2 + MAX_CLIENTS]; /* corresponds to pollfds */

pid_t serve_maprequest (int sock, struct map_info *data, int mapfd)
{
  struct msghdr rmsg, msg;
  pid_t pid;
  struct iovec iov[1];
  struct {
    struct cmsghdr hdr;
    int fd;
  } cmsg;
  ssize_t rr;
  /* Read the pid of the client */
  rmsg.msg_name = NULL;
  rmsg.msg_namelen = 0;
  iov[0].iov_base = &pid;
  iov[0].iov_len = sizeof (pid);
  rmsg.msg_iov = iov;
  rmsg.msg_iovlen = 1;
  rmsg.msg_control = NULL;
  rmsg.msg_controllen = 0;
  if (recvmsg (sock, &rmsg, 0) != (int) iov[0].iov_len)
  {
    perror ("recvmsg: incorrect message size or error\n");
    return -1;
  }
  if (rmsg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
  {
    fprintf (stderr, "flags %d %d: truncated message\n", (rmsg.msg_flags & MSG_TRUNC) ? 1 : 0, (rmsg.msg_flags & MSG_CTRUNC) ? 1 : 0);
    return -1;
  }
  /* Construct the reply */
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  iov[0].iov_base = data;
  iov[0].iov_len = sizeof (*data);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  cmsg.hdr.cmsg_len = sizeof (cmsg);
  cmsg.hdr.cmsg_level = SOL_SOCKET;
  cmsg.hdr.cmsg_type = SCM_RIGHTS;
  cmsg.fd = mapfd;
  msg.msg_control = &cmsg;
  msg.msg_controllen = sizeof (cmsg);
  msg.msg_flags = 0;
  if (sendmsg (sock, &msg, 0) != (int) iov[0].iov_len)
  {
    perror ("send failed");
    return -1;
  }
  return pid;
}

void sigh (int sig __attribute__ ((unused)))
{
  terminate = 1;
}

void print_hottest_locks (void)
{
  lkst_full_lockid_t hot[20];
  int nhot;
  nhot = lkst_hottest_locks (hot, (int) (sizeof (hot) / sizeof (*hot)));
  if (nhot)
  {
    int i;
    for (i = 0; i < nhot; i++)
      lkst_dump_lock (stdout, hot[i], LKST_DF_LOCKSTACK, backtrace_by_pid, 0);
  }
  else
  {
    printf ("[no locks known]\n");
  }
}

char *rdstring (int fd)
{
  static char buf[128];
  static int pos = 0;
  char *str = NULL;
  int n = 0, slen = 0;
  do {
    if (n >= 0)
    {
      char *nul;
      pos += n;
      nul = memchr (buf, 0, pos);
      if (nul)
      {
        nul++;
        str = realloc (str, slen + (nul - buf));
        memcpy (str + slen, buf, (nul - buf));
        memmove (buf, nul, buf + pos - nul);
        pos = buf + pos - nul;
        return str;
      }
      else if (pos == sizeof (buf))
      {
        str = realloc (str, slen + pos);
        memcpy (str + slen, buf, pos);
        slen += pos;
        pos = 0;
      }
    }
  } while ((n = read (fd, buf + pos, sizeof (buf) - pos)) > 0 || (n == -1 && errno == EINTR));
  if (n <= 0)
  {
    if (str) free (str);
  }
  return NULL;
}

void backtrace_by_pid (FILE *fp, pid_t pid, const void *stack, int depth, void *arg __attribute__ ((unused)))
{
  union {
    struct backtrace_request req;
    char buf[sizeof (struct backtrace_request)];
  } x;
  int i, n, pos = 0, fd = -1;
  for (i = 2; i < 2 + nclients; i++)
  {
    if (clientpids[i] == pid)
      fd = pollfds[i].fd;
  }
  if (fd == -1)
  {
    printf ("[pid %ld not available for stack traces]\n", (long) pid);
    return;
  }
  //printf ("pid %ld => sock %d\n", (long) pid, fd);
  assert (depth <= MAX_STACK_DEPTH);
  x.req.depth = depth;
  memcpy (x.req.stack, stack, depth * sizeof (*x.req.stack));
  while ((n = write (fd, x.buf + pos, sizeof (x.req) - pos)) > 0 || (n == -1 && errno == EINTR))
  {
    if (n > 0)
    {
      pos += n;
      if (pos == sizeof (x.req))
        break;
    }
  }
  for (i = 0; i < x.req.depth; i++)
  {
    char *str = rdstring (fd);
    if (str == NULL)
      break;
    fprintf (fp, "  | %s\n", str);
    free (str);
  }
}

void usagenotes (void)
{
  printf ("\
* tracking clients connecting to %s\n\
* state is reset on transition from 0 to 1 client\n\
* symbolic stack traces depend on service thread in client, beware of stopped clients\n\
* stack traces have at most %d levels, unavoidable stuff at the top removed\n\
* \"traced\" locks: individual lock/unlock operations disambiguated by stack trace\n\
* a lock is printed as: LOCK P:A-G L [flags] c C uc UC st S\n\
  where P      process id of lock creator\n\
        A      lock address (uniquely determines shared locks, but not private ones)\n\
        G      generation, incremented for each new lock at the same address\n\
        L      if currently locked: lock[Z] @T ([Z] only if tracing)\n\
        flags  tr: tracing, Rtr: tracing requested, sh: shared\n\
        C      number of contended lock attempts (lock claimed by another thread)\n\
        UC     uncontended lock attempts (lock free)\n\
        S      creation stack trace\n\
  possibly followed by a symbolic stack trace\n\
* a trace is either a LOCK or an UNLOCK line, following which a distribution of durations\n\
  and a symbolic stack trace:\n\
    |?lock[Z] c C uc UC t WT pid P st S\n\
    | unlock[Z] n N t LT pid P st S\n\
  where ? is * if currently locked here, blank otherwise, Z is a unique identifier\n\
  for the stack trace, WT is total Wait Time on lock, N is number of unlock operations\n\
  and LT is total Lock held Time.\n\
* distribution of durations: lines are formatted as:\n\
    | B: X%% @@@@\n\
  where B is the bin, X%% is the percentage of events in bin B and the @@@@ form a\n\
  rudimentary bar graph. An event is counted in bin 0 if corresponding duration is 0,\n\
  in bin B>0 if 2**(B-1) <= duration < 2**B.\n\
* for LOCK traces, bin 0 is printed as UC as it represents the number of uncontended\n\
  lock attempts, others are for contended ones and show the time spent waiting for the\n\
  lock (usually large, as it likely involves the scheduler).\n\
* for UNLOCK traces, the distribution of lock held durations is shown.\n\
* commands accepted on stdin (besides ?):\n\
  a        prints all locks\n\
  h        prints hottest 20 locks (by number of contended lock operations)\n\
  l        those currently locked\n\
  p P:A-G  print all that is known about lock P:A-G (P, G may be omitted)\n\
  q        (or ^D or ^C) quit\n\
  t P:A-G  trace lock P:A-G (sets Rtr flag, tr follows on unlock; A: bit may be omitted)\n\
  t hot    equivalent to issuing t P:A-G commands for locks printed by 'h' command\n",
          LKST_SOCKET_NAME, MAX_STACK_DEPTH);
}

int scan_full_lockid (lkst_full_lockid_t *fid, const char *arg)
{
  uintptr_t id;
  long pid;
  unsigned gen;
  int p;
  if (sscanf (arg, "%"SCNxPTR"%n", &id, &p) == 1 && arg[p] == 0)
  {
    fid->id = id;
    fid->pid = 0;
    fid->generation = 0;
    return 1;
  }
  else if (sscanf (arg, "%ld:%"SCNxPTR"%n", &pid, &id, &p) == 2 && arg[p] == 0)
  {
    fid->id = id;
    fid->pid = (pid_t) pid;
    fid->generation = 0;
    return 1;
  }
  else if (sscanf (arg, "%"SCNxPTR"-%u%n", &id, &gen, &p) == 2 && arg[p] == 0)
  {
    fid->id = id;
    fid->pid = 0;
    fid->generation = gen;
    return 1;
  }
  else if (sscanf (arg, "%ld:%"SCNxPTR"-%u%n", &pid, &id, &gen, &p) == 3 && arg[p] == 0)
  {
    fid->id = id;
    fid->pid = (pid_t) pid;
    fid->generation = gen;
    return 1;
  }
  return 0;
}

int handle_command (const char *cmd)
{
  int p;
  switch (*cmd)
  {
    case '?':
      usagenotes ();
      return 0;

    case 'a':
      {
        lkst_dump_all_locks (stdout, LKST_DF_SHORT, 0, backtrace_by_pid, 0);
        return 0;
      }

    case 'h':
      {
        print_hottest_locks ();
        return 0;
      }

    case 'l':
      {
        lkst_dump_all_locks (stdout, LKST_DF_INITSTACK | LKST_DF_LOCKSTACK, 1, backtrace_by_pid, 0);
        return 0;
      }

    case 'p':
      {
        lkst_full_lockid_t id;
        if (!scan_full_lockid (&id, cmd+1))
          goto args;
        else
        {
#define MAX_TRACES 20
#define RESVD_UNLOCK 7
          lkst_trace_t traces[MAX_TRACES];
          int i, n;
          lkst_dump_lock (stdout, id, LKST_DF_INITSTACK, backtrace_by_pid, 0);
          n = lkst_hottest_traces_of_lock (traces, MAX_TRACES, RESVD_UNLOCK, id);
          for (i = 0; i < n; i++)
            lkst_dump_trace (stdout, &traces[i], 0, backtrace_by_pid, 0);
#undef RESVD_UNLOCK
#undef MAX_TRACES
        }
        return 0;
      }

    case 'q':
      terminate = 1;
      return 0;

    case 't':
      {
        lkst_full_lockid_t id;
        char tag[11];
        if (scan_full_lockid (&id, cmd+1))
        {
          struct lkinfo *lki = lkst_lkinfo_lookup_full (id);
          if (lki)
            lkst_setclear_lkinfo_flag (lki, LKI_REQUEST_TRACE, 0);
          else
            printf ("lock %ld:%"PRIxPTR"-%u: unknown\n", (long) id.pid, id.id, id.generation);
        }
        else if (sscanf (cmd+1, "%10s%n", tag, &p) == 1 && cmd[p+1] == 0 && strcmp (tag, "hot") == 0)
        {
          lkst_full_lockid_t hot[20];
          int i, nhot;
          nhot = lkst_hottest_locks (hot, (int) (sizeof (hot) / sizeof (*hot)));
          for (i = 0; i < nhot; i++)
          {
            struct lkinfo *lki = lkst_lkinfo_lookup_full (hot[i]);
            if (lki)
            {
              printf ("t %ld:%"PRIxPTR"-%u\n", (long) hot[i].pid, hot[i].id, hot[i].generation);
              lkst_setclear_lkinfo_flag (lki, LKI_REQUEST_TRACE, 0);
            }
          }
        }
        else
        {
          goto args;
        }
        return 0;
      }

    default:
      printf ("%c: invalid command\n", *cmd);
      return -1;
  }

 args:
  printf ("%s: invalid args for %c command\n", cmd + 1+strspn (cmd+1, " "), *cmd);
  return -1;
}

int handle_stdin (void)
{
  static char buf[100];
  static int bufpos = 0;
  int n;
  if ((n = read (0, buf + bufpos, sizeof (buf) - bufpos)) == -1)
  {
    if (errno != EINTR)
    {
      perror ("read(stdin)");
      return -1;
    }
    return 0;
  }
  if (n == 0)
  {
    /* EOF */
    return -1;
  }
  assert (n > 0);
  bufpos += n;
  while (bufpos > 0)
  {
    int start, end, shift;
    for (start = 0; start < bufpos && buf[start] == ' '; start++);
    for (shift = start; shift < bufpos && buf[shift] != '\n'; shift++);
    for (end = shift-1; end >= start && buf[end] == ' '; end--);
    //printf ("start %d end %d shift %d bufpos %d\n", start, end, shift, bufpos);
    if (shift < bufpos)
    {
      end++;
      assert (end >= start && end <= shift);
      buf[end] = 0;
      if (end - start > 0)
        handle_command (buf + start);
      shift++;
      memmove (buf, buf + shift, bufpos - shift);
      bufpos -= shift;
      if (!terminate)
      {
        printf ("lkst> ");
        fflush (stdout);
      }
    }
    else if (bufpos == sizeof (buf))
    {
      printf ("input too long\n");
      fflush (stdout);
      bufpos = 0;
    }
    else
    {
      break;
    }
  }
  return 0;
}

int grab_lock_file (void)
{
  /* Fooling around a little: 'tis not so much to produce a nice error
     message on startup when attempting to start a second instance
     (although "already running" is friendlier than "address already
     in use"), but rather to automatically remove the socket if lkst
     was killed or crashed and thereby allow it to be started again
     without further ado. */
  pid_t pid = getpid ();
  uid_t uid = getuid ();
  char src[32], xsrc[32];
  int xsrclen, p;
  long xpid, xuid;
  struct stat statbuf;
  assert (sizeof (long) >= sizeof (uid_t));
  assert (sizeof (long) >= sizeof (pid_t));
  sprintf (src, "%ld:%ld", (long) uid, (long) pid);
 retry:
  if (symlink (src, LOCKFILE_NAME) == 0)
    return 0;
  if (errno != EEXIST)
  {
    perror ("symlink");
    return -1;
  }
  if (lstat (LOCKFILE_NAME, &statbuf) == -1)
  {
    if (errno == EEXIST)
      goto retry;
    perror ("lstat");
    return -1;
  }
  if ((xsrclen = readlink (LOCKFILE_NAME, xsrc, sizeof (xsrc) - 1)) == -1)
  {
    if (errno == ENOENT)
      goto retry;
    perror ("readlink");
    return -1;
  }
  xsrc[xsrclen] = 0;
  if (sscanf (xsrc, "%ld:%ld%n", &xuid, &xpid, &p) != 2 || xsrc[p] != 0 || xpid <= 0 || xuid != (long) statbuf.st_uid)
  {
    fprintf (stderr, "%s: has unexpected contents (%s)\n", LOCKFILE_NAME, xsrc);
    return -1;
  }
  if (xuid != (long) uid)
  {
    fprintf (stderr, "%s: different user\n", LOCKFILE_NAME);
    return -1;
  }
  if (kill (xpid, 0) == -1 && errno == ESRCH)
  {
    fprintf (stderr, "removing %s, %s and retrying\n", LKST_SOCKET_NAME, LOCKFILE_NAME);
    unlink (LKST_SOCKET_NAME);
    unlink (LOCKFILE_NAME);
    goto retry;
  }
  fprintf (stderr, "lkst appears to be running already\n");
  return -1;
}

int rm_lock_file (void)
{
  unlink (LOCKFILE_NAME);
  return 0;
}

int main (int argc, char **argv)
{
  char template[] = "/tmp/lkst.XXXXXX";
  struct sockaddr_un addr;
  struct map_info map_info;
  struct lkadmin *lkadmin;
  struct stat statbuf;
  const int size_default = 32;
  int size = size_default;
  int sock;
  int lkadmin_fd;
  int opt;
  int trace_all_flag = 0;
  int random_delay_flag = 0;

  while ((opt = getopt (argc, argv, "ads:")) != EOF)
  {
    switch (opt)
    {
      case 'a':
        trace_all_flag = 1;
        break;
      case 'd':
        random_delay_flag = 1;
        break;
      case 's':
        size = atoi (optarg);
        break;
      default:
        fprintf (stderr, "usage: %s [-ad] [-sSIZE]\n\
\n\
  -a       automatically enable tracing of all locks\n\
  -sSIZE   create a shared memory segment of SIZE MB (default = %d)\n",
                 argv[0], size_default);
        return 1;
    }
  }
  map_info.len = size * 1048576;
  umask (077);
  if (grab_lock_file () == -1)
    return 2;
  if ((lkadmin_fd = mkstemp (template)) == -1)
  {
    perror ("mkstemp");
    goto err_mkstemp;
  }
  if (unlink (template) == -1)
  {
    perror ("unlink");
    goto err_unlink;
  }
  if (fstat (lkadmin_fd, &statbuf) == -1)
  {
    perror ("fstat");
    goto err_fstat;
  }
  if (statbuf.st_nlink != 0)
  {
    fprintf (stderr, "Filesystem sill has links to the inode? Someone must be playing games\n");
    goto err_fstat;
  }
  if ((ftruncate (lkadmin_fd, map_info.len)) == -1)
  {
    perror ("ftruncate");
    goto err_ftruncate;
  }
  lkadmin = mmap (NULL, map_info.len, PROT_READ | PROT_WRITE, MAP_SHARED, lkadmin_fd, 0);
  if (lkadmin == (void *) -1)
  {
    perror ("mmap");
    goto err_mmap;
  }
  lkadmin->lkinfo_hash_size = 8192;
  lkadmin->lktrace_hash_size = 32768;
  lkadmin->lkinfo_hash_offset = sizeof (struct lkadmin);
  lkadmin->lktrace_hash_offset =
    lkadmin->lkinfo_hash_offset + lkadmin->lkinfo_hash_size * sizeof (struct lkinfo);
  lkadmin->next_offset =
    lkadmin->lktrace_hash_offset + lkadmin->lktrace_hash_size * sizeof (struct lktrace);
  lkadmin->init_lock_flags = trace_all_flag ? LKI_TRACE : 0;
  lkadmin->random_delay = random_delay_flag;
  lkst_init_internal (0, lkadmin);
  if ((sock = socket (PF_LOCAL, SOCK_STREAM, 0)) == -1)
  {
    perror ("socket");
    goto err_socket;
  }
  addr.sun_family = AF_UNIX;
  strcpy (addr.sun_path, LKST_SOCKET_NAME);
  if (bind (sock, (struct sockaddr *) &addr, sizeof (addr)) == -1)
  {
    perror ("bind");
    goto err_bind;
  }
  if (listen (sock, 0) == -1)
  {
    perror ("listen");
    goto err_listen;
  }
  signal (SIGINT, sigh);
  signal (SIGTERM, sigh);
  pollfds[0].fd = sock;
  pollfds[0].events = POLLIN;
  pollfds[1].fd = 0;
  pollfds[1].events = POLLIN;
  printf ("listening ... %suse ?<RET> for help\n", lkadmin->init_lock_flags ? "tracing all ... " : "");
  printf ("lkst> "); fflush (stdout);
  while (!terminate)
  {
    int res;
    if ((res = poll (pollfds, 2 + nclients, -1)) == -1)
    {
      if (errno == EINTR)
        continue;
      else
      {
        perror ("poll");
        goto err_poll;
      }
    }

    if (res > 0)
    {
      int i;

      /* Accept new clients */
      if (nclients < MAX_CLIENTS && (pollfds[0].revents & POLLIN))
      {
        struct sockaddr_un addr;
        int addrlen;
        int s;
        pid_t pid;
        if ((s = accept (sock, (struct sockaddr *) &addr, (socklen_t *) &addrlen)) == -1)
        {
          perror ("accept");
          goto err_accept;
        }
        if (nclients == 0)
        {
          printf ("zero'ing memory\n");
          memset (lkadmin + 1, 0, lkadmin->next_offset);
          lkadmin->next_offset =
            lkadmin->lktrace_hash_offset + lkadmin->lktrace_hash_size * sizeof (struct lktrace);
        }
        pollfds[2 + nclients].fd = s;
        pollfds[2 + nclients].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
        pollfds[2 + nclients].revents = 0;
        if ((pid = serve_maprequest (s, &map_info, lkadmin_fd)) > 0)
        {
          printf ("sock %d: pid %ld\n", s, (long) pid);
          clientpids[2 + nclients] = pid;
          nclients++;
          if (nclients == MAX_CLIENTS)
            pollfds[0].events &= ~POLLIN;
        }
      }

      /* Read commands from stdin; terminate if EOF on stdin */
      if (pollfds[1].revents & POLLIN)
      {
        if (handle_stdin () != 0)
          terminate = 1;
      }
      if (pollfds[1].revents & POLLHUP)
      {
        printf ("HUP on stdin\n");
        terminate = 1;
      }

      /* Only respond to errors on other fds: those indicate the process is gone */
      i = 2;
      while (i < 2 + nclients)
      {
        int killclient = 0;

        if (pollfds[i].revents & POLLIN)
        {
          char buf[1024];
          int n;
          if ((n = read (pollfds[i].fd, buf, sizeof (buf))) > 0)
            write (1, buf, n);
          killclient = (n == 0);
        }
        if (pollfds[i].revents & (POLLERR | POLLHUP | POLLNVAL))
        {
          killclient = 1;
        }

        if (!killclient)
        {
          i++;
        }
        else
        {
          printf ("sock %d: pid %ld: gone\n", pollfds[i].fd, (long) clientpids[i]);
          close (pollfds[i].fd);
          nclients--;
          if (i < 2 + nclients)
          {
            pollfds[i] = pollfds[2 + nclients];
            clientpids[i] = clientpids[2 + nclients];
          }
          if (nclients == MAX_CLIENTS - 1)
          {
            pollfds[0].events |= POLLIN;
          }
        }
      }
    }
  }
  lkst_fini ();
  unlink (LKST_SOCKET_NAME);
  close (sock);
  munmap (lkadmin, map_info.len);
  close (lkadmin_fd);
  rm_lock_file ();
  return 0;

 err_accept:
 err_poll:
 err_listen:
  unlink (LKST_SOCKET_NAME);
 err_bind:
  close (sock);
 err_socket:
  if (munmap (lkadmin, map_info.len) == -1)
    perror ("munmap");
 err_mmap:
 err_ftruncate:
 err_fstat:
 err_unlink:
  close (lkadmin_fd);
 err_mkstemp:
  rm_lock_file ();
  return 2;
}
