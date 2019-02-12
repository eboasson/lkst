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
#define _GNU_SOURCE
#include <pthread.h>
#include <dlfcn.h>

#include "lkst.h"
#include "lkst_cas.h"

/* __lkst_pw_...: LocK STatistics Pthread Wrapper */

#if 0
#define MSG(x) do { char _msg[] = x "\n"; write (2, _msg, sizeof (_msg) - 1); } while (0)
#else
#define MSG(x) do { } while (0)
#endif

static volatile int lkst_enabled;
static unsigned init_flag, init_done;

static int (*mutex_init) (pthread_mutex_t * __restrict mtx, const pthread_mutexattr_t * __restrict mtx_attr);
static int (*mutex_destroy) (pthread_mutex_t *mtx);
static int (*mutex_trylock) (pthread_mutex_t *mtx);
static int (*mutex_lock) (pthread_mutex_t *mtx);
static int (*mutex_unlock) (pthread_mutex_t *mtx);

static int (*cond_wait) (pthread_cond_t * __restrict cv, pthread_mutex_t * __restrict mtx);
static int (*cond_timedwait) (pthread_cond_t * __restrict cv, pthread_mutex_t * __restrict mtx, const struct timespec * __restrict abstime);

#if defined __APPLE__
#include <mach/mach_time.h>
static inline lkst_monotime_t monotime (void)
{
  return mach_absolute_time ();
}
#elif defined __sun
#include <sys/time.h>
static inline lkst_monotime_t monotime (void)
{
  return gethrtime ();
}
#elif defined __linux
#include <time.h>
static inline unsigned long long monotime (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (lkst_monotime_t) ts.tv_sec * 1000000000 + ts.tv_nsec;
}
#endif

__attribute__ ((constructor)) void __lkst_pw_init (void)
{
  if (cas_u (0, 1, &init_flag))
  {
    lkst_enabled = lkst_init (1);

    mutex_init = dlsym (RTLD_NEXT, "pthread_mutex_init");
    mutex_destroy = dlsym (RTLD_NEXT, "pthread_mutex_destroy");
    mutex_trylock = dlsym (RTLD_NEXT, "pthread_mutex_trylock");
    mutex_lock = dlsym (RTLD_NEXT, "pthread_mutex_lock");
    mutex_unlock = dlsym (RTLD_NEXT, "pthread_mutex_unlock");

    cond_wait = dlsym (RTLD_NEXT, "pthread_cond_wait");
    cond_timedwait = dlsym (RTLD_NEXT, "pthread_cond_timedwait");

    init_done = 1;
  }
  else
  {
    int count = 0;
    while (!init_done && count < 10000)
      usleep (1000);
    if (!init_done)
    {
      const char msg[] = "lkst: init: wait timed out\n";
      write (2, msg, sizeof (msg) - 1);
      _exit (1);
    }
  }
}

__attribute__ ((destructor)) void __lkst_pw_fini (void)
{
  if (cas_u (1, 0, &init_done))
  {
    if (lkst_enabled)
      lkst_fini ();
  }
}

int pthread_mutex_init (pthread_mutex_t * __restrict mtx, const pthread_mutexattr_t * __restrict mtx_attr)
{
  int r, shared;
  MSG ("init");
  if (!init_done)
    __lkst_pw_init ();
  if (mtx_attr == NULL)
    shared = 0;
  else if ((r = pthread_mutexattr_getpshared (mtx_attr, &shared)) != 0)
    return r;
  if ((r = (*mutex_init) (mtx, mtx_attr)) != 0)
    return r;
  if (lkst_enabled)
    lkst_track_init (mtx, shared ? LKST_MF_SHARED : 0);
  return 0;
}

int pthread_mutex_destroy (pthread_mutex_t *mtx)
{
  MSG ("destroy");
  if (!init_done)
    __lkst_pw_init ();
  if (lkst_enabled)
    lkst_track_destroy (mtx);
  return (*mutex_destroy) (mtx);
}

int pthread_mutex_trylock (pthread_mutex_t *mtx)
{
  int r;
  MSG ("trylock");
  if (!init_done)
    __lkst_pw_init ();
  r = (*mutex_trylock) (mtx);
  if (lkst_enabled && r == 0)
    lkst_track_op (mtx, LKST_LOCK, monotime (), 0);
  return r;
}

int pthread_mutex_lock (pthread_mutex_t *mtx)
{
  MSG ("lock");
  if (!init_done)
    __lkst_pw_init ();
  if (!lkst_enabled)
    return (*mutex_lock) (mtx);
  else
  {
    unsigned long long t = monotime (), dt;
    int r;
    if ((r = (*mutex_trylock) (mtx)) == 0)
      dt = 0;
    else
    {
      r = (*mutex_lock) (mtx);
      dt = 1 | (monotime () - t);
    }
    lkst_track_op (mtx, LKST_LOCK, t, dt);
    return r;
  }
}

int pthread_mutex_unlock (pthread_mutex_t *mtx)
{
  MSG ("unlock");
  if (!init_done)
    __lkst_pw_init ();
  if (lkst_enabled)
    lkst_track_op (mtx, LKST_UNLOCK, monotime (), 0);
  return (*mutex_unlock) (mtx);
}

int pthread_cond_wait (pthread_cond_t * __restrict cv, pthread_mutex_t * __restrict mtx)
{
  MSG ("cond_wait");
  if (!init_done)
    __lkst_pw_init ();
  if (!lkst_enabled)
    return (*cond_wait) (cv, mtx);
  else
  {
    int r;
    lkst_track_op (mtx, LKST_UNLOCK, monotime (), 0);
    r = (*cond_wait) (cv, mtx);
    /* Have no way of determining whether it was uncontended or not,
       and if not, how long the wait was. */
    lkst_track_op (mtx, LKST_LOCK, monotime (), 0);
    return r;
  }
}

int pthread_cond_timedwait (pthread_cond_t * __restrict cv, pthread_mutex_t * __restrict mtx, const struct timespec * __restrict abstime)
{
  /* see also cond_timedwait() */
  MSG ("cond_timedwait");
  if (!init_done)
    __lkst_pw_init ();
  if (!lkst_enabled)
    return (*cond_timedwait) (cv, mtx, abstime);
  else
  {
    int r;
    lkst_track_op (mtx, LKST_UNLOCK, monotime (), 0);
    r = (*cond_timedwait) (cv, mtx, abstime);
    lkst_track_op (mtx, LKST_LOCK, monotime (), 0);
    return r;
  }
}


