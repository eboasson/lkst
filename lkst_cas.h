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
#ifndef LKST_CAS_H
#define LKST_CAS_H

#if __APPLE__
#include "libkern/OSAtomic.h"
#endif

static inline int cas_u (unsigned old, unsigned new, unsigned *x)
{
  /* ATOMIC { if (*x != old) { return false; } else { *x = new; return true; } } */
#if __APPLE__
  return OSAtomicCompareAndSwapIntBarrier ((int) old, (int) new, (int *) x);
#elif (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) > 40100
  return __sync_bool_compare_and_swap (x, old, new);
#elif __i386 && __GNUC__
  unsigned ret;
  volatile unsigned *vx = (volatile unsigned *) x;
  asm volatile ("lock; cmpxchgl %2, %1; sete %%al; movzbl %%al, %%eax"
                : "=a" (ret), "+m" (*vx)
                : "r" (new), "0" (old)
                : "memory", "cc");
  return ret;
#else
#error "no cas implementation"
#endif
}

#endif /* LKST_CAS_H */
