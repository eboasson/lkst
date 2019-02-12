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

#include "lkst.h"

uint64_t a, b, c;

void f (void)
{
  static int kk = 1;
  lkst_track_op (&a, LKST_LOCK, lkst_monotime (), 100 * kk++);
  lkst_track_op (&a, LKST_UNLOCK, lkst_monotime (), 0);
}

void g (uint64_t *l)
{
  lkst_track_op (l, LKST_LOCK, lkst_monotime (), 0);
  f ();
  lkst_track_op (l, LKST_UNLOCK, lkst_monotime (), 0);
}

void h (void)
{
  lkst_track_op (&c, LKST_LOCK, lkst_monotime (), 0);
  g (&b);
  lkst_track_op (&c, LKST_UNLOCK, lkst_monotime (), 0);
}

int main ()
{
  lkst_full_lockid_t hot[2];
  int nhot;
  int i;

  lkst_init (0);
  lkst_track_init (&a, LKST_MF_SHARED);
  lkst_track_init (&b, 0);
  lkst_track_init (&c, 0);

  //printf ("----\n");

  printf ("[press enter ...]"); fflush (stdout);
  getchar ();

  for (i = 0; i < 4; i++)
    f ();
  g (&b);
  g (&c);
  h ();
  lkst_track_op (&a, LKST_LOCK, lkst_monotime (), 1);
  printf ("[press enter ...]"); fflush (stdout);
  getchar ();
  lkst_track_op (&a, LKST_UNLOCK, lkst_monotime (), 0);

  printf ("HOTTEST LOCKS <<\n");
  nhot = lkst_hottest_locks (hot, (int) (sizeof (hot) / sizeof (*hot)));
  for (i = 0; i < nhot; i++)
    lkst_dump_lock (stdout, hot[i], LKST_DF_SHORT, 0, 0);
  printf (">>\n");

  lkst_track_destroy (&c);
  lkst_track_destroy (&b);
  lkst_track_destroy (&a);

  printf ("[press enter ...]"); fflush (stdout);
  getchar ();

  lkst_fini ();
  return 0;
}
