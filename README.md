# LKST
A simple locking statistics system that supports locks in shared
memory.

There are two components to LKST: a tool called "lkst" and a library
"liblkst".  There is also a library "liblkstpw", which is meant as a
pre-loadable wrapper for the pthreads library, but it doesn't work
yet.

The liblkst implements a number of operations for tracking lock
operations.  The lkst.h header defines the interface for user code,
and includes comments providing a very adumbrated reference to the
operations.

Applications must first initialise the library, by calling
lkst_init(), which returns 0 if initialisation failed and 1 if it
succeeded.  Only if initialisation was successful, the other functions
in the interface may be called.

An initialisation failure is usually caused by the lkst tool not
running, and should not be regarded as an error condition.  The reason
for this particular behaviour is that it allows the mutex\_lock() and
mutex\_unlock() wrappers to rely on a simple test of a global variable
to decide whether or not it should call the locking library.  The
result of this test is very predictable, and therefore the overhead of
the overhead of linking with this library is negligible unless it is
used.

The lkst\_track_...() functions track creation, destruction, locking
and unlocking of mutexes.  Depending on the behaviour selected for
that mutex, they maintain aggregate information on the lock, or
maintain information per-call stack.  The latter is called "trace"
mode.

Obviously, enabling trace mode on many locks will cause significant
memory consumption.

The lkst tool is the main user interface to the library, creates the
shared memory used by the process for tracking the locking operations
and allows a user to inspect the locks of a running application.  (The
shared memory segment may be mapped anywhere in the address space, it
doesn't have to be at the same address in all processes.)

A very brief summary of commands accepted by the lkst tool is
available from within the tool, using the "?" command.
