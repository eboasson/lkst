# Copyright (c) 2011 to 2017 Erik Boasson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. */
ifeq "$(shell uname -s)" "Darwin"
SOSUF = .dylib
SOFLAG = -dynamiclib
CC = clang
APPLE = 1
else
SOSUF = .so
SOFLAG = -shared
CC = gcc
APPLE = 0
endif

TARGETS = lkst liblkst$(SOSUF) liblkstpw$(SOSUF) test

SOURCES_lkst = lkst.c
SOURCES_liblkst$(SOSUF) = liblkst.c lookup3.c
SOURCES_liblkstpw$(SOSUF) = liblkstpw.c $(SOURCES_liblkst$(SOSUF))
SOURCES_test = test.c
SOURCES = $(foreach t, $(TARGETS), $(SOURCES_$t))

CFLAGS = -g -Wall -W -O2 -fpic
LDLIBS = -lpthread

ifeq "$(shell uname -s)" "Linux"
LDLIBS += -lrt
endif

.PHONY: all clean

all: $(TARGETS)

clean:
	-rm -f *.[od] $(TARGETS)

ifeq "$(APPLE)" "0"
%: %.o
	@$(MAKE) --no-print-directory liblkst$(SOSUF)
	$(CC) $(LDFLAGS) -L. -o $@ $(filter-out liblkst$(SOSUF), $^) -llkst
else
%: %.o
	@$(MAKE) --no-print-directory liblkst$(SOSUF)
	$(CC) $(LDFLAGS) -L. -o $@ $(filter-out liblkst$(SOSUF), $^) $(LDLIBS) -rpath $(PWD) -llkst
endif

lkst: $(SOURCES_lkst:%.c=%.o)
test: $(SOURCES_test:%.c=%.o)

ifeq "$(APPLE)" "0"
liblkst$(SOSUF): $(SOURCES_liblkst$(SOSUF):%.c=%.o)
	$(CC) $(SOFLAG) $(LDFLAGS) -o $@ $^ $(LDLIBS)
else
liblkst$(SOSUF): $(SOURCES_liblkst$(SOSUF):%.c=%.o)
	$(CC) $(SOFLAG) $(LDFLAGS) -install_name @rpath/$@ -o $@ $^ $(LDLIBS)
endif

liblkstpw$(SOSUF): $(SOURCES_liblkstpw$(SOSUF):%.c=%.o)
	$(CC) $(SOFLAG) $(LDFLAGS) -L. -o $@ $^ $(LDLIBS) -ldl

%.d: %.c
	$(SHELL) -ec "$(CC) -M $(CPPFLAGS) $< | sed 's/$*.o/& $@/g' > $@"

ifneq ($(MAKECMDGOALS),clean)
-include $(SOURCES:%.c=%.d)
endif
