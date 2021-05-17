################################################################################
#
#  Copyright 2019-2020 Inango Systems Ltd.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
################################################################################

CC ?= gcc

CFLAGS  += -std=c99 -g -Wall -Wextra -pthread
LDFLAGS +=
LDLIBS  += -ldl

INCLUDES := -I. -I../common
SOURCES  := \
    ../common/rsc_protocol.c \
    rsc_server.c \
    rsc_logger.c \
    rsc_malloc.c \
    rsc_packing.c \
    rsc_proc.c \
    rsc_syscall.c \
    rsc_threads.c

PREFIX   ?= .
EXEFILE  ?= rsc-server

include ../common/revision.mk

all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDES) -fPIC $(SOURCES) $(LDLIBS) -DRSC_GIT_COMMIT='"$(GIT_COMMIT)"' -o $(PREFIX)/$(EXEFILE)

clean:
	rm -vf $(PREFIX)/$(EXEFILE)
