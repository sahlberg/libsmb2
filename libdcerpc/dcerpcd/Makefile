# Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Simple in-tree build for dcerpcd.
# Requires libsmb2 and libdcerpc already built in the tree (./configure && make
# at the top level).

CC ?= gcc
CFLAGS ?= -g -O2 -Wall -Wextra
# libdcerpc's generated interface headers (<dcerpc/epm.h>) live in its
# per-interface build directories.
CPPFLAGS += -I. -I../../include -I../../include/smb2 -I../include \
	-I../epm \
	"-D_U_=__attribute__((unused))" -D_GNU_SOURCE
# Prefer libtool .libs/ (current in-tree build) over stale lib/*.so copies.
SMB2_LIBDIR := $(shell test -d ../../lib/.libs && echo ../../lib/.libs || echo ../../lib)
DCERPC_LIBDIR := $(shell test -d ../.libs && echo ../.libs || echo ..)
LIBS += -L$(DCERPC_LIBDIR) -L$(SMB2_LIBDIR) -ldcerpc -lsmb2 \
	-lgssapi_krb5 -ldl -lpthread
LDFLAGS += -Wl,-rpath,$(abspath $(DCERPC_LIBDIR)) \
	-Wl,-rpath,$(abspath $(SMB2_LIBDIR))

PROG = dcerpcd
SRCS = dcerpcd.c auth.c passwd.c config.c epm.c pipe.c external.c
OBJS = $(SRCS:.c=.o)

# ---------------------------------------------------------------------------
# Data-only IDL for config / passwd YAML (dcerpc_read_yaml_file), compiled
# with libdcerpc's IDL compiler.
# ---------------------------------------------------------------------------
IDLCOMP_PY = ../idlcomp.py
IDLCOMP = python3 $(IDLCOMP_PY)

CONFIG_IDL = config.idl
CONFIG_CODER_C = config_coder.c
CONFIG_CODER_H = config_coder.h
CONFIG_CODER_O = config_coder.o

PASSWD_IDL = passwd.idl
PASSWD_CODER_C = passwd_coder.c
PASSWD_CODER_H = passwd_coder.h
PASSWD_CODER_O = passwd_coder.o

DATA_IDL_OBJS = $(CONFIG_CODER_O) $(PASSWD_CODER_O)

.PHONY: all clean idl

all: $(PROG)

$(PROG): $(OBJS) $(DATA_IDL_OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(DATA_IDL_OBJS) $(LDFLAGS) $(LIBS)

%.o: %.c dcerpcd.h dcerpcd_proto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

config.o: config.c $(CONFIG_CODER_H) dcerpcd.h
passwd.o: passwd.c $(PASSWD_CODER_H) dcerpcd.h

$(CONFIG_CODER_C) $(CONFIG_CODER_H): $(CONFIG_IDL) $(IDLCOMP_PY)
	$(IDLCOMP) $(CONFIG_IDL) -o $(CONFIG_CODER_C)

$(PASSWD_CODER_C) $(PASSWD_CODER_H): $(PASSWD_IDL) $(IDLCOMP_PY)
	$(IDLCOMP) $(PASSWD_IDL) -o $(PASSWD_CODER_C)

$(CONFIG_CODER_O): $(CONFIG_CODER_C) $(CONFIG_CODER_H)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(CONFIG_CODER_C)

$(PASSWD_CODER_O): $(PASSWD_CODER_C) $(PASSWD_CODER_H)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(PASSWD_CODER_C)

# Regenerate the data-only IDL coders.
idl: $(CONFIG_CODER_O) $(PASSWD_CODER_O)

clean:
	rm -f $(PROG) $(OBJS) $(DATA_IDL_OBJS)
	rm -f dcerpcd.sock
