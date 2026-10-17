# Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>
#
# Build the axpy external service and clients (self-contained).
#
#   config.idl → config_coder.c/h  (data-only)
#   axpy.idl   → axpy_coder.c/h    (interface; stubs stay hand-written)
#   axpy_stubs.c + serviced.c (-DSERVICE=axpy) → binary "axpy"
#   axpy-clnt.c + axpy_coder.o → binary "axpy-clnt" (sync)
#   axpy-clnt-async.c + axpy_coder.o → binary "axpy-clnt-async"
#   axpy_coder.c (-fPIC) → shared object "axpy_coder.so" for dlopen()
#
# serviced.c is the generic external-service worker.
# Prerequisites: libsmb2 + libdcerpc built in the tree.
# Regenerate coders only: make idl
# Never pass --stubs from this Makefile (would risk overwriting stubs).

CC ?= gcc
CFLAGS ?= -g -O2 -Wall -Wextra
# -I.. for dcerpcd_proto.h (control framing shared with dcerpcd)
CPPFLAGS += -I. -I.. -I../../../include -I../../../include/smb2 \
	-I../../include \
	"-D_U_=__attribute__((unused))" -D_GNU_SOURCE

SMB2_LIBDIR := $(shell test -d ../../../lib/.libs && echo ../../../lib/.libs || echo ../../../lib)
DCERPC_LIBDIR := $(shell test -d ../../.libs && echo ../../.libs || echo ../..)
LIBS += -L$(DCERPC_LIBDIR) -L$(SMB2_LIBDIR) -ldcerpc -lsmb2 \
	-lgssapi_krb5 -ldl -lpthread
LDFLAGS += -Wl,-rpath,$(abspath $(DCERPC_LIBDIR)) \
	-Wl,-rpath,$(abspath $(SMB2_LIBDIR))

IDLCOMP_PY = ../../idlcomp.py
IDLCOMP = python3 $(IDLCOMP_PY)
SERVICE = axpy

CONFIG_IDL = config.idl
CONFIG_CODER_C = config_coder.c
CONFIG_CODER_H = config_coder.h
CONFIG_CODER_O = config_coder.o

AXPY_IDL = axpy.idl
AXPY_CODER_C = axpy_coder.c
AXPY_CODER_H = axpy_coder.h
AXPY_CODER_O = axpy_coder.o
AXPY_CODER_SO = axpy_coder.so
AXPY_SERVER_H = axpy_server.h

AXPY_STUBS_C = axpy_stubs.c
AXPY_STUBS_O = axpy_stubs.o

SERVICED_C = serviced.c
SERVICED_O = serviced.o

PROG = axpy
CLNT = axpy-clnt
CLNT_ASYNC = axpy-clnt-async
OBJS = $(SERVICED_O) $(AXPY_STUBS_O) $(AXPY_CODER_O) $(CONFIG_CODER_O)
CLNT_O = axpy-clnt.o
CLNT_ASYNC_O = axpy-clnt-async.o

.PHONY: all clean idl

all: $(PROG) $(CLNT) $(CLNT_ASYNC) $(AXPY_CODER_SO)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

# Clients link interface coders only (stub table lives in axpy_stubs.c).
$(CLNT): $(CLNT_O) $(AXPY_CODER_O)
	$(CC) $(CFLAGS) -o $@ $(CLNT_O) $(AXPY_CODER_O) $(LDFLAGS) $(LIBS)

$(CLNT_ASYNC): $(CLNT_ASYNC_O) $(AXPY_CODER_O)
	$(CC) $(CFLAGS) -o $@ $(CLNT_ASYNC_O) $(AXPY_CODER_O) $(LDFLAGS) $(LIBS)

# Interface coders as a shared object so external programs can dlopen()
# it and dlsym() axpy_interface / axpy_procs etc.
# Linked against libdcerpc so its dependencies resolve on dlopen.
$(AXPY_CODER_SO): $(AXPY_CODER_C) $(AXPY_CODER_H)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared -o $@ $(AXPY_CODER_C) \
		$(LDFLAGS) $(LIBS)

idl: $(CONFIG_CODER_C) $(CONFIG_CODER_H) $(AXPY_CODER_C) $(AXPY_CODER_H) $(AXPY_SERVER_H)

$(CONFIG_CODER_C) $(CONFIG_CODER_H): $(CONFIG_IDL) $(IDLCOMP_PY)
	$(IDLCOMP) $(CONFIG_IDL) -o $(CONFIG_CODER_C)

$(AXPY_CODER_C) $(AXPY_CODER_H) $(AXPY_SERVER_H): $(AXPY_IDL) $(IDLCOMP_PY)
	$(IDLCOMP) $(AXPY_IDL) -o $(AXPY_CODER_C)

$(CONFIG_CODER_O): $(CONFIG_CODER_C) $(CONFIG_CODER_H)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(CONFIG_CODER_C)

$(AXPY_CODER_O): $(AXPY_CODER_C) $(AXPY_CODER_H)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(AXPY_CODER_C)

$(AXPY_STUBS_O): $(AXPY_STUBS_C) $(AXPY_SERVER_H) $(CONFIG_CODER_H)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(AXPY_STUBS_C)

# -I. so #include "axpy_server.h" / SERVICE_SERVER_H resolve.
$(SERVICED_O): $(SERVICED_C) ../dcerpcd_proto.h $(AXPY_SERVER_H)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DSERVICE=$(SERVICE) \
		-DSERVICE_INIT=$(SERVICE)_init -c -o $@ $(SERVICED_C)

$(CLNT_O): axpy-clnt.c $(AXPY_CODER_H)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ axpy-clnt.c

$(CLNT_ASYNC_O): axpy-clnt-async.c $(AXPY_CODER_H)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ axpy-clnt-async.c

clean:
	rm -f $(PROG) $(CLNT) $(CLNT_ASYNC) $(AXPY_CODER_SO) $(OBJS) $(CLNT_O) $(CLNT_ASYNC_O)
	rm -f $(CONFIG_CODER_C) $(CONFIG_CODER_H)
	rm -f $(AXPY_CODER_C) $(AXPY_CODER_H) $(AXPY_SERVER_H)
