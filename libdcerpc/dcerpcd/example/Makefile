# Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>
#
# Build data-only IDL example: config.idl → config_coder.c/h (+ optional .o).
# Data-only IDL has no interface, so --stubs is not supported.

CC ?= gcc
CFLAGS ?= -g -O2 -Wall -Wextra
CPPFLAGS += -I. -I../../../include -I../../../include/smb2 -I../../include \
	"-D_U_=__attribute__((unused))" -D_GNU_SOURCE

IDLCOMP_PY = ../../idlcomp.py
IDLCOMP = python3 $(IDLCOMP_PY)
IDL = config.idl
CODER_C = config_coder.c
CODER_H = config_coder.h
CODER_O = config_coder.o

.PHONY: all clean idl

all: $(CODER_O)

idl: $(CODER_C) $(CODER_H)

$(CODER_C) $(CODER_H): $(IDL) $(IDLCOMP_PY)
	$(IDLCOMP) $(IDL) -o $(CODER_C)

$(CODER_O): $(CODER_C) $(CODER_H)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(CODER_C)

clean:
	rm -f $(CODER_O) $(CODER_C) $(CODER_H)
