/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * libsmb2-internal minimal DCE/RPC core with libsmb2_ symbol prefix.
 * Provides NetrShareEnum transport only; full DCE/RPC is in libdcerpc.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
/* Minimal build: never pull full interface tables into libsmb2. */
#undef HAVE_DCERPC_FULL
/* Stop nested #include "config.h" inside dcerpc.c from restoring defines. */
#ifdef HAVE_CONFIG_H
#undef HAVE_CONFIG_H
#define LIBSMB2_DCERPC_RESTORE_CONFIG_H 1
#endif
#include "libsmb2-dcerpc-prefix.h"
#include "../libdcerpc/dcerpc.c"
#ifdef LIBSMB2_DCERPC_RESTORE_CONFIG_H
#define HAVE_CONFIG_H 1
#endif
