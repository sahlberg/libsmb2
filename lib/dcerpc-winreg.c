/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef STDC_HEADERS
#include <stddef.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_UNISTD_H
#include <sys/unistd.h>
#endif

#include <errno.h>
#include <stdio.h>

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-dcerpc.h"
#include "libsmb2-dcerpc-winreg.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

/*
 * MS-RRP RRP_UNICODE_STRING is the same type as dcerpc's
 * RPC_UNICODE_STRINGz (NUL-terminated Buffer). Use
 * dcerpc_RRP_UNICODE_STRING_coder / dcerpc_RPC_UNICODE_STRINGz_coder —
 * they are the same coder (macro alias).
 */

/* MS-RRP: uuid(338cd001-2244-31f1-aaaa-900038001003), version(1.0) */
#define WINREG_UUID    0x338cd001, 0x2244, 0x31f1, {0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03}

p_syntax_id_t winreg_interface = {
        {WINREG_UUID}, 1, 0
};

static int
winreg_RPC_HKEY_STRUCT_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   dcerpc_context_handle_coder);
}

/*
 * PREGISTRY_SERVER_NAME is [unique] PWCHAR: a pointer to a raw
 * null-terminated UTF-16 array (no NDR string conformance/variance
 * fields). MS-RRP requires ServerName to be sent as NULL for
 * OpenLocalMachine (and related Open* root calls); non-NULL is not
 * supported here. This coder is only invoked when the unique pointer
 * is non-NULL, which is treated as an error.
 */
static int
winreg_ServerName_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct smb2_iovec *iov, int *offset,
                        void *ptr)
{
        smb2_set_error(dcerpc_get_smb2_context(dce),
                       "winreg ServerName must be NULL");
        return -1;
}

/**********************
 * Function: 0x02
 *      error_status_t OpenLocalMachine(
 *              [in, unique] PREGISTRY_SERVER_NAME ServerName,
 *              [in] REGSAM samDesired,
 *              [out] PRPC_HKEY phKey
 *              );
 *
 * ServerName SHOULD be sent as NULL and MUST be ignored on receipt.
 * Pass req->ServerName (the pointer value) so a NULL unique encodes/
 * decodes without invoking the referent coder; any non-NULL referent
 * fails in winreg_ServerName_coder.
 **********************/
int
winreg_OpenLocalMachine_req_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        struct winreg_OpenLocalMachine_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, req->ServerName,
                             PTR_UNIQUE, winreg_ServerName_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("samDesired", dce, pdu, iov, offset, &req->samDesired)) {
                return -1;
        }
        return 0;
}

int
winreg_OpenLocalMachine_rep_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        struct winreg_OpenLocalMachine_rep *rep = ptr;

        if (dcerpc_ptr_coder("phKey", dce, pdu, iov, offset, &rep->phKey,
                             PTR_REF, winreg_RPC_HKEY_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/**********************
 * Function: 0x05
 *      error_status_t BaseRegCloseKey(
 *              [in, out] PRPC_HKEY hKey
 *              );
 **********************/
int
winreg_BaseRegCloseKey_req_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        struct winreg_BaseRegCloseKey_req *req = ptr;

        if (dcerpc_ptr_coder("hKey", dce, pdu, iov, offset, &req->hKey,
                             PTR_REF, winreg_RPC_HKEY_STRUCT_coder)) {
                return -1;
        }

        return 0;
}

int
winreg_BaseRegCloseKey_rep_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        struct winreg_BaseRegCloseKey_rep *rep = ptr;

        if (dcerpc_ptr_coder("hKey", dce, pdu, iov, offset, &rep->hKey,
                             PTR_REF, winreg_RPC_HKEY_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

static int
winreg_FILETIME_coder(char *name, struct dcerpc_context *dce,
                      struct dcerpc_pdu *pdu,
                      struct smb2_iovec *iov, int *offset,
                      void *ptr)
{
        struct winreg_FILETIME *ft = ptr;

        if (dcerpc_uint32_coder("dwLowDateTime", dce, pdu, iov, offset,
                                &ft->dwLowDateTime)) {
                return -1;
        }
        if (dcerpc_uint32_coder("dwHighDateTime", dce, pdu, iov, offset,
                                &ft->dwHighDateTime)) {
                return -1;
        }
        return 0;
}

static int
winreg_FILETIME_STRUCT_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   winreg_FILETIME_coder);
}

/**********************
 * Function: 0x10
 *      error_status_t BaseRegQueryInfoKey(
 *              [in] RPC_HKEY hKey,
 *              [in] PRRP_UNICODE_STRING lpClassIn,
 *              [out] PRPC_UNICODE_STRING lpClassOut,
 *              [out] LPDWORD lpcSubKeys,
 *              [out] LPDWORD lpcbMaxSubKeyLen,
 *              [out] LPDWORD lpcbMaxClassLen,
 *              [out] LPDWORD lpcValues,
 *              [out] LPDWORD lpcbMaxValueNameLen,
 *              [out] LPDWORD lpcbMaxValueLen,
 *              [out] LPDWORD lpcbSecurityDescriptor,
 *              [out] PFILETIME lpftLastWriteTime
 *              );
 **********************/
int
winreg_BaseRegQueryInfoKey_req_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr)
{
        struct winreg_BaseRegQueryInfoKey_req *req = ptr;

        if (dcerpc_ptr_coder("hKey", dce, pdu, iov, offset, &req->hKey,
                             PTR_REF, winreg_RPC_HKEY_STRUCT_coder)) {
                return -1;
        }
        /* Top-level [in] PRRP_UNICODE_STRING: REF, NUL-terminated Buffer */
        if (dcerpc_ptr_coder("lpClass", dce, pdu, iov, offset, &req->lpClass,
                             PTR_REF, dcerpc_RRP_UNICODE_STRING_coder)) {
                return -1;
        }
        return 0;
}

int
winreg_BaseRegQueryInfoKey_rep_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr)
{
        struct winreg_BaseRegQueryInfoKey_rep *rep = ptr;

        /* [out] class: RRP_UNICODE_STRING (NUL-terminated) */
        if (dcerpc_ptr_coder("lpClass", dce, pdu, iov, offset, &rep->lpClass,
                             PTR_REF, dcerpc_RRP_UNICODE_STRING_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("lpcSubKeys", dce, pdu, iov, offset,
                                &rep->lpcSubKeys)) {
                return -1;
        }
        if (dcerpc_uint32_coder("lpcbMaxSubKeyLen", dce, pdu, iov, offset,
                                &rep->lpcbMaxSubKeyLen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("lpcbMaxClassLen", dce, pdu, iov, offset,
                                &rep->lpcbMaxClassLen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("lpcValues", dce, pdu, iov, offset,
                                &rep->lpcValues)) {
                return -1;
        }
        if (dcerpc_uint32_coder("lpcbMaxValueNameLen", dce, pdu, iov, offset,
                                &rep->lpcbMaxValueNameLen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("lpcbMaxValueLen", dce, pdu, iov, offset,
                                &rep->lpcbMaxValueLen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("lpcbSecurityDescriptor", dce, pdu, iov, offset,
                                &rep->lpcbSecurityDescriptor)) {
                return -1;
        }
        if (dcerpc_ptr_coder("lpftLastWriteTime", dce, pdu, iov, offset,
                             &rep->lpftLastWriteTime,
                             PTR_REF, winreg_FILETIME_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/**********************
 * Function: 0x09
 *      error_status_t BaseRegEnumKey(
 *              [in] RPC_HKEY hKey,
 *              [in] DWORD dwIndex,
 *              [in] PRRP_UNICODE_STRING lpNameIn,
 *              [out] PRRP_UNICODE_STRING lpNameOut,
 *              [in, unique] PRRP_UNICODE_STRING lpClassIn,
 *              [out] PRPC_UNICODE_STRING *lplpClassOut,
 *              [in, out, unique] PFILETIME lpftLastWriteTime
 *              );
 *
 * IDL names these RRP_UNICODE_STRING, but the EnumKey text requires
 * lpNameIn.Length MUST be 0 (content ignored; only MaximumLength matters).
 * Use plain RPC_UNICODE_STRING so an empty input encodes Length=0 without
 * a forced NUL wchar. lpClassIn / lpftLastWriteTime may be unique NULL.
 * Client buffer size is set via dcerpc_set_unicode_max_length.
 **********************/
/* Defaults match common clients (e.g. impacket hBaseRegEnumKey). */
#define WINREG_ENUMKEY_NAME_MAX_LENGTH  1024
#define WINREG_ENUMKEY_CLASS_MAX_LENGTH 128

int
winreg_BaseRegEnumKey_req_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        struct winreg_BaseRegEnumKey_req *req = ptr;
        uint16_t name_ml, class_ml;

        if (dcerpc_ptr_coder("hKey", dce, pdu, iov, offset, &req->hKey,
                             PTR_REF, winreg_RPC_HKEY_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("dwIndex", dce, pdu, iov, offset, &req->dwIndex)) {
                return -1;
        }
        /*
         * lpNameIn: content ignored; MaximumLength is the client name
         * buffer. Setter no-ops for non-NDR / non-encode PDUs.
         */
        name_ml = req->lpName_max_length ?
                req->lpName_max_length : WINREG_ENUMKEY_NAME_MAX_LENGTH;
        dcerpc_set_unicode_max_length(pdu, name_ml);
        if (dcerpc_ptr_coder("lpName", dce, pdu, iov, offset, &req->lpName,
                             PTR_REF, dcerpc_RPC_UNICODE_STRING_coder)) {
                return -1;
        }
        /*
         * [in, unique] lpClassIn: pass &req->lpClass so the coder gets
         * a char **. YAML may omit the key (unique NULL / empty).
         */
        class_ml = req->lpClass_max_length ?
                req->lpClass_max_length : WINREG_ENUMKEY_CLASS_MAX_LENGTH;
        dcerpc_set_unicode_max_length(pdu, class_ml);
        if (dcerpc_ptr_coder("lpClass", dce, pdu, iov, offset, &req->lpClass,
                             PTR_UNIQUE, dcerpc_RPC_UNICODE_STRING_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("lpftLastWriteTime", dce, pdu, iov, offset,
                             req->lpftLastWriteTime,
                             PTR_UNIQUE, winreg_FILETIME_STRUCT_coder)) {
                return -1;
        }
        return 0;
}

int
winreg_BaseRegEnumKey_rep_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        struct winreg_BaseRegEnumKey_rep *rep = ptr;

        if (dcerpc_ptr_coder("lpName", dce, pdu, iov, offset, &rep->lpName,
                             PTR_REF, dcerpc_RPC_UNICODE_STRING_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("lpClass", dce, pdu, iov, offset, &rep->lpClass,
                             PTR_UNIQUE, dcerpc_RPC_UNICODE_STRING_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("lpftLastWriteTime", dce, pdu, iov, offset,
                             &rep->lpftLastWriteTime,
                             PTR_UNIQUE, winreg_FILETIME_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

struct dcerpc_procedure winreg_procs[] = {
        {WINREG_OPENLOCALMACHINE, "OpenLocalMachine",
         winreg_OpenLocalMachine_req_coder, sizeof(struct winreg_OpenLocalMachine_req),
         winreg_OpenLocalMachine_rep_coder, sizeof(struct winreg_OpenLocalMachine_rep),
        },
        {WINREG_BASEREGCLOSEKEY, "BaseRegCloseKey",
         winreg_BaseRegCloseKey_req_coder, sizeof(struct winreg_BaseRegCloseKey_req),
         winreg_BaseRegCloseKey_rep_coder, sizeof(struct winreg_BaseRegCloseKey_rep),
        },
        {WINREG_BASEREGENUMKEY, "BaseRegEnumKey",
         winreg_BaseRegEnumKey_req_coder,
         sizeof(struct winreg_BaseRegEnumKey_req),
         winreg_BaseRegEnumKey_rep_coder,
         sizeof(struct winreg_BaseRegEnumKey_rep),
        },
        {WINREG_BASEREGQUERYINFOKEY, "BaseRegQueryInfoKey",
         winreg_BaseRegQueryInfoKey_req_coder,
         sizeof(struct winreg_BaseRegQueryInfoKey_req),
         winreg_BaseRegQueryInfoKey_rep_coder,
         sizeof(struct winreg_BaseRegQueryInfoKey_rep),
        },
        {-1, NULL, NULL, 0, NULL, 0}
};
