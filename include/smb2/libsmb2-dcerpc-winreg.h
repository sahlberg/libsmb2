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

#ifndef _LIBSMB2_DCERPC_WINREG_H_
#define _LIBSMB2_DCERPC_WINREG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <smb2/libsmb2-dcerpc.h>

/* MS-RRP opnums */
#define WINREG_OPENCLASSESROOT       0x00
#define WINREG_OPENCURRENTUSER       0x01
#define WINREG_OPENLOCALMACHINE      0x02
#define WINREG_OPENPERFORMANCEDATA   0x03
#define WINREG_OPENUSERS             0x04
#define WINREG_BASEREGCLOSEKEY       0x05

/*
 * REGSAM access rights (MS-RRP 2.2.3 and Win32 registry key rights).
 */
#define KEY_QUERY_VALUE              0x00000001
#define KEY_SET_VALUE                0x00000002
#define KEY_CREATE_SUB_KEY           0x00000004
#define KEY_ENUMERATE_SUB_KEYS       0x00000008
#define KEY_NOTIFY                   0x00000010
#define KEY_CREATE_LINK              0x00000020
#define KEY_WOW64_64KEY              0x00000100
#define KEY_WOW64_32KEY              0x00000200

#define KEY_READ                     0x00020019
#define KEY_WRITE                    0x00020006
#define KEY_EXECUTE                  0x00020019
#define KEY_ALL_ACCESS               0x000F003F

struct dcerpc_context;
struct dcerpc_pdu;

/*
 * error_status_t OpenLocalMachine(
 *   [in, unique] PREGISTRY_SERVER_NAME ServerName,
 *   [in] REGSAM samDesired,
 *   [out] PRPC_HKEY phKey
 * );
 *
 * ServerName is [unique] PWCHAR and MUST be NULL (MS-RRP). Non-NULL is
 * rejected by the coder. It is not a conformant/varying NDR string.
 */
struct winreg_OpenLocalMachine_req {
        char *ServerName; /* must be NULL */
        uint32_t samDesired;
};

struct winreg_OpenLocalMachine_rep {
        uint32_t status;

        struct dcerpc_context_handle phKey;
};

/*
 * error_status_t BaseRegCloseKey(
 *   [in, out] PRPC_HKEY hKey
 * );
 */
struct winreg_BaseRegCloseKey_req {
        struct dcerpc_context_handle hKey;
};

struct winreg_BaseRegCloseKey_rep {
        uint32_t status;

        struct dcerpc_context_handle hKey;
};

int winreg_OpenLocalMachine_rep_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int winreg_OpenLocalMachine_req_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int winreg_BaseRegCloseKey_rep_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr);
int winreg_BaseRegCloseKey_req_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr);

extern struct dcerpc_procedure winreg_procs[];

#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_DCERPC_WINREG_H_ */
