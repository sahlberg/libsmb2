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
#define WINREG_BASEREGENUMKEY        0x09
#define WINREG_BASEREGENUMVALUE      0x0a
#define WINREG_BASEREGOPENKEY        0x0f
#define WINREG_BASEREGQUERYINFOKEY   0x10
#define WINREG_OPENCURRENTCONFIG     0x1b

/* REG_VALUE_TYPE (MS-RRP 3.1.1.5) */
#define REG_NONE                       0
#define REG_SZ                         1
#define REG_EXPAND_SZ                  2
#define REG_BINARY                     3
#define REG_DWORD                      4
#define REG_DWORD_LITTLE_ENDIAN        4
#define REG_DWORD_BIG_ENDIAN           5
#define REG_LINK                       6
#define REG_MULTI_SZ                   7
#define REG_RESOURCE_LIST              8
#define REG_FULL_RESOURCE_DESCRIPTOR   9
#define REG_RESOURCE_REQUIREMENTS_LIST 10
#define REG_QWORD                      11
#define REG_QWORD_LITTLE_ENDIAN        11

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
 * Open* root keys share the same request/reply shape (MS-RRP):
 *   error_status_t OpenXxx(
 *     [in, unique] PREGISTRY_SERVER_NAME ServerName,
 *     [in] REGSAM samDesired,
 *     [out] PRPC_HKEY phKey
 *   );
 *
 * ServerName is [unique] PWCHAR and MUST be NULL (MS-RRP). Non-NULL is
 * rejected by the coder. It is not a conformant/varying NDR string.
 */
struct winreg_OpenRootKey_req {
        char *ServerName; /* must be NULL */
        uint32_t samDesired;
};

struct winreg_OpenRootKey_rep {
        uint32_t status;

        struct dcerpc_context_handle phKey;
};

/* Predefined keys we open (same layout as winreg_OpenRootKey_*) */
struct winreg_OpenClassesRoot_req {
        char *ServerName;
        uint32_t samDesired;
};
struct winreg_OpenClassesRoot_rep {
        uint32_t status;
        struct dcerpc_context_handle phKey;
};

struct winreg_OpenCurrentUser_req {
        char *ServerName;
        uint32_t samDesired;
};
struct winreg_OpenCurrentUser_rep {
        uint32_t status;
        struct dcerpc_context_handle phKey;
};

struct winreg_OpenLocalMachine_req {
        char *ServerName; /* must be NULL */
        uint32_t samDesired;
};

struct winreg_OpenLocalMachine_rep {
        uint32_t status;

        struct dcerpc_context_handle phKey;
};

struct winreg_OpenUsers_req {
        char *ServerName;
        uint32_t samDesired;
};
struct winreg_OpenUsers_rep {
        uint32_t status;
        struct dcerpc_context_handle phKey;
};

struct winreg_OpenCurrentConfig_req {
        char *ServerName;
        uint32_t samDesired;
};
struct winreg_OpenCurrentConfig_rep {
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

/*
 * typedef struct _FILETIME {
 *   DWORD dwLowDateTime;
 *   DWORD dwHighDateTime;
 * } FILETIME, *PFILETIME;
 */
struct winreg_FILETIME {
        uint32_t dwLowDateTime;
        uint32_t dwHighDateTime;
};

/*
 * error_status_t BaseRegQueryInfoKey(
 *   [in] RPC_HKEY hKey,
 *   [in] PRRP_UNICODE_STRING lpClassIn,
 *   [out] PRPC_UNICODE_STRING lpClassOut,
 *   [out] LPDWORD lpcSubKeys,
 *   [out] LPDWORD lpcbMaxSubKeyLen,
 *   [out] LPDWORD lpcbMaxClassLen,
 *   [out] LPDWORD lpcValues,
 *   [out] LPDWORD lpcbMaxValueNameLen,
 *   [out] LPDWORD lpcbMaxValueLen,
 *   [out] LPDWORD lpcbSecurityDescriptor,
 *   [out] PFILETIME lpftLastWriteTime
 * );
 *
 * lpClass is RRP_UNICODE_STRING (dcerpc_RPC_UNICODE_STRINGz_coder),
 * represented here as a UTF-8 C string (empty/NULL on request is typical).
 */
struct winreg_BaseRegQueryInfoKey_req {
        struct dcerpc_context_handle hKey;
        char *lpClass;
};

struct winreg_BaseRegQueryInfoKey_rep {
        uint32_t status;

        char *lpClass;
        uint32_t lpcSubKeys;
        uint32_t lpcbMaxSubKeyLen;
        uint32_t lpcbMaxClassLen;
        uint32_t lpcValues;
        uint32_t lpcbMaxValueNameLen;
        uint32_t lpcbMaxValueLen;
        uint32_t lpcbSecurityDescriptor;
        struct winreg_FILETIME lpftLastWriteTime;
};

/*
 * error_status_t BaseRegEnumKey(
 *   [in] RPC_HKEY hKey,
 *   [in] DWORD dwIndex,
 *   [in] PRRP_UNICODE_STRING lpNameIn,
 *   [out] PRRP_UNICODE_STRING lpNameOut,
 *   [in, unique] PRRP_UNICODE_STRING lpClassIn,
 *   [out] PRPC_UNICODE_STRING *lplpClassOut,
 *   [in, out, unique] PFILETIME lpftLastWriteTime
 * );
 *
 * IDL types these as RRP_UNICODE_STRING, but EnumKey requires
 * lpNameIn.Length == 0, so we encode them as plain RPC_UNICODE_STRING
 * (dcerpc_RPC_UNICODE_STRING_coder): empty content => Length 0, no forced
 * NUL. Content of the in-strings is ignored; only MaximumLength (client
 * buffer size in bytes) is significant. Set lpName_max_length /
 * lpClass_max_length (0 = default 1024 / 128). lpClass and
 * lpftLastWriteTime are optional unique (NULL is fine).
 */
struct winreg_BaseRegEnumKey_req {
        struct dcerpc_context_handle hKey;
        uint32_t dwIndex;
        char *lpName;
        uint16_t lpName_max_length;  /* not on wire; MaximumLength override */
        char *lpClass; /* unique; NULL ok */
        uint16_t lpClass_max_length; /* not on wire; MaximumLength override */
        struct winreg_FILETIME *lpftLastWriteTime; /* unique; NULL ok */
};

struct winreg_BaseRegEnumKey_rep {
        uint32_t status;

        char *lpName;
        char *lpClass; /* unique */
        struct winreg_FILETIME lpftLastWriteTime; /* unique on wire */
};

/*
 * error_status_t BaseRegOpenKey(
 *   [in] RPC_HKEY hKey,
 *   [in] PRRP_UNICODE_STRING lpSubKey,
 *   [in] DWORD dwOptions,
 *   [in] REGSAM samDesired,
 *   [out] PRPC_HKEY phkResult
 * );
 *
 * lpSubKey is a real key name (RRP_UNICODE_STRING / NUL-terminated).
 */
struct winreg_BaseRegOpenKey_req {
        struct dcerpc_context_handle hKey;
        char *lpSubKey;
        uint32_t dwOptions;
        uint32_t samDesired;
};

struct winreg_BaseRegOpenKey_rep {
        uint32_t status;

        struct dcerpc_context_handle phkResult;
};

/*
 * error_status_t BaseRegEnumValue(
 *   [in] RPC_HKEY hKey,
 *   [in] DWORD dwIndex,
 *   [in] PRRP_UNICODE_STRING lpValueNameIn,
 *   [out] PRPC_UNICODE_STRING lpValueNameOut,
 *   [in, out, unique] LPDWORD lpType,
 *   [in, out, unique, size_is(lpcbData?*lpcbData:0),
 *                     length_is(lpcbLen?*lpcbLen:0)] LPBYTE lpData,
 *   [in, out, unique] LPDWORD lpcbData,
 *   [in, out, unique] LPDWORD lpcbLen
 * );
 *
 * lpValueNameIn: content ignored; MaximumLength is the name buffer size
 * (same EnumKey pattern — use plain RPC_UNICODE_STRING + max_length).
 * On request set cbData to the client data buffer capacity and point
 * lpData at a buffer of that size (may be zero-filled). cbLen is the
 * number of bytes transmitted (0 on request is fine).
 */
struct winreg_BaseRegEnumValue_req {
        struct dcerpc_context_handle hKey;
        uint32_t dwIndex;
        char *lpValueName;
        uint16_t lpValueName_max_length; /* not on wire; MaximumLength */
        uint32_t type;
        uint8_t *lpData;
        uint32_t cbData; /* size of lpData buffer */
        uint32_t cbLen;  /* length_is: bytes to send / sent */
};

struct winreg_BaseRegEnumValue_rep {
        uint32_t status;

        char *lpValueName;
        uint32_t type;
        uint8_t *lpData;
        uint32_t cbData;
        uint32_t cbLen;
};

int winreg_OpenClassesRoot_rep_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr);
int winreg_OpenClassesRoot_req_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr);
int winreg_OpenCurrentUser_rep_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr);
int winreg_OpenCurrentUser_req_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr);
int winreg_OpenLocalMachine_rep_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int winreg_OpenLocalMachine_req_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int winreg_OpenUsers_rep_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr);
int winreg_OpenUsers_req_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr);
int winreg_OpenCurrentConfig_rep_coder(char *name, struct dcerpc_context *dce,
                                       struct dcerpc_pdu *pdu,
                                       struct smb2_iovec *iov, int *offset,
                                       void *ptr);
int winreg_OpenCurrentConfig_req_coder(char *name, struct dcerpc_context *dce,
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
int winreg_BaseRegQueryInfoKey_rep_coder(char *name, struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         struct smb2_iovec *iov, int *offset,
                                         void *ptr);
int winreg_BaseRegQueryInfoKey_req_coder(char *name, struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         struct smb2_iovec *iov, int *offset,
                                         void *ptr);
int winreg_BaseRegEnumKey_rep_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr);
int winreg_BaseRegEnumKey_req_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr);
int winreg_BaseRegOpenKey_rep_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr);
int winreg_BaseRegOpenKey_req_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr);
int winreg_BaseRegEnumValue_rep_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int winreg_BaseRegEnumValue_req_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);

extern struct dcerpc_procedure winreg_procs[];

#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_DCERPC_WINREG_H_ */
