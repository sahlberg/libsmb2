/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Recursively enumerate registry keys and values under predefined hives
 * via MS-RRP (winreg on IPC$):
 *   HKCR  HKEY_CLASSES_ROOT    (OpenClassesRoot)
 *   HKCU  HKEY_CURRENT_USER    (OpenCurrentUser)
 *   HKLM  HKEY_LOCAL_MACHINE   (OpenLocalMachine)
 *   HKU   HKEY_USERS           (OpenUsers)
 *   HKCC  HKEY_CURRENT_CONFIG  (OpenCurrentConfig)
 *
 * Walks each hive with BaseRegEnumValue / BaseRegEnumKey / BaseRegOpenKey
 * / BaseRegCloseKey. Prints one entry per line, indented two spaces per
 * depth level. Values are shown as:  name (TYPE) = data
 *
 * Usage:
 *   smb2-winreg-enum smb://[<domain;][<user>@]<host>/
 *
 * Share path in the URL is ignored; the tool always uses IPC$.
 * Access-denied keys are skipped with a message on stderr.
 * Full walks can be large and slow.
 */

#define _GNU_SOURCE

#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-winreg.h>

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

/* Win32 / MS-ERREF */
#define ERROR_SUCCESS           0x00000000
#define ERROR_ACCESS_DENIED     0x00000005
#define ERROR_MORE_DATA         0x000000ea
#define ERROR_NO_MORE_ITEMS     0x00000103

/* SamDesired for walking: read + enumerate */
#define WINREG_WALK_ACCESS      (KEY_READ)

#define WALK_PHASE_VALUES  0
#define WALK_PHASE_KEYS    1

#define VALUE_DATA_BUF     65536

static int is_finished;
static struct dcerpc_context *g_dce;
/* Which predefined hive to open next after the current root walk ends. */
/* 0=HKCR, 1=HKCU, 2=HKLM, 3=HKU, 4=HKCC, 5=done */
static int g_next_hive;

/*
 * One open key in the recursive walk. parent is the key we will continue
 * enumerating after this one is fully processed and closed.
 * phase: first enumerate values, then subkeys.
 */
struct walk {
        struct dcerpc_context_handle hKey;
        uint32_t index;   /* next enum index for current phase */
        int phase;        /* WALK_PHASE_VALUES or WALK_PHASE_KEYS */
        int depth;        /* indent level for children of this key */
        char *pending;    /* subkey name waiting for BaseRegOpenKey */
        uint8_t *valbuf;  /* scratch buffer for EnumValue data */
        struct walk *parent;
};

static void walk_continue(struct walk *w);
static void walk_close(struct walk *w);
static void walk_open_child(struct walk *parent, const char *name);
static void walk_enum_values(struct walk *w);
static void walk_enum_keys(struct walk *w);
static void open_next_hive(void);

static int
usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-winreg-enum <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/\n"
                "Connects to IPC$/winreg and dumps HKCR, HKCU, HKLM, HKU, "
                "then HKCC recursively.\n");
        exit(1);
}

static void
print_indent(int depth)
{
        int i;

        for (i = 0; i < depth; i++) {
                printf("  ");
        }
}

static void
print_key(int depth, const char *name)
{
        print_indent(depth);
        printf("%s\n", name ? name : "");
}

static const char *
reg_type_name(uint32_t type)
{
        switch (type) {
        case REG_NONE:       return "REG_NONE";
        case REG_SZ:         return "REG_SZ";
        case REG_EXPAND_SZ:  return "REG_EXPAND_SZ";
        case REG_BINARY:     return "REG_BINARY";
        case REG_DWORD:      return "REG_DWORD";
        case REG_DWORD_BIG_ENDIAN: return "REG_DWORD_BE";
        case REG_LINK:       return "REG_LINK";
        case REG_MULTI_SZ:   return "REG_MULTI_SZ";
        case REG_QWORD:      return "REG_QWORD";
        default:             return "REG_UNKNOWN";
        }
}

/* Decode UTF-16LE registry string data (may lack NUL) into utf8 scratch. */
static char *
utf16le_to_utf8(const uint8_t *data, uint32_t len)
{
        uint32_t nchars = len / 2;
        uint16_t *tmp;
        const char *u8;
        char *out;
        uint32_t i;

        if (data == NULL || nchars == 0) {
                return strdup("");
        }
        tmp = malloc((size_t)nchars * sizeof(uint16_t));
        if (tmp == NULL) {
                return NULL;
        }
        for (i = 0; i < nchars; i++) {
                tmp[i] = (uint16_t)data[i * 2] |
                        ((uint16_t)data[i * 2 + 1] << 8);
        }
        /* drop trailing NUL if present */
        if (nchars > 0 && tmp[nchars - 1] == 0) {
                nchars--;
        }
        u8 = smb2_utf16_to_utf8(tmp, nchars);
        free(tmp);
        if (u8 == NULL) {
                return NULL;
        }
        out = strdup(u8);
        free(discard_const(u8));
        return out;
}

static void
print_value(int depth, const char *name, uint32_t type,
            const uint8_t *data, uint32_t len)
{
        const char *nm = (name && name[0]) ? name : "(Default)";

        print_indent(depth);
        printf("%s (%s) = ", nm, reg_type_name(type));

        switch (type) {
        case REG_SZ:
        case REG_EXPAND_SZ: {
                char *s = utf16le_to_utf8(data, len);

                printf("\"%s\"\n", s ? s : "");
                free(s);
                break;
        }
        case REG_DWORD:
                if (len >= 4 && data) {
                        uint32_t v = (uint32_t)data[0] |
                                ((uint32_t)data[1] << 8) |
                                ((uint32_t)data[2] << 16) |
                                ((uint32_t)data[3] << 24);
                        printf("0x%08x (%u)\n", v, v);
                } else {
                        printf("(short)\n");
                }
                break;
        case REG_DWORD_BIG_ENDIAN:
                if (len >= 4 && data) {
                        uint32_t v = ((uint32_t)data[0] << 24) |
                                ((uint32_t)data[1] << 16) |
                                ((uint32_t)data[2] << 8) |
                                (uint32_t)data[3];
                        printf("0x%08x (%u)\n", v, v);
                } else {
                        printf("(short)\n");
                }
                break;
        case REG_QWORD:
                if (len >= 8 && data) {
                        uint64_t v = 0;
                        int i;
                        for (i = 7; i >= 0; i--) {
                                v = (v << 8) | data[i];
                        }
                        printf("0x%016" PRIx64 "\n", v);
                } else {
                        printf("(short)\n");
                }
                break;
        case REG_MULTI_SZ: {
                uint32_t off = 0;
                int first = 1;

                printf("{");
                while (off + 2 <= len) {
                        uint32_t start = off;
                        /* find next double-NUL or end */
                        while (off + 2 <= len) {
                                if (data[off] == 0 && data[off + 1] == 0) {
                                        break;
                                }
                                off += 2;
                        }
                        if (off == start) {
                                break; /* empty = end of multi */
                        }
                        {
                                char *s = utf16le_to_utf8(data + start,
                                                          off - start);
                                printf("%s\"%s\"", first ? "" : ", ",
                                       s ? s : "");
                                free(s);
                                first = 0;
                        }
                        off += 2;
                }
                printf("}\n");
                break;
        }
        default: {
                uint32_t i, n = len < 32 ? len : 32;

                printf("hex:");
                for (i = 0; i < n; i++) {
                        printf("%02x", data ? data[i] : 0);
                }
                if (len > n) {
                        printf("... (%u bytes)", len);
                }
                printf("\n");
                break;
        }
        }
}

static struct walk *
walk_new(struct dcerpc_context_handle *hKey, int depth, struct walk *parent)
{
        struct walk *w;

        w = calloc(1, sizeof(*w));
        if (w == NULL) {
                fprintf(stderr, "out of memory\n");
                exit(10);
        }
        memcpy(&w->hKey, hKey, sizeof(w->hKey));
        w->index = 0;
        w->phase = WALK_PHASE_VALUES;
        w->depth = depth;
        w->parent = parent;
        w->valbuf = malloc(VALUE_DATA_BUF);
        if (w->valbuf == NULL) {
                fprintf(stderr, "out of memory\n");
                exit(10);
        }
        return w;
}

static void
walk_free(struct walk *w)
{
        if (w == NULL) {
                return;
        }
        free(w->pending);
        free(w->valbuf);
        free(w);
}

static void
fail_rpc(struct dcerpc_context *dce, const char *what, int status)
{
        fprintf(stderr, "%s failed (%s) %s\n",
                what, strerror(-status), dcerpc_get_error(dce));
        exit(10);
}

static void
cl_cb(struct dcerpc_context *dce, int status,
      void *command_data, void *cb_data)
{
        struct winreg_BaseRegCloseKey_rep *rep = command_data;
        struct walk *w = cb_data;
        struct walk *parent;

        if (status) {
                dcerpc_free_data(dce, rep);
                fail_rpc(dce, "BaseRegCloseKey", status);
        }
        dcerpc_free_data(dce, rep);

        parent = w->parent;
        walk_free(w);

        if (parent == NULL) {
                /* Finished one hive root; open the next predefined key. */
                open_next_hive();
                return;
        }
        /* Continue enumerating the parent after finishing this child. */
        walk_continue(parent);
}

static void
walk_close(struct walk *w)
{
        struct winreg_BaseRegCloseKey_req req;

        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, &w->hKey, sizeof(req.hKey));
        if (dcerpc_call_async(g_dce,
                              WINREG_BASEREGCLOSEKEY,
                              winreg_BaseRegCloseKey_req_coder, &req,
                              winreg_BaseRegCloseKey_rep_coder,
                              sizeof(struct winreg_BaseRegCloseKey_rep),
                              cl_cb, w) != 0) {
                fprintf(stderr, "dcerpc_call_async CloseKey: %s\n",
                        dcerpc_get_error(g_dce));
                exit(10);
        }
}

static void
op_cb(struct dcerpc_context *dce, int status,
      void *command_data, void *cb_data)
{
        struct winreg_BaseRegOpenKey_rep *rep = command_data;
        struct walk *parent = cb_data;
        struct walk *child;
        char *name;

        if (status) {
                dcerpc_free_data(dce, rep);
                fail_rpc(dce, "BaseRegOpenKey", status);
        }

        name = parent->pending;
        parent->pending = NULL;

        if (rep->status == ERROR_ACCESS_DENIED) {
                fprintf(stderr, "%*s# access denied: %s\n",
                        parent->depth * 2, "", name ? name : "");
                dcerpc_free_data(dce, rep);
                free(name);
                walk_continue(parent);
                return;
        }
        if (rep->status != ERROR_SUCCESS) {
                fprintf(stderr, "%*s# open failed 0x%x: %s\n",
                        parent->depth * 2, "", rep->status,
                        name ? name : "");
                dcerpc_free_data(dce, rep);
                free(name);
                walk_continue(parent);
                return;
        }

        print_key(parent->depth, name);
        free(name);

        child = walk_new(&rep->phkResult, parent->depth + 1, parent);
        dcerpc_free_data(dce, rep);
        walk_continue(child);
}

static void
walk_open_child(struct walk *parent, const char *name)
{
        struct winreg_BaseRegOpenKey_req req;

        free(parent->pending);
        parent->pending = strdup(name);
        if (parent->pending == NULL) {
                fprintf(stderr, "out of memory\n");
                exit(10);
        }

        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, &parent->hKey, sizeof(req.hKey));
        req.lpSubKey = parent->pending;
        req.dwOptions = 0;
        req.samDesired = WINREG_WALK_ACCESS;

        if (dcerpc_call_async(g_dce,
                              WINREG_BASEREGOPENKEY,
                              winreg_BaseRegOpenKey_req_coder, &req,
                              winreg_BaseRegOpenKey_rep_coder,
                              sizeof(struct winreg_BaseRegOpenKey_rep),
                              op_cb, parent) != 0) {
                fprintf(stderr, "dcerpc_call_async OpenKey: %s\n",
                        dcerpc_get_error(g_dce));
                exit(10);
        }
}

static void
ev_cb(struct dcerpc_context *dce, int status,
      void *command_data, void *cb_data)
{
        struct winreg_BaseRegEnumValue_rep *rep = command_data;
        struct walk *w = cb_data;
        uint32_t data_len;

        if (status) {
                dcerpc_free_data(dce, rep);
                fail_rpc(dce, "BaseRegEnumValue", status);
        }

        if (rep->status == ERROR_NO_MORE_ITEMS) {
                dcerpc_free_data(dce, rep);
                /* switch to subkey enumeration */
                w->phase = WALK_PHASE_KEYS;
                w->index = 0;
                walk_enum_keys(w);
                return;
        }
        if (rep->status == ERROR_MORE_DATA) {
                /* buffer too small — skip this value */
                fprintf(stderr, "%*s# value data too large at index %u\n",
                        w->depth * 2, "", w->index);
                dcerpc_free_data(dce, rep);
                w->index++;
                walk_enum_values(w);
                return;
        }
        if (rep->status == ERROR_ACCESS_DENIED) {
                fprintf(stderr, "%*s# value enumerate access denied\n",
                        (w->depth > 0 ? w->depth - 1 : 0) * 2, "");
                dcerpc_free_data(dce, rep);
                w->phase = WALK_PHASE_KEYS;
                w->index = 0;
                walk_enum_keys(w);
                return;
        }
        if (rep->status != ERROR_SUCCESS) {
                fprintf(stderr, "BaseRegEnumValue status 0x%x at index %u\n",
                        rep->status, w->index);
                dcerpc_free_data(dce, rep);
                w->phase = WALK_PHASE_KEYS;
                w->index = 0;
                walk_enum_keys(w);
                return;
        }

        data_len = rep->cbLen ? rep->cbLen : rep->cbData;
        print_value(w->depth,
                    rep->lpValueName,
                    rep->type,
                    rep->lpData,
                    data_len);
        dcerpc_free_data(dce, rep);
        w->index++;
        walk_enum_values(w);
}

static void
walk_enum_values(struct walk *w)
{
        struct winreg_BaseRegEnumValue_req req;

        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, &w->hKey, sizeof(req.hKey));
        req.dwIndex = w->index;
        req.lpValueName = NULL;
        req.lpValueName_max_length = 0;
        req.type = 0;
        req.lpData = w->valbuf;
        req.cbData = VALUE_DATA_BUF;
        req.cbLen = 0;

        if (dcerpc_call_async(g_dce,
                              WINREG_BASEREGENUMVALUE,
                              winreg_BaseRegEnumValue_req_coder, &req,
                              winreg_BaseRegEnumValue_rep_coder,
                              sizeof(struct winreg_BaseRegEnumValue_rep),
                              ev_cb, w) != 0) {
                fprintf(stderr, "dcerpc_call_async EnumValue: %s\n",
                        dcerpc_get_error(g_dce));
                exit(10);
        }
}

static void
en_cb(struct dcerpc_context *dce, int status,
      void *command_data, void *cb_data)
{
        struct winreg_BaseRegEnumKey_rep *rep = command_data;
        struct walk *w = cb_data;
        char *name;

        if (status) {
                dcerpc_free_data(dce, rep);
                fail_rpc(dce, "BaseRegEnumKey", status);
        }

        if (rep->status == ERROR_NO_MORE_ITEMS) {
                dcerpc_free_data(dce, rep);
                walk_close(w);
                return;
        }
        if (rep->status == ERROR_ACCESS_DENIED) {
                fprintf(stderr, "%*s# key enumerate access denied\n",
                        (w->depth > 0 ? w->depth - 1 : 0) * 2, "");
                dcerpc_free_data(dce, rep);
                walk_close(w);
                return;
        }
        if (rep->status != ERROR_SUCCESS) {
                fprintf(stderr, "BaseRegEnumKey status 0x%x at index %u\n",
                        rep->status, w->index);
                dcerpc_free_data(dce, rep);
                walk_close(w);
                return;
        }

        name = rep->lpName ? rep->lpName : "";
        /*
         * Advance index before open so when we resume this walk after the
         * child closes we request the next sibling.
         */
        w->index++;
        walk_open_child(w, name);
        dcerpc_free_data(dce, rep);
}

static void
walk_enum_keys(struct walk *w)
{
        struct winreg_BaseRegEnumKey_req req;

        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, &w->hKey, sizeof(req.hKey));
        req.dwIndex = w->index;
        req.lpName = NULL;
        req.lpName_max_length = 0; /* coder default 1024 */
        req.lpClass = NULL;
        req.lpClass_max_length = 0;
        req.lpftLastWriteTime = NULL;

        if (dcerpc_call_async(g_dce,
                              WINREG_BASEREGENUMKEY,
                              winreg_BaseRegEnumKey_req_coder, &req,
                              winreg_BaseRegEnumKey_rep_coder,
                              sizeof(struct winreg_BaseRegEnumKey_rep),
                              en_cb, w) != 0) {
                fprintf(stderr, "dcerpc_call_async EnumKey: %s\n",
                        dcerpc_get_error(g_dce));
                exit(10);
        }
}

static void
walk_continue(struct walk *w)
{
        if (w->phase == WALK_PHASE_VALUES) {
                walk_enum_values(w);
        } else {
                walk_enum_keys(w);
        }
}

static void
open_root_cb(struct dcerpc_context *dce, int status,
             void *command_data, void *cb_data)
{
        struct winreg_OpenRootKey_rep *rep = command_data;
        const char *label = cb_data;
        struct walk *root;

        if (status) {
                dcerpc_free_data(dce, rep);
                fail_rpc(dce, label, status);
        }
        if (rep->status != ERROR_SUCCESS) {
                fprintf(stderr, "%s status 0x%x\n", label, rep->status);
                dcerpc_free_data(dce, rep);
                /* Skip this hive and try the next */
                open_next_hive();
                return;
        }

        print_key(0, label);
        root = walk_new(&rep->phKey, 1, NULL);
        dcerpc_free_data(dce, rep);
        walk_continue(root);
}

static void
open_next_hive(void)
{
        struct winreg_OpenRootKey_req req;
        int opnum;
        dcerpc_coder req_coder, rep_coder;
        int rep_size;
        const char *label;

        memset(&req, 0, sizeof(req));
        req.ServerName = NULL;
        req.samDesired = WINREG_WALK_ACCESS;

        switch (g_next_hive) {
        case 0:
                label = "HKCR";
                opnum = WINREG_OPENCLASSESROOT;
                req_coder = winreg_OpenClassesRoot_req_coder;
                rep_coder = winreg_OpenClassesRoot_rep_coder;
                rep_size = sizeof(struct winreg_OpenClassesRoot_rep);
                g_next_hive = 1;
                break;
        case 1:
                label = "HKCU";
                opnum = WINREG_OPENCURRENTUSER;
                req_coder = winreg_OpenCurrentUser_req_coder;
                rep_coder = winreg_OpenCurrentUser_rep_coder;
                rep_size = sizeof(struct winreg_OpenCurrentUser_rep);
                g_next_hive = 2;
                break;
        case 2:
                label = "HKLM";
                opnum = WINREG_OPENLOCALMACHINE;
                req_coder = winreg_OpenLocalMachine_req_coder;
                rep_coder = winreg_OpenLocalMachine_rep_coder;
                rep_size = sizeof(struct winreg_OpenLocalMachine_rep);
                g_next_hive = 3;
                break;
        case 3:
                label = "HKU";
                opnum = WINREG_OPENUSERS;
                req_coder = winreg_OpenUsers_req_coder;
                rep_coder = winreg_OpenUsers_rep_coder;
                rep_size = sizeof(struct winreg_OpenUsers_rep);
                g_next_hive = 4;
                break;
        case 4:
                label = "HKCC";
                opnum = WINREG_OPENCURRENTCONFIG;
                req_coder = winreg_OpenCurrentConfig_req_coder;
                rep_coder = winreg_OpenCurrentConfig_rep_coder;
                rep_size = sizeof(struct winreg_OpenCurrentConfig_rep);
                g_next_hive = 5;
                break;
        default:
                is_finished = 1;
                return;
        }

        if (dcerpc_call_async(g_dce, opnum, req_coder, &req, rep_coder,
                              rep_size, open_root_cb,
                              discard_const(label)) != 0) {
                fprintf(stderr, "dcerpc_call_async %s: %s\n",
                        label, dcerpc_get_error(g_dce));
                exit(10);
        }
}

static void
co_cb(struct dcerpc_context *dce, int status,
      void *command_data, void *cb_data)
{
        if (status != SMB2_STATUS_SUCCESS) {
                fprintf(stderr, "failed to connect to winreg (%s) %s\n",
                        strerror(-status), dcerpc_get_error(dce));
                exit(10);
        }

        g_next_hive = 0;
        open_next_hive();
}

int
main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct pollfd pfd;

        if (argc < 2) {
                usage();
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                exit(1);
        }

        url = smb2_parse_url(smb2, argv[1]);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(smb2));
                exit(1);
        }
        if (url->user) {
                smb2_set_user(smb2, url->user);
        }
        if (url->domain) {
                smb2_set_domain(smb2, url->domain);
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

        if (smb2_connect_share(smb2, url->server, "IPC$", NULL) < 0) {
                fprintf(stderr, "Failed to connect to IPC$. %s\n",
                        smb2_get_error(smb2));
                exit(10);
        }

        g_dce = dcerpc_create_context(smb2);
        if (g_dce == NULL) {
                fprintf(stderr, "Failed to create dce context. %s\n",
                        smb2_get_error(smb2));
                exit(10);
        }

        if (dcerpc_connect_context_async(g_dce, "winreg", &winreg_interface,
                                         co_cb, NULL) != 0) {
                fprintf(stderr, "Failed to connect dce context. %s\n",
                        smb2_get_error(smb2));
                exit(10);
        }

        while (!is_finished) {
                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);

                if (poll(&pfd, 1, 1000) < 0) {
                        fprintf(stderr, "Poll failed\n");
                        exit(10);
                }
                if (pfd.revents == 0) {
                        continue;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        fprintf(stderr, "smb2_service failed with : %s\n",
                                smb2_get_error(smb2));
                        break;
                }
        }

        dcerpc_destroy_context(g_dce);
        smb2_disconnect_share(smb2);
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);

        return 0;
}
