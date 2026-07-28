/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * ncurses TUI for browsing predefined registry hives via MS-RRP
 * (winreg on IPC$):
 *   HKEY_CLASSES_ROOT
 *   HKEY_CURRENT_USER
 *   HKEY_LOCAL_MACHINE
 *   HKEY_USERS
 *   HKEY_CURRENT_CONFIG
 *
 * Usage:
 *   winreg-tui smb://[<domain;][<user>@]<host>/
 *
 * Keys: press '?' in the UI for the full help screen.
 *
 * Lines with children show '>' when collapsed and 'v' when expanded.
 * Indentation is two spaces per depth level (same as smb2-winreg-enum).
 */

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <ncurses.h>
#include <poll.h>
#include <stdarg.h>
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

#define ERROR_SUCCESS           0x00000000
#define ERROR_ACCESS_DENIED     0x00000005
#define ERROR_MORE_DATA         0x000000ea
#define ERROR_NO_MORE_ITEMS     0x00000103

/* Read + write + DELETE so CreateKey / DeleteKey work on opened handles */
#define WINREG_WALK_ACCESS      (KEY_READ | KEY_WRITE | WINREG_DELETE)

#define MAX_VISIBLE  8192
#define STATUS_LEN   256
#define VALUE_DATA_BUF 65536

struct node {
        char *name;
        int depth;
        int expanded;
        int loaded;              /* children enumerated */
        int has_children;        /* known after load; 1 before load (assume) */
        int is_value;            /* registry value (leaf), not a subkey */
        uint32_t reg_type;
        char *value_text;        /* formatted value for display */
        int has_handle;
        struct dcerpc_context_handle hKey;
        struct node *parent;
        struct node **children;
        int nchildren;
        int achildren;
};

static struct smb2_context *g_smb2;
static struct dcerpc_context *g_dce;
static struct node *g_roots[5];  /* CLASSES_ROOT, CURRENT_USER, LOCAL_MACHINE, USERS, CURRENT_CONFIG */
static int g_nroots;
static struct node *g_visible[MAX_VISIBLE];
static int g_nvisible;
static int g_sel;                /* index into g_visible */
static int g_top;                /* first visible row in window */
static char g_status[STATUS_LEN];
static int g_ui_active;

/* ---- single-flight RPC wait ---- */
static int rpc_done;
static int rpc_transport_status;
static uint32_t rpc_win_status;
static void *rpc_rep;

static void
set_status(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vsnprintf(g_status, sizeof(g_status), fmt, ap);
        va_end(ap);
}

static void
rpc_pump(void)
{
        struct pollfd pfd;

        while (!rpc_done) {
                pfd.fd = smb2_get_fd(g_smb2);
                pfd.events = smb2_which_events(g_smb2);
                if (poll(&pfd, 1, 1000) < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        rpc_transport_status = -errno;
                        rpc_done = 1;
                        return;
                }
                if (pfd.revents == 0) {
                        continue;
                }
                if (smb2_service(g_smb2, pfd.revents) < 0) {
                        rpc_transport_status = -EIO;
                        rpc_done = 1;
                        return;
                }
        }
}

static void
rpc_generic_cb(struct dcerpc_context *dce, int status,
               void *command_data, void *cb_data)
{
        rpc_transport_status = status;
        rpc_rep = command_data;
        rpc_done = 1;
}

static int
rpc_call(int opnum,
         dcerpc_coder req_coder, void *req,
         dcerpc_coder rep_coder, int rep_size,
         void **repp)
{
        rpc_done = 0;
        rpc_transport_status = 0;
        rpc_win_status = 0;
        rpc_rep = NULL;

        if (dcerpc_call_async(g_dce, opnum, req_coder, req,
                              rep_coder, rep_size,
                              rpc_generic_cb, NULL) != 0) {
                set_status("RPC submit failed: %s", dcerpc_get_error(g_dce));
                return -1;
        }
        rpc_pump();
        if (rpc_transport_status) {
                set_status("RPC transport error: %s",
                           dcerpc_get_error(g_dce));
                if (rpc_rep) {
                        dcerpc_free_data(g_dce, rpc_rep);
                        rpc_rep = NULL;
                }
                return -1;
        }
        *repp = rpc_rep;
        return 0;
}

/* ---- tree nodes ---- */

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

static char *
format_reg_value(uint32_t type, const uint8_t *data, uint32_t len)
{
        char buf[512];

        switch (type) {
        case REG_SZ:
        case REG_EXPAND_SZ: {
                char *s = utf16le_to_utf8(data, len);
                char *out;

                if (s == NULL) {
                        return strdup("\"\"");
                }
                if (asprintf(&out, "\"%s\"", s) < 0) {
                        free(s);
                        return NULL;
                }
                free(s);
                return out;
        }
        case REG_DWORD:
                if (len >= 4 && data) {
                        uint32_t v = (uint32_t)data[0] |
                                ((uint32_t)data[1] << 8) |
                                ((uint32_t)data[2] << 16) |
                                ((uint32_t)data[3] << 24);
                        snprintf(buf, sizeof(buf), "0x%08x (%u)", v, v);
                        return strdup(buf);
                }
                return strdup("(short)");
        case REG_DWORD_BIG_ENDIAN:
                if (len >= 4 && data) {
                        uint32_t v = ((uint32_t)data[0] << 24) |
                                ((uint32_t)data[1] << 16) |
                                ((uint32_t)data[2] << 8) |
                                (uint32_t)data[3];
                        snprintf(buf, sizeof(buf), "0x%08x (%u)", v, v);
                        return strdup(buf);
                }
                return strdup("(short)");
        case REG_QWORD:
                if (len >= 8 && data) {
                        uint64_t v = 0;
                        int i;
                        for (i = 7; i >= 0; i--) {
                                v = (v << 8) | data[i];
                        }
                        snprintf(buf, sizeof(buf), "0x%016" PRIx64, v);
                        return strdup(buf);
                }
                return strdup("(short)");
        case REG_MULTI_SZ: {
                uint32_t off = 0;
                char *acc = strdup("{");
                int first = 1;

                if (acc == NULL) {
                        return NULL;
                }
                while (off + 2 <= len) {
                        uint32_t start = off;
                        char *s, *nacc;

                        while (off + 2 <= len) {
                                if (data[off] == 0 && data[off + 1] == 0) {
                                        break;
                                }
                                off += 2;
                        }
                        if (off == start) {
                                break;
                        }
                        s = utf16le_to_utf8(data + start, off - start);
                        if (asprintf(&nacc, "%s%s\"%s\"", acc,
                                     first ? "" : ", ", s ? s : "") < 0) {
                                free(s);
                                free(acc);
                                return NULL;
                        }
                        free(s);
                        free(acc);
                        acc = nacc;
                        first = 0;
                        off += 2;
                }
                {
                        char *nacc;
                        if (asprintf(&nacc, "%s}", acc) < 0) {
                                free(acc);
                                return NULL;
                        }
                        free(acc);
                        return nacc;
                }
        }
        default: {
                uint32_t i, n = len < 24 ? len : 24;
                size_t pos = 0;

                pos = (size_t)snprintf(buf, sizeof(buf), "hex:");
                for (i = 0; i < n && pos + 3 < sizeof(buf); i++) {
                        pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos,
                                                "%02x", data ? data[i] : 0);
                }
                if (len > n && pos + 16 < sizeof(buf)) {
                        snprintf(buf + pos, sizeof(buf) - pos,
                                 "...(%u)", len);
                }
                return strdup(buf);
        }
        }
}

static struct node *
node_new(const char *name, int depth, struct node *parent)
{
        struct node *n;

        n = calloc(1, sizeof(*n));
        if (n == NULL) {
                return NULL;
        }
        n->name = strdup(name ? name : "");
        if (n->name == NULL) {
                free(n);
                return NULL;
        }
        n->depth = depth;
        n->parent = parent;
        n->has_children = 1; /* assume until loaded empty */
        return n;
}

static struct node *
node_new_value(const char *name, int depth, struct node *parent,
               uint32_t type, const uint8_t *data, uint32_t len)
{
        struct node *n;
        const char *nm = (name && name[0]) ? name : "(Default)";

        n = node_new(nm, depth, parent);
        if (n == NULL) {
                return NULL;
        }
        n->is_value = 1;
        n->has_children = 0;
        n->loaded = 1;
        n->reg_type = type;
        n->value_text = format_reg_value(type, data, len);
        return n;
}

static void
node_close_handle(struct node *n)
{
        struct winreg_BaseRegCloseKey_req req;
        struct winreg_BaseRegCloseKey_rep *rep;

        if (!n->has_handle) {
                return;
        }
        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, &n->hKey, sizeof(req.hKey));
        if (rpc_call(WINREG_BASEREGCLOSEKEY,
                     winreg_BaseRegCloseKey_req_coder, &req,
                     winreg_BaseRegCloseKey_rep_coder,
                     sizeof(*rep), (void **)&rep) == 0) {
                dcerpc_free_data(g_dce, rep);
        }
        n->has_handle = 0;
        memset(&n->hKey, 0, sizeof(n->hKey));
}

static void
node_free(struct node *n)
{
        int i;

        if (n == NULL) {
                return;
        }
        for (i = 0; i < n->nchildren; i++) {
                node_free(n->children[i]);
        }
        free(n->children);
        node_close_handle(n);
        free(n->name);
        free(n->value_text);
        free(n);
}

static int
node_add_child(struct node *parent, struct node *child)
{
        struct node **p;

        if (parent->nchildren >= parent->achildren) {
                int na = parent->achildren ? parent->achildren * 2 : 8;

                p = realloc(parent->children, (size_t)na * sizeof(*p));
                if (p == NULL) {
                        return -1;
                }
                parent->children = p;
                parent->achildren = na;
        }
        parent->children[parent->nchildren++] = child;
        return 0;
}

static void
node_free_children(struct node *n)
{
        int i;

        for (i = 0; i < n->nchildren; i++) {
                node_free(n->children[i]);
        }
        free(n->children);
        n->children = NULL;
        n->nchildren = 0;
        n->achildren = 0;
        n->loaded = 0;
        n->has_children = 1;
}

static int
node_ensure_handle(struct node *n)
{
        struct winreg_BaseRegOpenKey_req req;
        struct winreg_BaseRegOpenKey_rep *rep;

        if (n->has_handle) {
                return 0;
        }
        if (n->parent == NULL || !n->parent->has_handle) {
                set_status("No parent handle for %s", n->name);
                return -1;
        }

        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, &n->parent->hKey, sizeof(req.hKey));
        req.lpSubKey = n->name;
        req.dwOptions = 0;
        req.samDesired = WINREG_WALK_ACCESS;

        if (rpc_call(WINREG_BASEREGOPENKEY,
                     winreg_BaseRegOpenKey_req_coder, &req,
                     winreg_BaseRegOpenKey_rep_coder,
                     sizeof(*rep), (void **)&rep) != 0) {
                return -1;
        }
        if (rep->status == ERROR_ACCESS_DENIED) {
                set_status("Access denied: %s", n->name);
                dcerpc_free_data(g_dce, rep);
                n->has_children = 0;
                n->loaded = 1;
                return -1;
        }
        if (rep->status != ERROR_SUCCESS) {
                set_status("OpenKey 0x%x: %s", rep->status, n->name);
                dcerpc_free_data(g_dce, rep);
                n->has_children = 0;
                n->loaded = 1;
                return -1;
        }
        memcpy(&n->hKey, &rep->phkResult, sizeof(n->hKey));
        n->has_handle = 1;
        dcerpc_free_data(g_dce, rep);
        return 0;
}

static int
node_load_children(struct node *n)
{
        struct winreg_BaseRegEnumKey_req kreq;
        struct winreg_BaseRegEnumKey_rep *krep;
        struct winreg_BaseRegEnumValue_req vreq;
        struct winreg_BaseRegEnumValue_rep *vrep;
        uint8_t *valbuf;
        uint32_t index;
        int nvalues = 0;
        int nkeys = 0;

        if (n->loaded) {
                return 0;
        }
        if (n->is_value) {
                return 0;
        }
        if (node_ensure_handle(n) != 0) {
                return -1;
        }

        set_status("Loading %s ...", n->name);

        valbuf = malloc(VALUE_DATA_BUF);
        if (valbuf == NULL) {
                set_status("Out of memory");
                return -1;
        }

        /* Values first */
        for (index = 0; ; index++) {
                uint32_t data_len;
                struct node *c;

                memset(&vreq, 0, sizeof(vreq));
                memcpy(&vreq.hKey, &n->hKey, sizeof(vreq.hKey));
                vreq.dwIndex = index;
                vreq.lpValueName = NULL;
                vreq.lpValueName_max_length = 0;
                vreq.type = 0;
                vreq.lpData = valbuf;
                vreq.cbData = VALUE_DATA_BUF;
                vreq.cbLen = 0;

                if (rpc_call(WINREG_BASEREGENUMVALUE,
                             winreg_BaseRegEnumValue_req_coder, &vreq,
                             winreg_BaseRegEnumValue_rep_coder,
                             sizeof(*vrep), (void **)&vrep) != 0) {
                        free(valbuf);
                        node_free_children(n);
                        return -1;
                }
                if (vrep->status == ERROR_NO_MORE_ITEMS) {
                        dcerpc_free_data(g_dce, vrep);
                        break;
                }
                if (vrep->status == ERROR_MORE_DATA) {
                        dcerpc_free_data(g_dce, vrep);
                        continue; /* skip oversized */
                }
                if (vrep->status == ERROR_ACCESS_DENIED) {
                        dcerpc_free_data(g_dce, vrep);
                        break;
                }
                if (vrep->status != ERROR_SUCCESS) {
                        dcerpc_free_data(g_dce, vrep);
                        break;
                }
                data_len = vrep->cbLen ? vrep->cbLen : vrep->cbData;
                c = node_new_value(vrep->lpValueName, n->depth + 1, n,
                                   vrep->type, vrep->lpData, data_len);
                dcerpc_free_data(g_dce, vrep);
                if (c == NULL || node_add_child(n, c) != 0) {
                        node_free(c);
                        free(valbuf);
                        set_status("Out of memory");
                        return -1;
                }
                nvalues++;
        }
        free(valbuf);

        /* Then subkeys */
        for (index = 0; ; index++) {
                struct node *c;
                const char *nm;

                memset(&kreq, 0, sizeof(kreq));
                memcpy(&kreq.hKey, &n->hKey, sizeof(kreq.hKey));
                kreq.dwIndex = index;
                kreq.lpName = NULL;
                kreq.lpName_max_length = 0;
                kreq.lpClass = NULL;
                kreq.lpClass_max_length = 0;
                kreq.lpftLastWriteTime = NULL;

                if (rpc_call(WINREG_BASEREGENUMKEY,
                             winreg_BaseRegEnumKey_req_coder, &kreq,
                             winreg_BaseRegEnumKey_rep_coder,
                             sizeof(*krep), (void **)&krep) != 0) {
                        node_free_children(n);
                        return -1;
                }
                if (krep->status == ERROR_NO_MORE_ITEMS) {
                        dcerpc_free_data(g_dce, krep);
                        break;
                }
                if (krep->status == ERROR_ACCESS_DENIED) {
                        set_status("Enumerate access denied: %s", n->name);
                        dcerpc_free_data(g_dce, krep);
                        break;
                }
                if (krep->status != ERROR_SUCCESS) {
                        set_status("EnumKey 0x%x at %u under %s",
                                   krep->status, index, n->name);
                        dcerpc_free_data(g_dce, krep);
                        break;
                }
                nm = krep->lpName ? krep->lpName : "";
                c = node_new(nm, n->depth + 1, n);
                dcerpc_free_data(g_dce, krep);
                if (c == NULL || node_add_child(n, c) != 0) {
                        node_free(c);
                        set_status("Out of memory");
                        return -1;
                }
                nkeys++;
        }

        n->loaded = 1;
        n->has_children = n->nchildren > 0;
        set_status("%s: %d value%s, %d subkey%s", n->name,
                   nvalues, nvalues == 1 ? "" : "s",
                   nkeys, nkeys == 1 ? "" : "s");
        return 0;
}

static void
node_collapse(struct node *n)
{
        if (!n->expanded) {
                return;
        }
        /* node_free closes any open child handles recursively */
        node_free_children(n);
        n->expanded = 0;
        /* keep n's own handle so re-expand only re-enums, no re-open */
}

static int
node_expand(struct node *n)
{
        if (n->is_value) {
                return 0;
        }
        if (n->expanded) {
                return 0;
        }
        if (node_load_children(n) != 0) {
                return -1;
        }
        if (!n->has_children) {
                n->expanded = 0;
                return 0;
        }
        n->expanded = 1;
        return 0;
}

/* ---- visible list / draw ---- */

static void
visible_add(struct node *n)
{
        int i;

        if (g_nvisible >= MAX_VISIBLE) {
                return;
        }
        g_visible[g_nvisible++] = n;
        if (n->expanded) {
                for (i = 0; i < n->nchildren; i++) {
                        visible_add(n->children[i]);
                }
        }
}

static void
rebuild_visible(void)
{
        struct node *sel = (g_sel >= 0 && g_sel < g_nvisible) ?
                g_visible[g_sel] : NULL;
        int i;

        g_nvisible = 0;
        for (i = 0; i < g_nroots; i++) {
                if (g_roots[i]) {
                        visible_add(g_roots[i]);
                }
        }
        g_sel = 0;
        if (sel) {
                for (i = 0; i < g_nvisible; i++) {
                        if (g_visible[i] == sel) {
                                g_sel = i;
                                break;
                        }
                }
        }
}

static char
node_marker(struct node *n)
{
        if (n->is_value || !n->has_children) {
                return ' ';
        }
        return n->expanded ? 'v' : '>';
}

static void
draw_ui(void)
{
        int rows, cols;
        int list_rows;
        int i, row;

        getmaxyx(stdscr, rows, cols);
        list_rows = rows > 2 ? rows - 2 : 1;

        if (g_sel < g_top) {
                g_top = g_sel;
        }
        if (g_sel >= g_top + list_rows) {
                g_top = g_sel - list_rows + 1;
        }
        if (g_top < 0) {
                g_top = 0;
        }

        erase();

        mvprintw(0, 0, "winreg-tui  [?]=help  [Space]  "
                 "[k]key [v]val [e]edit [d]del [q]quit");
        if (cols > 2) {
                mvhline(1, 0, ACS_HLINE, cols);
        }

        for (i = 0; i < list_rows; i++) {
                int vi = g_top + i;
                struct node *n;
                char marker;
                int attr = 0;

                row = i + 2;
                if (vi >= g_nvisible) {
                        break;
                }
                n = g_visible[vi];
                marker = node_marker(n);
                if (vi == g_sel) {
                        attr = A_REVERSE;
                }
                attron(attr);
                /* depth*2 spaces, then marker, then name */
                if (n->is_value) {
                        mvprintw(row, 0, "%*s%c %s (%s) = %s",
                                 n->depth * 2, "",
                                 marker,
                                 n->name,
                                 reg_type_name(n->reg_type),
                                 n->value_text ? n->value_text : "");
                } else {
                        mvprintw(row, 0, "%*s%c %s",
                                 n->depth * 2, "",
                                 marker,
                                 n->name);
                }
                attroff(attr);
                /* clear rest of line for reverse video cleanliness */
                if (cols > 0) {
                        int y, x;

                        getyx(stdscr, y, x);
                        (void)y;
                        if (x < cols) {
                                printw("%*s", cols - x, "");
                        }
                }
        }

        if (rows > 0) {
                mvprintw(rows - 1, 0, "%.*s", cols > 0 ? cols - 1 : 0, g_status);
        }
        refresh();
}

/* ---- connection ---- */

static int g_connect_done;
static int g_connect_status;

static void
connect_cb(struct dcerpc_context *dce, int status,
           void *command_data, void *cb_data)
{
        (void)dce;
        (void)command_data;
        (void)cb_data;
        g_connect_status = status;
        g_connect_done = 1;
}

static int
open_hive_root(int opnum, dcerpc_coder req_coder, dcerpc_coder rep_coder,
               int rep_size, const char *label, struct node **out)
{
        struct winreg_OpenRootKey_req req;
        struct winreg_OpenRootKey_rep *rep;
        struct node *n;

        memset(&req, 0, sizeof(req));
        req.ServerName = NULL;
        req.samDesired = WINREG_WALK_ACCESS;
        if (rpc_call(opnum, req_coder, &req, rep_coder, rep_size,
                     (void **)&rep) != 0) {
                fprintf(stderr, "%s failed\n", label);
                return -1;
        }
        if (rep->status != ERROR_SUCCESS) {
                fprintf(stderr, "%s status 0x%x\n", label, rep->status);
                dcerpc_free_data(g_dce, rep);
                return -1;
        }
        n = node_new(label, 0, NULL);
        if (n == NULL) {
                dcerpc_free_data(g_dce, rep);
                fprintf(stderr, "out of memory\n");
                return -1;
        }
        memcpy(&n->hKey, &rep->phKey, sizeof(n->hKey));
        n->has_handle = 1;
        n->expanded = 0;
        n->loaded = 0;
        n->has_children = 1;
        dcerpc_free_data(g_dce, rep);
        *out = n;
        return 0;
}

static int
connect_winreg(const char *url_str)
{
        struct smb2_url *url;
        struct pollfd pfd;
        struct node *n;

        g_smb2 = smb2_init_context();
        if (g_smb2 == NULL) {
                fprintf(stderr, "Failed to init smb2 context\n");
                return -1;
        }
        url = smb2_parse_url(g_smb2, url_str);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(g_smb2));
                return -1;
        }
        if (url->user) {
                smb2_set_user(g_smb2, url->user);
        }
        if (url->domain) {
                smb2_set_domain(g_smb2, url->domain);
        }
        smb2_set_security_mode(g_smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

        if (smb2_connect_share(g_smb2, url->server, "IPC$", NULL) < 0) {
                fprintf(stderr, "IPC$ connect failed: %s\n",
                        smb2_get_error(g_smb2));
                smb2_destroy_url(url);
                return -1;
        }
        smb2_destroy_url(url);

        g_dce = dcerpc_create_context(g_smb2);
        if (g_dce == NULL) {
                fprintf(stderr, "dcerpc_create_context failed: %s\n",
                        smb2_get_error(g_smb2));
                return -1;
        }

        g_connect_done = 0;
        g_connect_status = 0;
        if (dcerpc_connect_context_async(g_dce, "winreg", &winreg_interface,
                                         connect_cb, NULL) != 0) {
                fprintf(stderr, "winreg connect failed: %s\n",
                        smb2_get_error(g_smb2));
                return -1;
        }
        while (!g_connect_done) {
                pfd.fd = smb2_get_fd(g_smb2);
                pfd.events = smb2_which_events(g_smb2);
                if (poll(&pfd, 1, 1000) < 0) {
                        continue;
                }
                if (pfd.revents && smb2_service(g_smb2, pfd.revents) < 0) {
                        fprintf(stderr, "smb2_service: %s\n",
                                smb2_get_error(g_smb2));
                        return -1;
                }
        }
        if (g_connect_status != SMB2_STATUS_SUCCESS) {
                fprintf(stderr, "winreg bind failed (%d)\n", g_connect_status);
                return -1;
        }

        g_nroots = 0;
        if (open_hive_root(WINREG_OPENCLASSESROOT,
                           winreg_OpenClassesRoot_req_coder,
                           winreg_OpenClassesRoot_rep_coder,
                           sizeof(struct winreg_OpenClassesRoot_rep),
                           "HKEY_CLASSES_ROOT", &n) == 0) {
                g_roots[g_nroots++] = n;
        }
        if (open_hive_root(WINREG_OPENCURRENTUSER,
                           winreg_OpenCurrentUser_req_coder,
                           winreg_OpenCurrentUser_rep_coder,
                           sizeof(struct winreg_OpenCurrentUser_rep),
                           "HKEY_CURRENT_USER", &n) == 0) {
                g_roots[g_nroots++] = n;
        }
        if (open_hive_root(WINREG_OPENLOCALMACHINE,
                           winreg_OpenLocalMachine_req_coder,
                           winreg_OpenLocalMachine_rep_coder,
                           sizeof(struct winreg_OpenLocalMachine_rep),
                           "HKEY_LOCAL_MACHINE", &n) == 0) {
                g_roots[g_nroots++] = n;
        }
        if (open_hive_root(WINREG_OPENUSERS,
                           winreg_OpenUsers_req_coder,
                           winreg_OpenUsers_rep_coder,
                           sizeof(struct winreg_OpenUsers_rep),
                           "HKEY_USERS", &n) == 0) {
                g_roots[g_nroots++] = n;
        }
        if (open_hive_root(WINREG_OPENCURRENTCONFIG,
                           winreg_OpenCurrentConfig_req_coder,
                           winreg_OpenCurrentConfig_rep_coder,
                           sizeof(struct winreg_OpenCurrentConfig_rep),
                           "HKEY_CURRENT_CONFIG", &n) == 0) {
                g_roots[g_nroots++] = n;
        }
        if (g_nroots == 0) {
                fprintf(stderr, "Failed to open any registry hive\n");
                return -1;
        }

        rebuild_visible();
        g_sel = 0;
        set_status("Connected. Space expands a hive.");
        return 0;
}

static void
cleanup(void)
{
        int i;

        if (g_ui_active) {
                endwin();
                g_ui_active = 0;
        }
        for (i = 0; i < g_nroots; i++) {
                node_free(g_roots[i]);
                g_roots[i] = NULL;
        }
        g_nroots = 0;
        if (g_dce) {
                dcerpc_destroy_context(g_dce);
                g_dce = NULL;
        }
        if (g_smb2) {
                smb2_disconnect_share(g_smb2);
                smb2_destroy_context(g_smb2);
                g_smb2 = NULL;
        }
}

static int
usage(void)
{
        fprintf(stderr, "Usage:\n"
                "winreg-tui <smb2-url>\n\n"
                "URL format: smb://[<domain;][<username>@]<host>[:<port>]/\n"
                "Browse HKEY_CLASSES_ROOT, HKEY_CURRENT_USER,\n"
                "HKEY_LOCAL_MACHINE, HKEY_USERS, and HKEY_CURRENT_CONFIG\n"
                "on IPC$/winreg (ncurses).\n"
                "Press '?' in the UI for key bindings.\n");
        return 1;
}

/*
 * Prompt on the status line.
 * Returns 0 on Enter (buf may be empty after trim), -1 if cancelled with ESC.
 */
static int
prompt_string(const char *prompt, char *buf, size_t buflen)
{
        int rows, cols;
        int len = 0;
        int prompt_len;
        int ch;

        if (buflen < 2) {
                return -1;
        }
        getmaxyx(stdscr, rows, cols);
        prompt_len = (int)strlen(prompt);
        buf[0] = '\0';
        noecho();
        curs_set(1);
        cbreak();
        keypad(stdscr, TRUE);

        for (;;) {
                mvprintw(rows - 1, 0, "%s%.*s", prompt, (int)buflen - 1, buf);
                clrtoeol();
                if (prompt_len + len < cols) {
                        move(rows - 1, prompt_len + len);
                }
                refresh();

                ch = getch();
                if (ch == 27) {
                        /* ESC — abort without accepting input */
                        buf[0] = '\0';
                        curs_set(0);
                        return -1;
                }
                if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
                        while (len > 0 && buf[len - 1] == ' ') {
                                buf[--len] = '\0';
                        }
                        while (buf[0] == ' ') {
                                memmove(buf, buf + 1, strlen(buf));
                                len = (int)strlen(buf);
                        }
                        curs_set(0);
                        return 0;
                }
                if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b') {
                        if (len > 0) {
                                buf[--len] = '\0';
                        }
                        continue;
                }
                if (ch >= 32 && ch < 127 && (size_t)len + 1 < buflen) {
                        if (cols > 0 && prompt_len + len + 1 >= cols) {
                                continue;
                        }
                        buf[len++] = (char)ch;
                        buf[len] = '\0';
                }
        }
}

static void
close_handle_only(struct dcerpc_context_handle *h)
{
        struct winreg_BaseRegCloseKey_req req;
        struct winreg_BaseRegCloseKey_rep *rep;

        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, h, sizeof(req.hKey));
        if (rpc_call(WINREG_BASEREGCLOSEKEY,
                     winreg_BaseRegCloseKey_req_coder, &req,
                     winreg_BaseRegCloseKey_rep_coder,
                     sizeof(*rep), (void **)&rep) == 0) {
                dcerpc_free_data(g_dce, rep);
        }
}

/*
 * Create a subkey under parent (must be a key node). Returns 0 on success.
 */
static int
create_subkey(struct node *parent, const char *name)
{
        struct winreg_BaseRegCreateKey_req req;
        struct winreg_BaseRegCreateKey_rep *rep;
        struct node *child;
        char *empty_class = "";

        if (parent == NULL || parent->is_value || name == NULL || !name[0]) {
                return -1;
        }
        if (node_ensure_handle(parent) != 0) {
                return -1;
        }

        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, &parent->hKey, sizeof(req.hKey));
        req.lpSubKey = (char *)name;
        req.lpClass = empty_class;
        req.dwOptions = REG_OPTION_NON_VOLATILE;
        req.samDesired = WINREG_WALK_ACCESS;
        req.disposition = 0;

        if (rpc_call(WINREG_BASEREGCREATEKEY,
                     winreg_BaseRegCreateKey_req_coder, &req,
                     winreg_BaseRegCreateKey_rep_coder,
                     sizeof(*rep), (void **)&rep) != 0) {
                return -1;
        }
        if (rep->status != ERROR_SUCCESS) {
                set_status("CreateKey failed 0x%x under %s",
                           rep->status, parent->name);
                dcerpc_free_data(g_dce, rep);
                return -1;
        }

        /* We only needed the create; drop the new handle. */
        close_handle_only(&rep->phkResult);

        if (rep->disposition == REG_CREATED_NEW_KEY) {
                set_status("Created key %s\\%s", parent->name, name);
        } else {
                set_status("Key already exists: %s\\%s", parent->name, name);
        }
        dcerpc_free_data(g_dce, rep);

        parent->has_children = 1;
        if (parent->expanded) {
                int i;

                for (i = 0; i < parent->nchildren; i++) {
                        if (!parent->children[i]->is_value &&
                            strcmp(parent->children[i]->name, name) == 0) {
                                return 0;
                        }
                }
                child = node_new(name, parent->depth + 1, parent);
                if (child == NULL) {
                        set_status("Created, but out of memory for UI node");
                        return 0;
                }
                if (node_add_child(parent, child) != 0) {
                        node_free(child);
                        set_status("Created, but out of memory for UI node");
                        return 0;
                }
        } else {
                /* Will show up on next expand */
                parent->loaded = 0;
        }
        return 0;
}

static void
show_help(void)
{
        static const char *const lines[] = {
                "winreg-tui — remote registry browser (MS-RRP / IPC$\\winreg)",
                "",
                "Navigation",
                "  Up / Down       Move the selection one line",
                "  Page Up / Down  Move by roughly one screen",
                "  q / Q           Quit",
                "",
                "Tree",
                "  Space           Expand or collapse the selected key",
                "                  Subkeys and values are loaded only when",
                "                  a key is first expanded (lazy load).",
                "  >               Key has children and is collapsed",
                "  v               Key has children and is expanded",
                "  (space)         Leaf: value, or key with no children",
                "",
                "Editing",
                "  k / K           Create a new subkey under the selected key",
                "                  (if a value is selected, under its parent).",
                "                  You will be prompted for the key name.",
                "  v / V           Create or replace a value under the selected",
                "                  key. Prompts: name, type (s=string, d=DWORD),",
                "                  and data. Empty name is the (Default) value.",
                "  e / E           Edit the selected value (same type). Prompts",
                "                  for new data; shows the current value first.",
                "                  Then a dialog shows old vs new; y confirms,",
                "                  n or ESC cancels without writing.",
                "  d / D           Delete selection:",
                "                    · value  — delete that registry value",
                "                    · key    — delete the key (must have no",
                "                      subkeys; values alone are OK). Not for",
                "                      hive roots. Confirms first.",
                "",
                "Display",
                "  Top level       HKEY_CLASSES_ROOT, HKEY_CURRENT_USER,",
                "                  HKEY_LOCAL_MACHINE, HKEY_USERS,",
                "                  HKEY_CURRENT_CONFIG",
                "  Indentation     Two spaces per depth level",
                "  Values          name (TYPE) = data",
                "",
                "Status line (bottom) shows messages and prompts.",
                "",
                "Press any key to return...",
                NULL
        };
        int rows, cols;
        int i, row;
        int max_body;

        getmaxyx(stdscr, rows, cols);
        erase();
        max_body = rows > 1 ? rows - 1 : 1;
        for (i = 0, row = 0; lines[i] != NULL && row < max_body; i++, row++) {
                if (cols > 1) {
                        mvprintw(row, 0, "%.*s", cols - 1, lines[i]);
                }
        }
        refresh();
        (void)getch();
}

static void
action_create_key(void)
{
        struct node *sel, *parent;
        char name[256];

        if (g_nvisible == 0) {
                set_status("Nothing selected");
                return;
        }
        sel = g_visible[g_sel];
        if (sel->is_value) {
                parent = sel->parent;
        } else {
                parent = sel;
        }
        if (parent == NULL) {
                set_status("Cannot create key here");
                return;
        }

        set_status("New key under %s", parent->name);
        draw_ui();
        if (prompt_string("New key name: ", name, sizeof(name)) != 0 ||
            name[0] == '\0') {
                set_status("Create cancelled");
                return;
        }
        /* Disallow path separators in a single path component */
        if (strchr(name, '\\') != NULL || strchr(name, '/') != NULL) {
                set_status("Key name must not contain path separators");
                return;
        }

        set_status("Creating %s\\%s ...", parent->name, name);
        draw_ui();
        if (create_subkey(parent, name) == 0) {
                rebuild_visible();
                /* select the new child if visible */
                {
                        int i;
                        for (i = 0; i < g_nvisible; i++) {
                                if (g_visible[i]->parent == parent &&
                                    !g_visible[i]->is_value &&
                                    strcmp(g_visible[i]->name, name) == 0) {
                                        g_sel = i;
                                        break;
                                }
                        }
                }
        }
}

/* Encode UTF-8 string as UTF-16LE with trailing NUL. Caller frees *out. */
static int
utf8_to_reg_sz(const char *utf8, uint8_t **out, uint32_t *out_len)
{
        struct smb2_utf16 *u16;
        uint32_t n, i;

        u16 = smb2_utf8_to_utf16(utf8 ? utf8 : "");
        if (u16 == NULL) {
                return -1;
        }
        n = (uint32_t)u16->len + 1; /* include NUL */
        *out = malloc((size_t)n * 2);
        if (*out == NULL) {
                free(u16);
                return -1;
        }
        for (i = 0; i < u16->len; i++) {
                (*out)[i * 2] = (uint8_t)(u16->val[i] & 0xff);
                (*out)[i * 2 + 1] = (uint8_t)((u16->val[i] >> 8) & 0xff);
        }
        (*out)[u16->len * 2] = 0;
        (*out)[u16->len * 2 + 1] = 0;
        *out_len = n * 2;
        free(u16);
        return 0;
}

static int
parse_dword(const char *s, uint32_t *out)
{
        char *end = NULL;
        unsigned long v;

        if (s == NULL || !s[0]) {
                return -1;
        }
        errno = 0;
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                v = strtoul(s, &end, 16);
        } else {
                v = strtoul(s, &end, 10);
        }
        if (errno || end == s || (end && *end != '\0')) {
                return -1;
        }
        *out = (uint32_t)v;
        return 0;
}

static void
ui_add_or_update_value(struct node *parent, const char *name,
                       uint32_t type, const uint8_t *data, uint32_t len)
{
        const char *nm = (name && name[0]) ? name : "(Default)";
        struct node *child;
        int i;

        parent->has_children = 1;
        if (!parent->expanded) {
                parent->loaded = 0;
                return;
        }
        for (i = 0; i < parent->nchildren; i++) {
                if (parent->children[i]->is_value &&
                    strcmp(parent->children[i]->name, nm) == 0) {
                        free(parent->children[i]->value_text);
                        parent->children[i]->reg_type = type;
                        parent->children[i]->value_text =
                                format_reg_value(type, data, len);
                        return;
                }
        }
        child = node_new_value(name, parent->depth + 1, parent, type, data, len);
        if (child == NULL || node_add_child(parent, child) != 0) {
                node_free(child);
                set_status("SetValue ok, but out of memory for UI node");
        }
}

/*
 * Encode databuf for type into data and data_len.
 * REG_SZ allocates *data (caller frees); REG_DWORD uses dword_buf.
 * Returns 0 on success.
 */
static int
encode_value_data(uint32_t type, const char *databuf,
                  uint8_t **data, uint32_t *data_len, uint8_t dword_buf[4])
{
        if (type == REG_DWORD) {
                uint32_t v;

                if (parse_dword(databuf, &v) != 0) {
                        set_status("Invalid DWORD (use decimal or 0xhex)");
                        return -1;
                }
                dword_buf[0] = (uint8_t)(v & 0xff);
                dword_buf[1] = (uint8_t)((v >> 8) & 0xff);
                dword_buf[2] = (uint8_t)((v >> 16) & 0xff);
                dword_buf[3] = (uint8_t)((v >> 24) & 0xff);
                *data = dword_buf;
                *data_len = 4;
                return 0;
        }
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
                if (utf8_to_reg_sz(databuf, data, data_len) != 0) {
                        set_status("Failed to encode string");
                        return -1;
                }
                return 0;
        }
        set_status("Unsupported type for edit (use SZ or DWORD)");
        return -1;
}

static int
do_set_value(struct node *parent, char *name, uint32_t type,
             uint8_t *data, uint32_t data_len)
{
        struct winreg_BaseRegSetValue_req req;
        struct winreg_BaseRegSetValue_rep *rep;

        if (node_ensure_handle(parent) != 0) {
                return -1;
        }

        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, &parent->hKey, sizeof(req.hKey));
        req.lpValueName = name ? name : "";
        req.dwType = type;
        req.lpData = data;
        req.cbData = data_len;

        set_status("Setting value under %s ...", parent->name);
        draw_ui();
        if (rpc_call(WINREG_BASEREGSETVALUE,
                     winreg_BaseRegSetValue_req_coder, &req,
                     winreg_BaseRegSetValue_rep_coder,
                     sizeof(*rep), (void **)&rep) != 0) {
                return -1;
        }
        if (rep->status != ERROR_SUCCESS) {
                set_status("SetValue failed 0x%x", rep->status);
                dcerpc_free_data(g_dce, rep);
                return -1;
        }
        dcerpc_free_data(g_dce, rep);

        ui_add_or_update_value(parent, name, type, data, data_len);
        rebuild_visible();
        set_status("Set value under %s", parent->name);
        return 0;
}

static void
action_create_value(void)
{
        struct node *sel, *parent;
        char name[256];
        char typebuf[32];
        char databuf[512];
        uint32_t type = REG_SZ;
        uint8_t *data = NULL;
        uint32_t data_len = 0;
        uint8_t dword_buf[4];

        if (g_nvisible == 0) {
                set_status("Nothing selected");
                return;
        }
        sel = g_visible[g_sel];
        if (sel->is_value) {
                parent = sel->parent;
        } else {
                parent = sel;
        }
        if (parent == NULL || parent->is_value) {
                set_status("Cannot set value here");
                return;
        }

        set_status("New value under %s", parent->name);
        draw_ui();
        /* Empty name is allowed (Default value) */
        {
                int rows, cols;

                getmaxyx(stdscr, rows, cols);
                (void)cols;
                echo();
                curs_set(1);
                nocbreak();
                mvprintw(rows - 1, 0, "Value name (empty=Default): ");
                clrtoeol();
                refresh();
                name[0] = '\0';
                getnstr(name, (int)sizeof(name) - 1);
                noecho();
                curs_set(0);
                cbreak();
        }

        draw_ui();
        if (prompt_string("Type [s=SZ / d=DWORD] (default s): ",
                          typebuf, sizeof(typebuf)) != 0) {
                set_status("Create cancelled");
                return;
        }
        if (typebuf[0] == '\0') {
                typebuf[0] = 's';
                typebuf[1] = '\0';
        }
        if (typebuf[0] == 'd' || typebuf[0] == 'D') {
                type = REG_DWORD;
        } else {
                type = REG_SZ;
        }

        draw_ui();
        if (prompt_string(type == REG_DWORD ?
                          "DWORD value (dec or 0xhex): " :
                          "String value: ",
                          databuf, sizeof(databuf)) != 0) {
                set_status("Create cancelled");
                return;
        }
        if (type == REG_DWORD && databuf[0] == '\0') {
                set_status("Value data required for DWORD");
                return;
        }

        if (encode_value_data(type, databuf, &data, &data_len, dword_buf) != 0) {
                return;
        }
        if (do_set_value(parent, name, type, data, data_len) != 0) {
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                        free(data);
                }
                return;
        }
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
                free(data);
        }
}

/*
 * Extract a user-editable form of the current value for the prompt hint.
 * For REG_SZ, strip surrounding quotes from value_text when present.
 * For REG_DWORD, use the 0x... form if present.
 */
static void
current_value_hint(struct node *val, char *buf, size_t buflen)
{
        const char *vt = val->value_text ? val->value_text : "";
        size_t len;

        buf[0] = '\0';
        if (val->reg_type == REG_SZ || val->reg_type == REG_EXPAND_SZ) {
                if (vt[0] == '"' && strlen(vt) >= 2) {
                        len = strlen(vt);
                        if (vt[len - 1] == '"') {
                                if (len - 2 >= buflen) {
                                        len = buflen + 1; /* force truncate path */
                                }
                                if (len >= 2 && len - 2 < buflen) {
                                        memcpy(buf, vt + 1, len - 2);
                                        buf[len - 2] = '\0';
                                        return;
                                }
                        }
                }
                snprintf(buf, buflen, "%s", vt);
                return;
        }
        if (val->reg_type == REG_DWORD ||
            val->reg_type == REG_DWORD_BIG_ENDIAN) {
                /* value_text like "0x00000001 (1)" — take first token */
                size_t i;

                for (i = 0; vt[i] && vt[i] != ' ' && i + 1 < buflen; i++) {
                        buf[i] = vt[i];
                }
                buf[i] = '\0';
                return;
        }
        snprintf(buf, buflen, "%s", vt);
}

/*
 * Modal dialog showing old vs new value. Returns 1 if the user confirms
 * with y/Y, 0 if cancelled (n/N/ESC or any other key).
 */
static int
confirm_value_change(const char *name, const char *type_name,
                     const char *old_val, const char *new_val)
{
        WINDOW *win;
        int rows, cols;
        int w, h, y, x;
        int inner;
        int ch;
        const char *old_s = (old_val && old_val[0]) ? old_val : "(empty)";
        const char *new_s = (new_val && new_val[0]) ? new_val : "(empty)";
        const char *nm = (name && name[0]) ? name : "(Default)";
        const char *tn = type_name ? type_name : "";

        getmaxyx(stdscr, rows, cols);
        w = cols > 60 ? 60 : (cols > 20 ? cols - 2 : cols);
        if (w < 30 && cols >= 30) {
                w = 30;
        }
        h = 11;
        if (h > rows - 2) {
                h = rows > 2 ? rows - 2 : rows;
        }
        y = (rows - h) / 2;
        x = (cols - w) / 2;
        if (y < 0) {
                y = 0;
        }
        if (x < 0) {
                x = 0;
        }
        inner = w > 4 ? w - 4 : 1;

        win = newwin(h, w, y, x);
        if (win == NULL) {
                set_status("Could not open confirm dialog");
                return 0;
        }
        keypad(win, TRUE);
        box(win, 0, 0);
        mvwprintw(win, 1, 2, "%.*s", inner, "Confirm value change");
        mvwhline(win, 2, 1, ACS_HLINE, w > 2 ? w - 2 : 0);
        mvwprintw(win, 3, 2, "Name: %.*s",
                  inner > 6 ? inner - 6 : 1, nm);
        mvwprintw(win, 4, 2, "Type: %.*s",
                  inner > 6 ? inner - 6 : 1, tn);
        mvwprintw(win, 5, 2, "Old:  %.*s",
                  inner > 6 ? inner - 6 : 1, old_s);
        mvwprintw(win, 6, 2, "New:  %.*s",
                  inner > 6 ? inner - 6 : 1, new_s);
        mvwhline(win, 7, 1, ACS_HLINE, w > 2 ? w - 2 : 0);
        mvwprintw(win, 8, 2, "%.*s", inner,
                  "Write this change? [y/N]");
        if (h > 9) {
                mvwprintw(win, 9, 2, "%.*s", inner,
                          "y=yes  n/ESC=cancel");
        }
        wrefresh(win);

        ch = wgetch(win);
        delwin(win);
        touchwin(stdscr);
        refresh();

        return (ch == 'y' || ch == 'Y');
}

static void
action_edit_value(void)
{
        struct node *sel, *parent;
        char databuf[512];
        char hint[256];
        char prompt[STATUS_LEN];
        uint32_t type;
        uint8_t *data = NULL;
        uint32_t data_len = 0;
        uint8_t dword_buf[4];
        char wire_name[256];
        char empty_name[] = "";
        char *name_ptr;
        char *new_text = NULL;

        if (g_nvisible == 0) {
                set_status("Nothing selected");
                return;
        }
        sel = g_visible[g_sel];
        if (!sel->is_value) {
                set_status("Select a value to edit (use v to create)");
                return;
        }
        parent = sel->parent;
        if (parent == NULL) {
                set_status("Cannot edit value (no parent key)");
                return;
        }

        type = sel->reg_type;
        if (type != REG_SZ && type != REG_EXPAND_SZ &&
            type != REG_DWORD && type != REG_DWORD_BIG_ENDIAN) {
                set_status("Edit supports REG_SZ and REG_DWORD only");
                return;
        }
        /* Treat big-endian DWORD as little-endian on rewrite */
        if (type == REG_DWORD_BIG_ENDIAN) {
                type = REG_DWORD;
        }
        if (type == REG_EXPAND_SZ) {
                type = REG_SZ;
        }

        if (strcmp(sel->name, "(Default)") == 0) {
                wire_name[0] = '\0';
                name_ptr = empty_name;
        } else {
                snprintf(wire_name, sizeof(wire_name), "%s", sel->name);
                name_ptr = wire_name;
        }

        current_value_hint(sel, hint, sizeof(hint));
        set_status("Edit %s (%s) currently %s",
                   sel->name, reg_type_name(sel->reg_type),
                   sel->value_text ? sel->value_text : "");
        draw_ui();

        if (type == REG_DWORD) {
                snprintf(prompt, sizeof(prompt),
                         "New DWORD [%s]: ", hint[0] ? hint : "0");
        } else {
                snprintf(prompt, sizeof(prompt),
                         "New string [%s]: ", hint);
        }
        if (prompt_string(prompt, databuf, sizeof(databuf)) != 0) {
                set_status("Edit cancelled");
                return;
        }
        if (type == REG_DWORD && databuf[0] == '\0') {
                set_status("Edit cancelled");
                return;
        }

        if (encode_value_data(type, databuf, &data, &data_len, dword_buf) != 0) {
                return;
        }

        new_text = format_reg_value(type, data, data_len);
        if (!confirm_value_change(sel->name,
                                  reg_type_name(sel->reg_type),
                                  sel->value_text,
                                  new_text ? new_text : databuf)) {
                free(new_text);
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                        free(data);
                }
                set_status("Edit cancelled");
                return;
        }
        free(new_text);

        if (do_set_value(parent, name_ptr, type, data, data_len) != 0) {
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                        free(data);
                }
                return;
        }
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
                free(data);
        }
}

/*
 * Remove child from parent's children array (does not free child).
 * Returns 0 if removed, -1 if not found.
 */
static int
node_detach_child(struct node *parent, struct node *child)
{
        int i, j;

        if (parent == NULL || child == NULL) {
                return -1;
        }
        for (i = 0; i < parent->nchildren; i++) {
                if (parent->children[i] == child) {
                        for (j = i; j + 1 < parent->nchildren; j++) {
                                parent->children[j] = parent->children[j + 1];
                        }
                        parent->nchildren--;
                        if (parent->nchildren == 0) {
                                parent->has_children = 0;
                        }
                        return 0;
                }
        }
        return -1;
}

static int
confirm_yes_no(const char *prompt)
{
        int rows, cols;
        int ch;

        getmaxyx(stdscr, rows, cols);
        (void)cols;
        mvprintw(rows - 1, 0, "%s [y/N]: ", prompt);
        clrtoeol();
        refresh();
        ch = getch();
        return (ch == 'y' || ch == 'Y');
}

static void
action_delete_value(struct node *sel)
{
        struct node *parent = sel->parent;
        struct winreg_BaseRegDeleteValue_req req;
        struct winreg_BaseRegDeleteValue_rep *rep;
        char prompt[STATUS_LEN];
        char empty_name[] = "";
        char *wire_name;

        if (parent == NULL) {
                set_status("Cannot delete value (no parent key)");
                return;
        }

        snprintf(prompt, sizeof(prompt), "Delete value \"%s\"", sel->name);
        draw_ui();
        if (!confirm_yes_no(prompt)) {
                set_status("Delete cancelled");
                return;
        }

        if (node_ensure_handle(parent) != 0) {
                return;
        }

        /* UI uses "(Default)" for the empty value name */
        if (strcmp(sel->name, "(Default)") == 0) {
                wire_name = empty_name;
        } else {
                wire_name = sel->name;
        }

        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, &parent->hKey, sizeof(req.hKey));
        req.lpValueName = wire_name;

        set_status("Deleting value %s ...", sel->name);
        draw_ui();
        if (rpc_call(WINREG_BASEREGDELETEVALUE,
                     winreg_BaseRegDeleteValue_req_coder, &req,
                     winreg_BaseRegDeleteValue_rep_coder,
                     sizeof(*rep), (void **)&rep) != 0) {
                return;
        }
        if (rep->status != ERROR_SUCCESS) {
                set_status("DeleteValue failed 0x%x", rep->status);
                dcerpc_free_data(g_dce, rep);
                return;
        }
        dcerpc_free_data(g_dce, rep);

        node_detach_child(parent, sel);
        node_free(sel);
        if (g_sel > 0) {
                g_sel--;
        }
        rebuild_visible();
        if (g_sel >= g_nvisible && g_nvisible > 0) {
                g_sel = g_nvisible - 1;
        }
        set_status("Deleted value under %s", parent->name);
}

static void
action_delete_key(void)
{
        struct node *sel, *parent;
        struct winreg_BaseRegDeleteKey_req req;
        struct winreg_BaseRegDeleteKey_rep *rep;
        char prompt[STATUS_LEN];

        if (g_nvisible == 0) {
                set_status("Nothing selected");
                return;
        }
        sel = g_visible[g_sel];
        if (sel->is_value) {
                action_delete_value(sel);
                return;
        }
        parent = sel->parent;
        if (parent == NULL) {
                set_status("Cannot delete a hive root");
                return;
        }

        snprintf(prompt, sizeof(prompt), "Delete key \"%s\"", sel->name);
        draw_ui();
        if (!confirm_yes_no(prompt)) {
                set_status("Delete cancelled");
                return;
        }

        if (node_ensure_handle(parent) != 0) {
                return;
        }

        /* Close any open handle on the key being deleted */
        if (sel->has_handle) {
                node_close_handle(sel);
        }

        memset(&req, 0, sizeof(req));
        memcpy(&req.hKey, &parent->hKey, sizeof(req.hKey));
        req.lpSubKey = sel->name;

        set_status("Deleting %s\\%s ...", parent->name, sel->name);
        draw_ui();
        if (rpc_call(WINREG_BASEREGDELETEKEY,
                     winreg_BaseRegDeleteKey_req_coder, &req,
                     winreg_BaseRegDeleteKey_rep_coder,
                     sizeof(*rep), (void **)&rep) != 0) {
                return;
        }
        if (rep->status != ERROR_SUCCESS) {
                set_status("DeleteKey failed 0x%x (key not empty?)",
                           rep->status);
                dcerpc_free_data(g_dce, rep);
                return;
        }
        dcerpc_free_data(g_dce, rep);

        node_detach_child(parent, sel);
        node_free(sel);
        if (g_sel > 0) {
                g_sel--;
        }
        rebuild_visible();
        if (g_sel >= g_nvisible && g_nvisible > 0) {
                g_sel = g_nvisible - 1;
        }
        set_status("Deleted key under %s", parent->name);
}

int
main(int argc, char *argv[])
{
        int ch;
        struct node *n;

        if (argc < 2) {
                return usage();
        }

        if (connect_winreg(argv[1]) != 0) {
                cleanup();
                return 1;
        }

        initscr();
        g_ui_active = 1;
        cbreak();
        noecho();
        keypad(stdscr, TRUE);
        curs_set(0);

        draw_ui();

        while ((ch = getch()) != 'q' && ch != 'Q') {
                switch (ch) {
                case KEY_UP:
                        if (g_sel > 0) {
                                g_sel--;
                        }
                        break;
                case KEY_DOWN:
                        if (g_sel + 1 < g_nvisible) {
                                g_sel++;
                        }
                        break;
                case KEY_PPAGE: {
                        int rows, cols, page;

                        getmaxyx(stdscr, rows, cols);
                        (void)cols;
                        page = rows > 3 ? rows - 3 : 1;
                        g_sel -= page;
                        if (g_sel < 0) {
                                g_sel = 0;
                        }
                        break;
                }
                case KEY_NPAGE: {
                        int rows, cols, page;

                        getmaxyx(stdscr, rows, cols);
                        (void)cols;
                        page = rows > 3 ? rows - 3 : 1;
                        g_sel += page;
                        if (g_sel >= g_nvisible) {
                                g_sel = g_nvisible ? g_nvisible - 1 : 0;
                        }
                        break;
                }
                case ' ':
                        if (g_nvisible == 0) {
                                break;
                        }
                        n = g_visible[g_sel];
                        if (n->is_value) {
                                set_status("%s (%s) = %s", n->name,
                                           reg_type_name(n->reg_type),
                                           n->value_text ? n->value_text : "");
                                break;
                        }
                        if (n->expanded) {
                                node_collapse(n);
                                set_status("Collapsed %s", n->name);
                                rebuild_visible();
                        } else {
                                set_status("Expanding %s ...", n->name);
                                draw_ui();
                                if (node_expand(n) == 0) {
                                        rebuild_visible();
                                }
                        }
                        break;
                case 'k':
                case 'K':
                        action_create_key();
                        break;
                case 'v':
                case 'V':
                        action_create_value();
                        break;
                case 'e':
                case 'E':
                        action_edit_value();
                        break;
                case 'd':
                case 'D':
                        action_delete_key();
                        break;
                case '?':
                        show_help();
                        break;
                case KEY_RESIZE:
                        break;
                default:
                        break;
                }
                draw_ui();
        }

        cleanup();
        return 0;
}
