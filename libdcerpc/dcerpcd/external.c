/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * External DCE/RPC service control channel for dcerpcd.
 * Listens on a Unix domain socket (default: /var/run/dcerpcd/dcerpcd.sock).
 * Creates the parent directory if needed.  A service process connects and
 * sends a length-prefixed YAML registration describing its interface and
 * ncacn_np endpoints.  While the connection stays up, the endpoints appear
 * in the endpoint mapper and the pipe is available as DCERPCD_SVC_EXTERNAL.
 * On disconnect the registrations are removed.
 * Wire format (registration request):
 *   uint32_t body_len;          // little-endian
 *   char     body[body_len];    // UTF-8 YAML, max 64 KiB
 * YAML body (example):
 *   Service:
 *     name: srvsvc
 *     uuid: 4b324fc8-1670-01d3-1278-5a47bf6ee188
 *     version: 3.0
 *     annotation: Server Service
 *     endpoints:
 *       - transport: ncacn_np
 *         endpoint: \pipe\srvsvc
 * Reply (ASCII, not length-prefixed):
 *   OK\n
 *   or
 *   ERROR: <message>\n
 * After registration, dcerpcd may send RPC proxy messages framed as
 * documented in dcerpcd_proto.h (64-byte "DCER" header + ndr_len + stub).
 * Workers reply with the same framing; uid_or_status holds the status code
 * (0 = OK, 1 = FAIL). session_id + msgid identify the reply. On FAIL,
 * ndr_len is 0.
 *
 * Proxy RPC is asynchronous: each worker keeps an in-flight list keyed by
 * (session_id, msgid). Worker sockets and the listen fd are driven from
 * smb2_serve_port's select loop via dcerpcd_external_fdset/service.
 *
 */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"
#include <dcerpc/dcerpc.h>

#include "dcerpcd.h"
#include "dcerpcd_proto.h"

#ifndef _U_
#define _U_ __attribute__((unused))
#endif

#define MAX_REG_BODY (64 * 1024)
#define MAX_CLIENTS  32
#define MAX_ENDPOINTS 8
#define MAX_PROXY_BODY (16 * 1024 * 1024)
#define EXTERNAL_RPC_TIMEOUT_SEC 30

/* ------------------------------------------------------------------ */
/* Registration message parse                                          */
/* ------------------------------------------------------------------ */

struct reg_endpoint {
        char *transport;   /* "ncacn_np" for now */
        char *endpoint;    /* "\\pipe\\srvsvc" */
};

struct reg_msg {
        char *name;
        char *uuid_str;
        char *version_str;
        char *annotation;
        uint16_t vers_major;
        uint16_t vers_minor;
        dcerpc_uuid_t uuid;
        struct reg_endpoint eps[MAX_ENDPOINTS];
        int nep;
};

static void
reg_msg_free(struct reg_msg *m)
{
        int i;

        if (m == NULL) {
                return;
        }
        free(m->name);
        free(m->uuid_str);
        free(m->version_str);
        free(m->annotation);
        for (i = 0; i < m->nep; i++) {
                free(m->eps[i].transport);
                free(m->eps[i].endpoint);
        }
        memset(m, 0, sizeof(*m));
}

static char *
trim(char *s)
{
        char *e;

        while (*s == ' ' || *s == '\t' || *s == '\r') {
                s++;
        }
        e = s + strlen(s);
        while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' ||
                         e[-1] == '\n')) {
                e--;
        }
        *e = '\0';
        /* strip optional surrounding quotes */
        if ((s[0] == '"' || s[0] == '\'') && e > s + 1 && e[-1] == s[0]) {
                s++;
                e[-1] = '\0';
        }
        return s;
}

static char *
xstrdup(const char *s)
{
        return s ? strdup(s) : NULL;
}

/*
 * Parse a standard UUID string into dcerpc_uuid_t.
 * Accepts 8-4-4-4-12 hex with optional braces.
 */
static int
parse_uuid(const char *s, dcerpc_uuid_t *u)
{
        unsigned int p1, p2, p3, b[8];
        int n;

        if (s == NULL || u == NULL) {
                return -1;
        }
        while (*s == '{' || *s == ' ' || *s == '\t') {
                s++;
        }
        n = sscanf(s,
                   "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   &p1, &p2, &p3,
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7]);
        if (n != 11) {
                return -1;
        }
        u->v1 = (uint32_t)p1;
        u->v2 = (uint16_t)p2;
        u->v3 = (uint16_t)p3;
        {
                int i;

                for (i = 0; i < 8; i++) {
                        u->v4[i] = (uint8_t)b[i];
                }
        }
        return 0;
}

static int
parse_version(const char *s, uint16_t *maj, uint16_t *min)
{
        unsigned int a = 0, b = 0;

        if (s == NULL) {
                return -1;
        }
        if (sscanf(s, "%u.%u", &a, &b) < 1) {
                return -1;
        }
        *maj = (uint16_t)a;
        *min = (uint16_t)b;
        return 0;
}

/*
 * Minimal YAML subset parser for the Service registration document.
 * Indentation-based; only the keys we care about.
 */
static int
parse_reg_yaml(char *body, struct reg_msg *out, char *err, size_t errlen)
{
        char *save = NULL;
        char *line;
        int in_service = 0;
        int in_endpoints = 0;
        int cur_ep = -1;

        memset(out, 0, sizeof(*out));

        for (line = strtok_r(body, "\n", &save); line;
             line = strtok_r(NULL, "\n", &save)) {
                char *p = line;
                int indent = 0;
                char *key, *val, *colon;

                while (*p == ' ') {
                        indent++;
                        p++;
                }
                if (*p == '\0' || *p == '#') {
                        continue;
                }

                if (indent == 0 && !strncmp(p, "Service:", 8)) {
                        in_service = 1;
                        in_endpoints = 0;
                        continue;
                }
                if (!in_service) {
                        continue;
                }

                /* list item under endpoints */
                if (in_endpoints && indent >= 4 && p[0] == '-' &&
                    (p[1] == ' ' || p[1] == '\0')) {
                        p++;
                        while (*p == ' ') {
                                p++;
                        }
                        if (out->nep >= MAX_ENDPOINTS) {
                                snprintf(err, errlen, "too many endpoints");
                                return -1;
                        }
                        cur_ep = out->nep++;
                        memset(&out->eps[cur_ep], 0, sizeof(out->eps[cur_ep]));
                        if (*p == '\0') {
                                continue;
                        }
                        /* inline "- transport: foo" */
                }

                colon = strchr(p, ':');
                if (colon == NULL) {
                        continue;
                }
                *colon = '\0';
                key = trim(p);
                val = trim(colon + 1);

                if (!strcmp(key, "endpoints")) {
                        in_endpoints = 1;
                        cur_ep = -1;
                        continue;
                }

                if (in_endpoints) {
                        if (cur_ep < 0) {
                                continue;
                        }
                        if (!strcmp(key, "transport")) {
                                free(out->eps[cur_ep].transport);
                                out->eps[cur_ep].transport = xstrdup(val);
                        } else if (!strcmp(key, "endpoint")) {
                                free(out->eps[cur_ep].endpoint);
                                out->eps[cur_ep].endpoint = xstrdup(val);
                        }
                        continue;
                }

                if (!strcmp(key, "name")) {
                        free(out->name);
                        out->name = xstrdup(val);
                } else if (!strcmp(key, "uuid")) {
                        free(out->uuid_str);
                        out->uuid_str = xstrdup(val);
                } else if (!strcmp(key, "version")) {
                        free(out->version_str);
                        out->version_str = xstrdup(val);
                } else if (!strcmp(key, "annotation")) {
                        free(out->annotation);
                        out->annotation = xstrdup(val);
                }
        }

        if (out->name == NULL || out->name[0] == '\0') {
                snprintf(err, errlen, "missing Service.name");
                return -1;
        }
        if (out->uuid_str == NULL || parse_uuid(out->uuid_str, &out->uuid)) {
                snprintf(err, errlen, "missing/invalid Service.uuid");
                return -1;
        }
        if (out->version_str == NULL ||
            parse_version(out->version_str, &out->vers_major, &out->vers_minor)) {
                snprintf(err, errlen, "missing/invalid Service.version");
                return -1;
        }
        if (out->nep < 1) {
                snprintf(err, errlen, "Service.endpoints must list at least one");
                return -1;
        }
        {
                int i;

                for (i = 0; i < out->nep; i++) {
                        if (out->eps[i].transport == NULL ||
                            out->eps[i].endpoint == NULL) {
                                snprintf(err, errlen,
                                         "endpoint %d missing transport/endpoint",
                                         i);
                                return -1;
                        }
                        if (strcasecmp(out->eps[i].transport, "ncacn_np") != 0) {
                                snprintf(err, errlen,
                                         "unsupported transport '%s' "
                                         "(only ncacn_np for now)",
                                         out->eps[i].transport);
                                return -1;
                        }
                }
        }
        return 0;
}

/* ------------------------------------------------------------------ */
/* Client connection state                                             */
/* ------------------------------------------------------------------ */

/* One outstanding proxy RPC on a worker connection. */
struct ext_inflight {
        struct ext_inflight *next;
        uint32_t session_id;
        uint32_t msgid;
        struct smb2_context *smb2; /* for cancel_by_smb2 */
        dcerpcd_external_done_cb cb;
        void *cb_data;
        time_t started;
};

struct ext_client {
        int fd;
        int registered;
        uint8_t *buf;
        size_t buflen;
        size_t bufcap;
        char name[64];
        struct ext_inflight *inflight;
};

static int listen_fd = -1;
static char *sock_path_owned;
static int clients_inited;
static uint32_t next_msgid = 1;

static struct ext_client clients[MAX_CLIENTS];

static void
inflight_fail_all(struct ext_client *c, int err)
{
        struct ext_inflight *p;

        while (c->inflight) {
                p = c->inflight;
                c->inflight = p->next;
                if (p->cb) {
                        p->cb(p->cb_data, err, DCERPCD_RPC_STATUS_FAIL,
                              NULL, 0);
                }
                free(p);
        }
}

static void
client_close(struct ext_client *c)
{
        if (c == NULL || c->fd < 0) {
                return;
        }
        inflight_fail_all(c, -1);
        if (c->registered) {
                dcerpcd_epm_unregister_by_owner(c->fd);
                dcerpcd_service_remove_by_fd(c->fd);
                printf("external: disconnected service name=%s fd=%d\n",
                       c->name[0] ? c->name : "?", c->fd);
        }
        close(c->fd);
        free(c->buf);
        memset(c, 0, sizeof(*c));
        c->fd = -1;
}

static void
ensure_clients_inited(void)
{
        int i;

        if (clients_inited) {
                return;
        }
        for (i = 0; i < MAX_CLIENTS; i++) {
                clients[i].fd = -1;
        }
        clients_inited = 1;
}

static struct ext_client *
client_by_fd(int fd)
{
        int i;

        if (fd < 0) {
                return NULL;
        }
        for (i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].fd == fd) {
                        return &clients[i];
                }
        }
        return NULL;
}

static int
send_reply(int fd, const char *msg)
{
        size_t len = strlen(msg);
        ssize_t n;

        n = write(fd, msg, len);
        return (n == (ssize_t)len) ? 0 : -1;
}

/*
 * Pipe path helpers: accept "srvsvc", "\\pipe\\srvsvc", "/pipe/srvsvc".
 * Returns malloc'd base name ("srvsvc") and optionally normalized
 * "\\pipe\\name" for the tower.
 */
static char *
pipe_base_name(const char *endpoint)
{
        const char *p = endpoint;

        if (p == NULL) {
                return NULL;
        }
        while (*p == '\\' || *p == '/') {
                p++;
        }
        if (!strncasecmp(p, "pipe", 4) && (p[4] == '\\' || p[4] == '/')) {
                p += 5;
        }
        while (*p == '\\' || *p == '/') {
                p++;
        }
        if (*p == '\0') {
                return NULL;
        }
        return strdup(p);
}

static char *
pipe_tower_path(const char *endpoint)
{
        char *base = pipe_base_name(endpoint);
        char *path;
        size_t n;

        if (base == NULL) {
                return NULL;
        }
        n = strlen(base) + 16;
        path = malloc(n);
        if (path == NULL) {
                free(base);
                return NULL;
        }
        /* C string "\\pipe\\name" is the wire path \pipe\name */
        snprintf(path, n, "\\pipe\\%s", base);
        free(base);
        return path;
}

static int
apply_registration(struct ext_client *c, struct reg_msg *msg, char *err,
                   size_t errlen)
{
        int i;
        char *base = NULL;
        char *tower_path = NULL;

        /* Use first ncacn_np endpoint for the pipe service binding. */
        base = pipe_base_name(msg->eps[0].endpoint);
        if (base == NULL) {
                snprintf(err, errlen, "invalid pipe endpoint");
                return -1;
        }

        /*
         * Prefer Service.name as the pipe base if it matches a simple
         * identifier; otherwise use the endpoint base name.
         */
        if (msg->name && msg->name[0] && strchr(msg->name, '\\') == NULL &&
            strchr(msg->name, '/') == NULL) {
                free(base);
                base = strdup(msg->name);
                if (base == NULL) {
                        snprintf(err, errlen, "out of memory");
                        return -1;
                }
        }

        if (dcerpcd_service_add_external(base, msg->annotation, c->fd,
                                         &msg->uuid,
                                         msg->vers_major,
                                         msg->vers_minor) != 0) {
                snprintf(err, errlen, "failed to register service '%s'", base);
                free(base);
                return -1;
        }

        for (i = 0; i < msg->nep; i++) {
                tower_path = pipe_tower_path(msg->eps[i].endpoint);
                if (tower_path == NULL) {
                        dcerpcd_service_remove_by_fd(c->fd);
                        dcerpcd_epm_unregister_by_owner(c->fd);
                        snprintf(err, errlen, "bad endpoint path");
                        free(base);
                        return -1;
                }
                if (dcerpcd_epm_register_np(&msg->uuid,
                                            msg->vers_major, msg->vers_minor,
                                            NULL,
                                            tower_path,
                                            msg->annotation,
                                            NULL,
                                            c->fd) != 0) {
                        free(tower_path);
                        dcerpcd_service_remove_by_fd(c->fd);
                        dcerpcd_epm_unregister_by_owner(c->fd);
                        snprintf(err, errlen, "epm register failed");
                        free(base);
                        return -1;
                }
                free(tower_path);
        }

        snprintf(c->name, sizeof(c->name), "%s", base);
        c->registered = 1;
        free(base);
        printf("external: registered service name=%s uuid=%s v%u.%u fd=%d "
               "(%u epm entries total)\n",
               c->name, msg->uuid_str ? msg->uuid_str : "?",
               (unsigned)msg->vers_major, (unsigned)msg->vers_minor,
               c->fd, dcerpcd_epm_count());
        return 0;
}

static int
client_try_register(struct ext_client *c)
{
        uint32_t body_len;
        char *body_copy = NULL;
        struct reg_msg msg;
        char err[256];
        char reply[300];

        if (c->buflen < 4) {
                return 0; /* need more */
        }
        body_len = (uint32_t)c->buf[0] |
                   ((uint32_t)c->buf[1] << 8) |
                   ((uint32_t)c->buf[2] << 16) |
                   ((uint32_t)c->buf[3] << 24);
        if (body_len == 0 || body_len > MAX_REG_BODY) {
                send_reply(c->fd, "ERROR: invalid registration length\n");
                return -1;
        }
        if (c->buflen < 4 + body_len) {
                return 0; /* need more */
        }

        body_copy = malloc(body_len + 1);
        if (body_copy == NULL) {
                send_reply(c->fd, "ERROR: out of memory\n");
                return -1;
        }
        memcpy(body_copy, c->buf + 4, body_len);
        body_copy[body_len] = '\0';

        /* Consume the message from the buffer. */
        {
                size_t rest = c->buflen - (4 + body_len);

                if (rest) {
                        memmove(c->buf, c->buf + 4 + body_len, rest);
                }
                c->buflen = rest;
        }

        memset(&msg, 0, sizeof(msg));
        err[0] = '\0';
        if (parse_reg_yaml(body_copy, &msg, err, sizeof(err)) != 0) {
                snprintf(reply, sizeof(reply), "ERROR: %s\n",
                         err[0] ? err : "parse failed");
                send_reply(c->fd, reply);
                free(body_copy);
                reg_msg_free(&msg);
                return -1;
        }
        free(body_copy);

        if (apply_registration(c, &msg, err, sizeof(err)) != 0) {
                snprintf(reply, sizeof(reply), "ERROR: %s\n",
                         err[0] ? err : "register failed");
                send_reply(c->fd, reply);
                reg_msg_free(&msg);
                return -1;
        }
        reg_msg_free(&msg);
        send_reply(c->fd, "OK\n");
        return 1;
}

static int
buf_append(struct ext_client *c, const uint8_t *data, size_t n)
{
        if (c->buflen + n > c->bufcap) {
                size_t ncap = c->bufcap ? c->bufcap * 2 : 1024;
                uint8_t *nb;

                while (ncap < c->buflen + n) {
                        ncap *= 2;
                }
                nb = realloc(c->buf, ncap);
                if (nb == NULL) {
                        return -1;
                }
                c->buf = nb;
                c->bufcap = ncap;
        }
        memcpy(c->buf + c->buflen, data, n);
        c->buflen += n;
        return 0;
}

static void
buf_consume(struct ext_client *c, size_t n)
{
        if (n >= c->buflen) {
                c->buflen = 0;
                return;
        }
        memmove(c->buf, c->buf + n, c->buflen - n);
        c->buflen -= n;
}

/*
 * Parse complete DCER proxy response frames from c->buf and complete
 * matching in-flight entries (session_id + msgid).
 */
static int
client_try_proxy_responses(struct ext_client *c)
{
        while (c->buflen >= DCERPCD_RPC_HDR_SIZE + 4) {
                struct dcerpcd_rpc_hdr hdr;
                uint32_t ndr_len;
                unsigned npad;
                size_t need;
                uint8_t *ndr = NULL;
                struct ext_inflight **pp;
                struct ext_inflight *inf;

                memcpy(&hdr, c->buf, sizeof(hdr));
                if (!dcerpcd_rpc_hdr_ok(&hdr)) {
                        fprintf(stderr,
                                "external: bad RPC magic on fd=%d "
                                "(%02x %02x %02x %02x)\n",
                                c->fd,
                                (unsigned)(uint8_t)hdr.magic[0],
                                (unsigned)(uint8_t)hdr.magic[1],
                                (unsigned)(uint8_t)hdr.magic[2],
                                (unsigned)(uint8_t)hdr.magic[3]);
                        return -1;
                }
                ndr_len = (uint32_t)c->buf[DCERPCD_RPC_HDR_SIZE] |
                          ((uint32_t)c->buf[DCERPCD_RPC_HDR_SIZE + 1] << 8) |
                          ((uint32_t)c->buf[DCERPCD_RPC_HDR_SIZE + 2] << 16) |
                          ((uint32_t)c->buf[DCERPCD_RPC_HDR_SIZE + 3] << 24);
                if (ndr_len > MAX_PROXY_BODY) {
                        fprintf(stderr,
                                "external: ndr_len %u too large on fd=%d\n",
                                ndr_len, c->fd);
                        return -1;
                }
                npad = dcerpcd_rpc_ndr_pad(ndr_len);
                need = DCERPCD_RPC_HDR_SIZE + 4 + ndr_len + npad;
                if (c->buflen < need) {
                        return 0; /* need more */
                }

                if (ndr_len) {
                        ndr = malloc(ndr_len);
                        if (ndr == NULL) {
                                return -1;
                        }
                        memcpy(ndr, c->buf + DCERPCD_RPC_HDR_SIZE + 4,
                               ndr_len);
                }
                buf_consume(c, need);

                inf = NULL;
                for (pp = &c->inflight; *pp; pp = &(*pp)->next) {
                        if ((*pp)->session_id == hdr.session_id &&
                            (*pp)->msgid == hdr.msgid) {
                                inf = *pp;
                                *pp = inf->next;
                                break;
                        }
                }
                if (inf == NULL) {
                        fprintf(stderr,
                                "external: unmatched response session=%u "
                                "msgid=%u fd=%d\n",
                                hdr.session_id, hdr.msgid, c->fd);
                        free(ndr);
                        continue;
                }

                printf("external: response session=%u msgid=%u opnum=%u "
                       "status=%d ndr_len=%u\n",
                       hdr.session_id, hdr.msgid, hdr.opnum,
                       (int)hdr.uid_or_status, ndr_len);

                if (inf->cb) {
                        uint8_t *cb_ndr = NULL;
                        uint32_t cb_len = 0;

                        if (hdr.uid_or_status == DCERPCD_RPC_STATUS_OK &&
                            ndr_len > 0) {
                                cb_ndr = ndr;
                                cb_len = ndr_len;
                                ndr = NULL;
                        }
                        inf->cb(inf->cb_data, 0, hdr.uid_or_status,
                                cb_ndr, cb_len);
                }
                free(ndr);
                free(inf);
        }
        return 0;
}

static int
client_on_readable(struct ext_client *c)
{
        uint8_t tmp[4096];
        ssize_t n;

        n = read(c->fd, tmp, sizeof(tmp));
        if (n < 0) {
                if (errno == EINTR || errno == EAGAIN) {
                        return 0;
                }
                return -1;
        }
        if (n == 0) {
                return -1; /* EOF / disconnect */
        }

        if (!c->registered) {
                if (c->buflen + (size_t)n > MAX_REG_BODY + 4) {
                        send_reply(c->fd, "ERROR: registration too large\n");
                        return -1;
                }
                if (buf_append(c, tmp, (size_t)n) != 0) {
                        return -1;
                }
                if (client_try_register(c) < 0) {
                        return -1;
                }
                return 0;
        }

        /* Registered: accumulate proxy replies and demux. */
        if (c->buflen + (size_t)n > MAX_PROXY_BODY + 128) {
                fprintf(stderr, "external: proxy buffer overflow fd=%d\n",
                        c->fd);
                return -1;
        }
        if (buf_append(c, tmp, (size_t)n) != 0) {
                return -1;
        }
        return client_try_proxy_responses(c);
}

static int
client_slot_new(int fd)
{
        int i;
        int flags;

        ensure_clients_inited();
        flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
                (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        for (i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].fd < 0) {
                        memset(&clients[i], 0, sizeof(clients[i]));
                        clients[i].fd = fd;
                        return i;
                }
        }
        return -1;
}

/* ------------------------------------------------------------------ */
/* Async forward DCERPC request stubs to a registered worker           */
/* ------------------------------------------------------------------ */

static int
write_all(int fd, const void *buf, size_t len)
{
        const uint8_t *p = buf;

        while (len) {
                ssize_t n = write(fd, p, len);

                if (n < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                /* UDS usually buffers a full small message;
                                 * treat backpressure as failure for now. */
                                return -1;
                        }
                        return -1;
                }
                if (n == 0) {
                        return -1;
                }
                p += (size_t)n;
                len -= (size_t)n;
        }
        return 0;
}

int
dcerpcd_external_call_async(int conn_fd,
                            struct smb2_context *smb2,
                            uint32_t session_id,
                            int32_t uid,
                            uint32_t opnum,
                            const uint8_t *ndr,
                            uint32_t ndr_len,
                            dcerpcd_external_done_cb cb,
                            void *cb_data,
                            uint32_t *msgid_out)
{
        struct ext_client *c;
        struct ext_inflight *inf;
        struct dcerpcd_rpc_hdr hdr;
        uint8_t lenbuf[4];
        uint8_t pad[3];
        unsigned npad;
        uint32_t msgid;

        if (conn_fd < 0 || cb == NULL || (ndr_len > 0 && ndr == NULL)) {
                return -1;
        }
        c = client_by_fd(conn_fd);
        if (c == NULL || !c->registered) {
                fprintf(stderr,
                        "external: call_async: no registered worker fd=%d\n",
                        conn_fd);
                return -1;
        }

        memset(&hdr, 0, sizeof(hdr));
        hdr.magic[0] = DCERPCD_RPC_MAGIC0;
        hdr.magic[1] = DCERPCD_RPC_MAGIC1;
        hdr.magic[2] = DCERPCD_RPC_MAGIC2;
        hdr.magic[3] = DCERPCD_RPC_MAGIC3;
        hdr.uid_or_status = uid;
        hdr.session_id = session_id;
        hdr.opnum = opnum;

        npad = dcerpcd_rpc_ndr_pad(ndr_len);
        memset(pad, 0, sizeof(pad));

        lenbuf[0] = (uint8_t)(ndr_len & 0xff);
        lenbuf[1] = (uint8_t)((ndr_len >> 8) & 0xff);
        lenbuf[2] = (uint8_t)((ndr_len >> 16) & 0xff);
        lenbuf[3] = (uint8_t)((ndr_len >> 24) & 0xff);

        msgid = next_msgid++;
        if (next_msgid == 0) {
                next_msgid = 1;
        }
        hdr.msgid = msgid;

        inf = calloc(1, sizeof(*inf));
        if (inf == NULL) {
                return -1;
        }
        inf->session_id = session_id;
        inf->msgid = msgid;
        inf->smb2 = smb2;
        inf->cb = cb;
        inf->cb_data = cb_data;
        inf->started = time(NULL);

        if (write_all(conn_fd, &hdr, sizeof(hdr)) != 0 ||
            write_all(conn_fd, lenbuf, 4) != 0 ||
            (ndr_len && write_all(conn_fd, ndr, ndr_len) != 0) ||
            (npad && write_all(conn_fd, pad, npad) != 0)) {
                free(inf);
                fprintf(stderr,
                        "external: call_async write fd=%d session=%u "
                        "opnum=%u: %s\n",
                        conn_fd, session_id, opnum, strerror(errno));
                return -1;
        }

        inf->next = c->inflight;
        c->inflight = inf;
        if (msgid_out) {
                *msgid_out = msgid;
        }
        return 0;
}

void
dcerpcd_external_cancel_by_smb2(struct smb2_context *smb2)
{
        int i;

        if (smb2 == NULL) {
                return;
        }
        for (i = 0; i < MAX_CLIENTS; i++) {
                struct ext_inflight **pp;

                if (clients[i].fd < 0) {
                        continue;
                }
                pp = &clients[i].inflight;
                while (*pp) {
                        struct ext_inflight *inf = *pp;

                        if (inf->smb2 == smb2) {
                                *pp = inf->next;
                                if (inf->cb) {
                                        inf->cb(inf->cb_data, -2,
                                                DCERPCD_RPC_STATUS_FAIL,
                                                NULL, 0);
                                }
                                free(inf);
                        } else {
                                pp = &inf->next;
                        }
                }
        }
}

static void
external_scan_timeouts(void)
{
        int i;
        time_t now = time(NULL);

        for (i = 0; i < MAX_CLIENTS; i++) {
                struct ext_inflight **pp;

                if (clients[i].fd < 0) {
                        continue;
                }
                pp = &clients[i].inflight;
                while (*pp) {
                        struct ext_inflight *inf = *pp;

                        if (now - inf->started >= EXTERNAL_RPC_TIMEOUT_SEC) {
                                fprintf(stderr,
                                        "external: timeout session=%u "
                                        "msgid=%u fd=%d\n",
                                        inf->session_id, inf->msgid,
                                        clients[i].fd);
                                *pp = inf->next;
                                if (inf->cb) {
                                        inf->cb(inf->cb_data, -1,
                                                DCERPCD_RPC_STATUS_FAIL,
                                                NULL, 0);
                                }
                                free(inf);
                        } else {
                                pp = &inf->next;
                        }
                }
        }
}

void
dcerpcd_external_fdset(fd_set *rfds, int *maxfd)
{
        int i;

        if (rfds == NULL || maxfd == NULL) {
                return;
        }
        ensure_clients_inited();
        if (listen_fd >= 0) {
                FD_SET(listen_fd, rfds);
                if (listen_fd > *maxfd) {
                        *maxfd = listen_fd;
                }
        }
        for (i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].fd >= 0) {
                        FD_SET(clients[i].fd, rfds);
                        if (clients[i].fd > *maxfd) {
                                *maxfd = clients[i].fd;
                        }
                }
        }
}

void
dcerpcd_external_service(fd_set *rfds)
{
        int i;

        ensure_clients_inited();
        external_scan_timeouts();

        if (rfds == NULL) {
                return;
        }
        if (listen_fd >= 0 && FD_ISSET(listen_fd, rfds)) {
                int cfd = accept(listen_fd, NULL, NULL);

                if (cfd < 0) {
                        if (errno != EINTR && errno != EAGAIN) {
                                fprintf(stderr, "external: accept: %s\n",
                                        strerror(errno));
                        }
                } else if (client_slot_new(cfd) < 0) {
                        send_reply(cfd, "ERROR: too many services\n");
                        close(cfd);
                } else {
                        printf("external: new service connection fd=%d\n",
                               cfd);
                }
        }
        for (i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].fd >= 0 && FD_ISSET(clients[i].fd, rfds)) {
                        if (client_on_readable(&clients[i]) < 0) {
                                client_close(&clients[i]);
                        }
                }
        }
}

void
dcerpcd_external_serve_fdset(struct smb2_server *server _U_,
                             fd_set *rfds, fd_set *wfds _U_, int *maxfd)
{
        dcerpcd_external_fdset(rfds, maxfd);
}

void
dcerpcd_external_serve_service(struct smb2_server *server _U_,
                               fd_set *rfds, fd_set *wfds _U_)
{
        dcerpcd_external_service(rfds);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * Ensure the directory containing path exists (mkdir -p for a single level
 * under an existing parent, e.g. /var/run/dcerpcd).
 */
static int
ensure_sock_dir(const char *path)
{
        char *dir;
        char *slash;
        int rc = 0;

        if (path == NULL || path[0] == '\0') {
                return -1;
        }
        dir = strdup(path);
        if (dir == NULL) {
                return -1;
        }
        slash = strrchr(dir, '/');
        if (slash == NULL || slash == dir) {
                /* Relative path or root — nothing to create */
                free(dir);
                return 0;
        }
        *slash = '\0';
        if (dir[0] == '\0') {
                free(dir);
                return 0;
        }
        /*
         * 0755: anyone may list and traverse (needed so unprivileged
         * workers can open the socket); only the owner can add/remove
         * files. chmod after mkdir so umask cannot strip bits, and so an
         * already-existing directory is corrected.
         */
        if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
                fprintf(stderr, "external: mkdir %s: %s\n", dir,
                        strerror(errno));
                rc = -1;
        } else if (chmod(dir, 0755) != 0) {
                fprintf(stderr, "external: chmod %s: %s\n", dir,
                        strerror(errno));
                rc = -1;
        }
        free(dir);
        return rc;
}

int
dcerpcd_external_init(const char *path)
{
        struct sockaddr_un addr;
        mode_t old_umask;
        const char *sock = path && path[0] ? path : DCERPCD_DEFAULT_SVC_SOCK;

        if (listen_fd >= 0) {
                return 0;
        }

        sock_path_owned = strdup(sock);
        if (sock_path_owned == NULL) {
                return -1;
        }

        if (ensure_sock_dir(sock_path_owned) != 0) {
                free(sock_path_owned);
                sock_path_owned = NULL;
                return -1;
        }

        unlink(sock_path_owned);

        listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (listen_fd < 0) {
                fprintf(stderr, "external: socket: %s\n", strerror(errno));
                free(sock_path_owned);
                sock_path_owned = NULL;
                return -1;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        if (strlen(sock_path_owned) >= sizeof(addr.sun_path)) {
                fprintf(stderr, "external: socket path too long\n");
                close(listen_fd);
                listen_fd = -1;
                free(sock_path_owned);
                sock_path_owned = NULL;
                return -1;
        }
        strncpy(addr.sun_path, sock_path_owned, sizeof(addr.sun_path) - 1);

        /*
         * World-accessible local control socket so non-root workers can
         * register when dcerpcd itself runs as root (port 445).
         */
        old_umask = umask(0);
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                umask(old_umask);
                fprintf(stderr, "external: bind %s: %s\n", sock_path_owned,
                        strerror(errno));
                close(listen_fd);
                listen_fd = -1;
                free(sock_path_owned);
                sock_path_owned = NULL;
                return -1;
        }
        umask(old_umask);
        if (chmod(sock_path_owned, 0666) != 0) {
                fprintf(stderr, "external: chmod %s: %s\n", sock_path_owned,
                        strerror(errno));
                /* non-fatal: owner can still connect */
        }

        if (listen(listen_fd, 8) != 0) {
                fprintf(stderr, "external: listen: %s\n", strerror(errno));
                close(listen_fd);
                unlink(sock_path_owned);
                listen_fd = -1;
                free(sock_path_owned);
                sock_path_owned = NULL;
                return -1;
        }
        {
                int flags = fcntl(listen_fd, F_GETFL, 0);

                if (flags >= 0) {
                        (void)fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK);
                }
        }

        ensure_clients_inited();

        printf("external: listening on %s for service registrations "
               "(async, main event loop)\n",
               sock_path_owned);
        return 0;
}

void
dcerpcd_external_shutdown(void)
{
        int i;

        for (i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].fd >= 0) {
                        client_close(&clients[i]);
                }
        }
        if (listen_fd >= 0) {
                close(listen_fd);
                listen_fd = -1;
        }
        if (sock_path_owned) {
                unlink(sock_path_owned);
                free(sock_path_owned);
                sock_path_owned = NULL;
        }
}
