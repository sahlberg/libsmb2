/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * External DCE/RPC service control channel for dcerpcd.
 * Listens on a Unix domain socket (default: /var/run/dcerpcd/dcerpcd.sock).
 * Creates the parent directory if needed.  A service process connects and
 * sends a length-prefixed YAML registration naming the pipe it serves.
 * While the connection stays up, the pipe is available as
 * DCERPCD_SVC_EXTERNAL and the interfaces it lists are in the endpoint
 * mapper. On disconnect the registrations are removed.
 * Wire format (registration request):
 *   uint32_t body_len;          // little-endian
 *   char     body[body_len];    // UTF-8 YAML, max 64 KiB
 * YAML body (example):
 *   Service:
 *     pipe: lsarpc
 *     annotation: LSA
 *     interfaces:               # optional, for the endpoint mapper only
 *       - uuid: 12345778-1234-abcd-ef00-0123456789ab
 *         version: 0.0
 *       - uuid: 3919286a-b10c-11d0-9ba8-00c04fd92ef5
 *         version: 0.0
 * Reply (ASCII, not length-prefixed):
 *   OK\n
 *   or
 *   ERROR: <message>\n
 * After registration the connection carries the pipe traffic, framed as
 * documented in dcerpcd_proto.h: dcerpcd sends OPEN, WRITE and CLOSE for
 * each client open of the pipe, the service sends OUTPUT and CLOSE. The
 * DCE/RPC is the service's; dcerpcd does not look into the bytes.
 *
 * Messages to a service are queued and written as its socket allows, so
 * a slow service never blocks dcerpcd. Service sockets and the listen fd
 * are driven from smb2_serve_port's select loop via
 * dcerpcd_external_fdset/service.
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
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
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
#define MAX_INTERFACES 16
/* Bytes queued for a service that has stopped reading */
#define MAX_OUT_QUEUE (64 * 1024 * 1024)

/* ------------------------------------------------------------------ */
/* Registration message parse                                          */
/* ------------------------------------------------------------------ */

struct reg_interface {
        dcerpc_uuid_t uuid;
        uint16_t vers_major;
        uint16_t vers_minor;
        char *uuid_str;
        char *version_str;
};

struct reg_msg {
        char *pipe;
        char *annotation;
        struct reg_interface ifs[MAX_INTERFACES];
        int nif;
};

static void
reg_msg_free(struct reg_msg *m)
{
        int i;

        if (m == NULL) {
                return;
        }
        free(m->pipe);
        free(m->annotation);
        for (i = 0; i < m->nif; i++) {
                free(m->ifs[i].uuid_str);
                free(m->ifs[i].version_str);
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
        int in_interfaces = 0;
        int cur_if = -1;
        int i;

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
                        in_interfaces = 0;
                        continue;
                }
                if (!in_service) {
                        continue;
                }

                /* list item under interfaces */
                if (in_interfaces && indent >= 4 && p[0] == '-' &&
                    (p[1] == ' ' || p[1] == '\0')) {
                        p++;
                        while (*p == ' ') {
                                p++;
                        }
                        if (out->nif >= MAX_INTERFACES) {
                                snprintf(err, errlen, "too many interfaces");
                                return -1;
                        }
                        cur_if = out->nif++;
                        memset(&out->ifs[cur_if], 0, sizeof(out->ifs[cur_if]));
                        if (*p == '\0') {
                                continue;
                        }
                        /* inline "- uuid: ..." */
                } else if (indent <= 2) {
                        in_interfaces = 0;
                }

                colon = strchr(p, ':');
                if (colon == NULL) {
                        continue;
                }
                *colon = '\0';
                key = trim(p);
                val = trim(colon + 1);

                if (!in_interfaces && !strcmp(key, "interfaces")) {
                        in_interfaces = 1;
                        cur_if = -1;
                        continue;
                }

                if (in_interfaces) {
                        if (cur_if < 0) {
                                continue;
                        }
                        if (!strcmp(key, "uuid")) {
                                free(out->ifs[cur_if].uuid_str);
                                out->ifs[cur_if].uuid_str = xstrdup(val);
                        } else if (!strcmp(key, "version")) {
                                free(out->ifs[cur_if].version_str);
                                out->ifs[cur_if].version_str = xstrdup(val);
                        }
                        continue;
                }

                if (!strcmp(key, "pipe")) {
                        free(out->pipe);
                        out->pipe = xstrdup(val);
                } else if (!strcmp(key, "annotation")) {
                        free(out->annotation);
                        out->annotation = xstrdup(val);
                }
        }

        if (out->pipe == NULL || out->pipe[0] == '\0') {
                snprintf(err, errlen, "missing Service.pipe");
                return -1;
        }
        for (i = 0; i < out->nif; i++) {
                struct reg_interface *ri = &out->ifs[i];

                if (ri->uuid_str == NULL || parse_uuid(ri->uuid_str, &ri->uuid)) {
                        snprintf(err, errlen, "interface %d: missing/invalid "
                                 "uuid", i);
                        return -1;
                }
                if (ri->version_str == NULL ||
                    parse_version(ri->version_str, &ri->vers_major,
                                  &ri->vers_minor)) {
                        snprintf(err, errlen, "interface %d: missing/invalid "
                                 "version", i);
                        return -1;
                }
        }
        return 0;
}

/* ------------------------------------------------------------------ */
/* Client connection state                                             */
/* ------------------------------------------------------------------ */

/* A client open of the service's pipe */
struct ext_pipe {
        struct ext_pipe *next;
        uint32_t id;
        dcerpcd_external_pipe_cb cb;
        void *cb_data;
};

struct ext_client {
        int fd;
        int registered;
        /* a write failed: closed from the main loop */
        int dead;
        /* read from the service, not yet a whole message */
        uint8_t *buf;
        size_t buflen;
        size_t bufcap;
        /* queued for the service: out[outoff..outlen) */
        uint8_t *out;
        size_t outoff;
        size_t outlen;
        size_t outcap;
        char name[64];
        struct ext_pipe *pipes;
};

static int listen_fd = -1;
static char *sock_path_owned;
static int clients_inited;
static uint32_t next_pipe_id = 1;

static struct ext_client clients[MAX_CLIENTS];

/* Unlink and free a pipe, telling its owner that it is broken */
static void
pipe_broken(struct ext_pipe **pp)
{
        struct ext_pipe *p = *pp;

        *pp = p->next;
        p->cb(p->cb_data, NULL, 0);
        free(p);
}

static void
client_close(struct ext_client *c)
{
        if (c == NULL || c->fd < 0) {
                return;
        }
        while (c->pipes) {
                pipe_broken(&c->pipes);
        }
        if (c->registered) {
                dcerpcd_epm_unregister_by_owner(c->fd);
                dcerpcd_service_remove_by_fd(c->fd);
                printf("external: disconnected service pipe=%s fd=%d\n",
                       c->name[0] ? c->name : "?", c->fd);
        }
        close(c->fd);
        free(c->buf);
        free(c->out);
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

/* The link to pipe id, or NULL. *cp is set to its service. */
static struct ext_pipe **
pipe_by_id(uint32_t id, struct ext_client **cp)
{
        int i;

        for (i = 0; i < MAX_CLIENTS; i++) {
                struct ext_pipe **pp;

                if (clients[i].fd < 0) {
                        continue;
                }
                for (pp = &clients[i].pipes; *pp; pp = &(*pp)->next) {
                        if ((*pp)->id == id) {
                                if (cp) {
                                        *cp = &clients[i];
                                }
                                return pp;
                        }
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

/* ------------------------------------------------------------------ */
/* Messages to the service                                             */
/* ------------------------------------------------------------------ */

/* Write what the socket takes. A write error marks the service dead. */
static void
client_flush(struct ext_client *c)
{
        while (!c->dead && c->outoff < c->outlen) {
                ssize_t n = write(c->fd, c->out + c->outoff,
                                  c->outlen - c->outoff);

                if (n < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                                fprintf(stderr, "external: write fd=%d: %s\n",
                                        c->fd, strerror(errno));
                                c->dead = 1;
                        }
                        break;
                }
                c->outoff += (size_t)n;
        }
        if (c->outoff == c->outlen) {
                c->outoff = 0;
                c->outlen = 0;
        }
}

/* Queue a message of a header and the payload a + b */
static int
client_send(struct ext_client *c, uint32_t type, uint32_t pipe_id,
            const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
        size_t need = DCERPCD_MSG_HDR_SIZE + alen + blen;

        if (c->dead || alen + blen > DCERPCD_MSG_MAX) {
                return -1;
        }
        if (c->outlen - c->outoff + need > MAX_OUT_QUEUE) {
                fprintf(stderr, "external: service %s fd=%d is not reading\n",
                        c->name, c->fd);
                return -1;
        }
        if (c->outoff && c->outlen + need > c->outcap) {
                memmove(c->out, c->out + c->outoff, c->outlen - c->outoff);
                c->outlen -= c->outoff;
                c->outoff = 0;
        }
        if (c->outlen + need > c->outcap) {
                size_t ncap = c->outcap ? c->outcap : 4096;
                uint8_t *nb;

                while (ncap < c->outlen + need) {
                        ncap *= 2;
                }
                nb = realloc(c->out, ncap);
                if (nb == NULL) {
                        return -1;
                }
                c->out = nb;
                c->outcap = ncap;
        }
        dcerpcd_msg_hdr_encode(c->out + c->outlen, type, pipe_id,
                               (uint32_t)(alen + blen));
        c->outlen += DCERPCD_MSG_HDR_SIZE;
        if (alen) {
                memcpy(c->out + c->outlen, a, alen);
                c->outlen += alen;
        }
        if (blen) {
                memcpy(c->out + c->outlen, b, blen);
                c->outlen += blen;
        }
        client_flush(c);
        return c->dead ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

/*
 * Pipe path helpers: accept "srvsvc", "\\pipe\\srvsvc", "/pipe/srvsvc".
 * Returns malloc'd base name ("srvsvc").
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
        if (*p == '\0' || strchr(p, '\\') || strchr(p, '/')) {
                return NULL;
        }
        return strdup(p);
}

static int
apply_registration(struct ext_client *c, struct reg_msg *msg, char *err,
                   size_t errlen)
{
        char *base;
        char tower_path[128];
        int i;

        base = pipe_base_name(msg->pipe);
        if (base == NULL || strlen(base) >= sizeof(c->name)) {
                snprintf(err, errlen, "invalid pipe name");
                free(base);
                return -1;
        }
        if (dcerpcd_service_add_external(base, msg->annotation, c->fd) != 0) {
                snprintf(err, errlen, "pipe '%s' is not available", base);
                free(base);
                return -1;
        }

        /* C string "\\pipe\\name" is the wire path \pipe\name */
        snprintf(tower_path, sizeof(tower_path), "\\pipe\\%s", base);
        for (i = 0; i < msg->nif; i++) {
                if (dcerpcd_epm_register_np(&msg->ifs[i].uuid,
                                            msg->ifs[i].vers_major,
                                            msg->ifs[i].vers_minor,
                                            NULL,
                                            tower_path,
                                            msg->annotation,
                                            NULL,
                                            c->fd) != 0) {
                        dcerpcd_service_remove_by_fd(c->fd);
                        dcerpcd_epm_unregister_by_owner(c->fd);
                        snprintf(err, errlen, "epm register failed");
                        free(base);
                        return -1;
                }
        }

        snprintf(c->name, sizeof(c->name), "%s", base);
        c->registered = 1;
        free(base);
        printf("external: registered service pipe=%s interfaces=%d fd=%d "
               "(%u epm entries total)\n",
               c->name, msg->nif, c->fd, dcerpcd_epm_count());
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
        body_len = dcerpcd_get_le32(c->buf);
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

/* ------------------------------------------------------------------ */
/* Messages from the service                                           */
/* ------------------------------------------------------------------ */

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

/* Handle the complete messages in c->buf. -1 drops the service. */
static int
client_try_messages(struct ext_client *c)
{
        while (c->buflen >= DCERPCD_MSG_HDR_SIZE) {
                struct dcerpcd_msg_hdr hdr;
                struct ext_pipe **pp;
                uint8_t *data;

                if (dcerpcd_msg_hdr_decode(c->buf, &hdr)) {
                        fprintf(stderr, "external: bad message from service "
                                "%s fd=%d\n", c->name, c->fd);
                        return -1;
                }
                if (c->buflen < DCERPCD_MSG_HDR_SIZE + hdr.len) {
                        return 0; /* need more */
                }
                pp = &c->pipes;
                while (*pp && (*pp)->id != hdr.pipe_id) {
                        pp = &(*pp)->next;
                }

                switch (hdr.type) {
                case DCERPCD_MSG_OUTPUT:
                        if (*pp == NULL || hdr.len == 0) {
                                break;
                        }
                        data = malloc(hdr.len);
                        if (data == NULL) {
                                return -1;
                        }
                        memcpy(data, c->buf + DCERPCD_MSG_HDR_SIZE, hdr.len);
                        (*pp)->cb((*pp)->cb_data, data, hdr.len);
                        break;
                case DCERPCD_MSG_CLOSE:
                        if (*pp) {
                                printf("external: service %s closed pipe "
                                       "id=%u\n", c->name, hdr.pipe_id);
                                pipe_broken(pp);
                        }
                        break;
                default:
                        fprintf(stderr, "external: unexpected message type "
                                "%u from service %s fd=%d\n", hdr.type,
                                c->name, c->fd);
                        return -1;
                }
                buf_consume(c, DCERPCD_MSG_HDR_SIZE + hdr.len);
        }
        return 0;
}

static int
client_on_readable(struct ext_client *c)
{
        uint8_t tmp[16384];
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
                /* pipe messages cannot come before OPEN, so none follow */
                return 0;
        }

        if (buf_append(c, tmp, (size_t)n) != 0) {
                return -1;
        }
        return client_try_messages(c);
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
/* Pipes                                                               */
/* ------------------------------------------------------------------ */

int
dcerpcd_external_open(int conn_fd,
                      uint32_t session_id,
                      int32_t uid,
                      const char *user,
                      dcerpcd_external_pipe_cb cb,
                      void *cb_data,
                      uint32_t *pipe_id)
{
        struct ext_client *c = client_by_fd(conn_fd);
        struct ext_pipe *p;
        uint8_t open[DCERPCD_OPEN_SIZE];

        if (c == NULL || !c->registered || cb == NULL) {
                return -1;
        }
        if (user == NULL) {
                user = "";
        }
        p = calloc(1, sizeof(*p));
        if (p == NULL) {
                return -1;
        }
        p->id = next_pipe_id++;
        if (next_pipe_id == 0) {
                next_pipe_id = 1;
        }
        p->cb = cb;
        p->cb_data = cb_data;

        dcerpcd_put_le32(open, session_id);
        dcerpcd_put_le32(open + 4, (uint32_t)uid);
        if (client_send(c, DCERPCD_MSG_OPEN, p->id, open, sizeof(open),
                        (const uint8_t *)user, strlen(user))) {
                free(p);
                return -1;
        }
        p->next = c->pipes;
        c->pipes = p;
        *pipe_id = p->id;
        return 0;
}

int
dcerpcd_external_write(uint32_t pipe_id, const uint8_t *buf, size_t len)
{
        struct ext_client *c = NULL;

        if (pipe_by_id(pipe_id, &c) == NULL) {
                return -1;
        }
        return client_send(c, DCERPCD_MSG_WRITE, pipe_id, buf, len, NULL, 0);
}

void
dcerpcd_external_close(uint32_t pipe_id)
{
        struct ext_client *c = NULL;
        struct ext_pipe **pp = pipe_by_id(pipe_id, &c);
        struct ext_pipe *p;

        if (pp == NULL) {
                return;
        }
        p = *pp;
        *pp = p->next;
        free(p);
        (void)client_send(c, DCERPCD_MSG_CLOSE, pipe_id, NULL, 0, NULL, 0);
}

/* ------------------------------------------------------------------ */
/* Main loop                                                           */
/* ------------------------------------------------------------------ */

void
dcerpcd_external_fdset(fd_set *rfds, fd_set *wfds, int *maxfd)
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
                if (clients[i].fd < 0) {
                        continue;
                }
                FD_SET(clients[i].fd, rfds);
                if (wfds && clients[i].outlen > clients[i].outoff) {
                        FD_SET(clients[i].fd, wfds);
                }
                if (clients[i].fd > *maxfd) {
                        *maxfd = clients[i].fd;
                }
        }
}

void
dcerpcd_external_service(fd_set *rfds, fd_set *wfds)
{
        int i;

        ensure_clients_inited();

        if (rfds && listen_fd >= 0 && FD_ISSET(listen_fd, rfds)) {
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
                struct ext_client *c = &clients[i];

                if (c->fd < 0) {
                        continue;
                }
                if (wfds && FD_ISSET(c->fd, wfds)) {
                        client_flush(c);
                }
                if (!c->dead && rfds && FD_ISSET(c->fd, rfds) &&
                    client_on_readable(c) < 0) {
                        c->dead = 1;
                }
                if (c->dead) {
                        client_close(c);
                }
        }
}

void
dcerpcd_external_serve_fdset(struct smb2_server *server _U_,
                             fd_set *rfds, fd_set *wfds, int *maxfd)
{
        dcerpcd_external_fdset(rfds, wfds, maxfd);
}

void
dcerpcd_external_serve_service(struct smb2_server *server _U_,
                               fd_set *rfds, fd_set *wfds)
{
        dcerpcd_external_service(rfds, wfds);
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
        mode_t mode;
        const char *sock = path && path[0] ? path : DCERPCD_DEFAULT_SVC_SOCK;
        const char *group = dcerpcd_config_get()->svc_group;
        gid_t gid = (gid_t)-1;

        if (listen_fd >= 0) {
                return 0;
        }

        /*
         * Whoever can connect can register a pipe name not taken yet and
         * serve that interface to remote clients. With svc_group only
         * that group (and root) can; else any local user, so that non-root
         * workers can register when dcerpcd runs as root (port 445).
         */
        if (group != NULL && group[0] != '\0') {
                struct group *gr = getgrnam(group);

                if (gr == NULL) {
                        fprintf(stderr, "external: svc_group %s: no such "
                                "group\n", group);
                        return -1;
                }
                gid = gr->gr_gid;
                mode = 0660;
        } else {
                mode = 0666;
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

        /* Created with the final mode: nobody else gets a window */
        old_umask = umask(~mode & 0777);
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
        if (gid != (gid_t)-1 && chown(sock_path_owned, (uid_t)-1, gid) != 0) {
                fprintf(stderr, "external: chown %s to group %s: %s\n",
                        sock_path_owned, group, strerror(errno));
                close(listen_fd);
                unlink(sock_path_owned);
                listen_fd = -1;
                free(sock_path_owned);
                sock_path_owned = NULL;
                return -1;
        }
        if (chmod(sock_path_owned, mode) != 0) {
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
