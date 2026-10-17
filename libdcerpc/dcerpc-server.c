/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Connection-oriented DCE/RPC server runtime ([C706] 12, [MS-RPCE] 2.2.2)
 * for named pipes, without the transport. See <dcerpc/server.h>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/server.h>

#include "dcerpc-private.h"

/* PDU types and flags ([C706] 12.6.3.1, 12.6.3.3) */
#define PTYPE_REQUEST            0
#define PTYPE_RESPONSE           2
#define PTYPE_FAULT              3
#define PTYPE_BIND              11
#define PTYPE_BIND_ACK          12
#define PTYPE_ALTER_CONTEXT     14
#define PTYPE_ALTER_CONTEXT_RESP 15
#define PTYPE_AUTH3             16
#define PTYPE_SHUTDOWN          17
#define PTYPE_CO_CANCEL         18
#define PTYPE_ORPHANED          19

#define PFC_FIRST_FRAG          0x01
#define PFC_LAST_FRAG           0x02
#define PFC_OBJECT_UUID         0x80

#define DREP_LITTLE_ENDIAN      0x10

/* p_cont_def_result_t and p_provider_reason_t ([C706] 12.6.3.1) */
#define RESULT_ACCEPTANCE       0
#define RESULT_PROVIDER_REJECTION 2
#define RESULT_NEGOTIATE_ACK    3
#define REASON_NOT_SPECIFIED    0
#define REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED 1
#define REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED 2

#define COMMON_HDR              16
#define REQUEST_HDR             8   /* alloc_hint, p_cont_id, opnum */
#define RESPONSE_HDR            8   /* alloc_hint, p_cont_id, cancel, pad */

/*
 * Largest fragment: frag_length is 16 bits; a multiple of 8 so stub data
 * in a non-final fragment stays 8-aligned.
 */
#define MAX_FRAG                0xfff8
/* Fragment size before a BIND has negotiated one */
#define DEFAULT_FRAG            4280
/* Largest reassembled REQUEST stub */
#define MAX_REQUEST_STUB        (4 * 1024 * 1024)
#define ASSOC_GROUP             0x12345

/* Bind time feature negotiation: 6cb71c2c-9812-4540-<bitmask> v1 */
#define BTFN_V1                 0x6cb71c2c
#define BTFN_V2                 0x9812
#define BTFN_V3                 0x4540

struct server_iface {
        struct server_iface *next;
        p_syntax_id_t syntax;
        const struct dcerpc_procedure *procs;
        const struct dcerpc_stub *stubs;
        dcerpc_server_dispatch_fn fn;
        void *private_data;
        uint32_t flavors;
};

struct dcerpc_server {
        char *pipe_name;
        struct server_iface *ifaces;
        struct dcerpc_context *dce;     /* for the coders */
        int npipes;
        uint16_t max_xmit;              /* 0, or the largest we send */
};

struct pres_context {
        uint16_t id;
        struct server_iface *iface;
        int ndr64;
};

struct dcerpc_server_call {
        struct dcerpc_server_call *next;
        struct dcerpc_server_pipe *pipe;   /* NULL when detached */
        struct server_iface *iface;
        uint32_t call_id;
        uint16_t context_id;
        uint16_t opnum;
        uint32_t flags;                    /* request NDR flavor */
        uint32_t reply_flags;
        uint8_t *stub;
        size_t stub_len;
};

struct dcerpc_server_pipe {
        struct dcerpc_server *srv;
        void *private_data;

        struct pres_context *contexts;
        int ncontexts;
        uint16_t max_xmit;

        /* bytes written that do not yet form a complete PDU */
        uint8_t *in_buf;
        size_t in_len;

        /* a fragmented REQUEST being reassembled */
        int req_active;
        uint32_t req_call_id;
        uint16_t req_context_id;
        uint16_t req_opnum;
        int req_little_endian;
        uint8_t *req_stub;
        size_t req_stub_len;

        /* output PDUs back to back; reads return one fragment at a time */
        uint8_t *out_buf;
        size_t out_len;
        size_t out_pos;
        size_t out_frag_left;

        struct dcerpc_server_call *calls;  /* dispatched, not finished */
};

static uint16_t
get16(const uint8_t *p, int le)
{
        return le ? (uint16_t)(p[0] | (p[1] << 8)) :
                    (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t
get32(const uint8_t *p, int le)
{
        return le ? (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24) :
                    ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                    ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void
put16(uint8_t *p, uint16_t v)
{
        p[0] = (uint8_t)v;
        p[1] = (uint8_t)(v >> 8);
}

static void
put32(uint8_t *p, uint32_t v)
{
        p[0] = (uint8_t)v;
        p[1] = (uint8_t)(v >> 8);
        p[2] = (uint8_t)(v >> 16);
        p[3] = (uint8_t)(v >> 24);
}

/*
 * A p_syntax_id_t on the wire, in the PDU's byte order: the UUID and a
 * 32-bit if_version, the major version in the low 16 bits and the minor
 * in the high 16 ([C706] 12.6.3.1).
 */
static void
get_syntax(const uint8_t *p, int le, p_syntax_id_t *s)
{
        uint32_t version;

        s->uuid.v1 = get32(p, le);
        s->uuid.v2 = get16(p + 4, le);
        s->uuid.v3 = get16(p + 6, le);
        memcpy(s->uuid.v4, p + 8, 8);
        version = get32(p + 16, le);
        s->vers = (uint16_t)version;
        s->vers_minor = (uint16_t)(version >> 16);
}

/* A p_syntax_id_t in a little-endian reply */
static void
put_syntax(uint8_t *p, const p_syntax_id_t *s)
{
        put32(p, s->uuid.v1);
        put16(p + 4, s->uuid.v2);
        put16(p + 6, s->uuid.v3);
        memcpy(p + 8, s->uuid.v4, 8);
        put32(p + 16, (uint32_t)s->vers | ((uint32_t)s->vers_minor << 16));
}

static int
uuid_equal(const dcerpc_uuid_t *a, const dcerpc_uuid_t *b)
{
        return a->v1 == b->v1 && a->v2 == b->v2 && a->v3 == b->v3 &&
               !memcmp(a->v4, b->v4, 8);
}

static int
syntax_equal(const p_syntax_id_t *a, const p_syntax_id_t *b)
{
        return uuid_equal(&a->uuid, &b->uuid) && a->vers == b->vers &&
               a->vers_minor == b->vers_minor;
}

/* ------------------------------------------------------------------ */
/* Server and interfaces                                               */
/* ------------------------------------------------------------------ */

struct dcerpc_server *
dcerpc_server_create(const char *pipe_name)
{
        struct dcerpc_server *srv;

        if (pipe_name == NULL) {
                return NULL;
        }
        srv = calloc(1, sizeof(*srv));
        if (srv == NULL) {
                return NULL;
        }
        srv->pipe_name = strdup(pipe_name);
        srv->dce = dcerpc_create_context(NULL);
        if (srv->pipe_name == NULL || srv->dce == NULL) {
                dcerpc_server_destroy(srv);
                return NULL;
        }
        return srv;
}

void
dcerpc_server_destroy(struct dcerpc_server *srv)
{
        struct server_iface *i;

        if (srv == NULL) {
                return;
        }
        while ((i = srv->ifaces) != NULL) {
                srv->ifaces = i->next;
                free(i);
        }
        if (srv->dce) {
                dcerpc_destroy_context(srv->dce);
        }
        free(srv->pipe_name);
        free(srv);
}

int
dcerpc_server_set_max_xmit_frag(struct dcerpc_server *srv, uint16_t max)
{
        max &= ~(uint16_t)7;
        if (max < COMMON_HDR + RESPONSE_HDR + 8) {
                return -1;
        }
        srv->max_xmit = max;
        return 0;
}

const char *
dcerpc_server_get_pipe_name(struct dcerpc_server *srv)
{
        return srv->pipe_name;
}

static struct server_iface *
find_iface(struct dcerpc_server *srv, const p_syntax_id_t *syntax)
{
        struct server_iface *i;

        for (i = srv->ifaces; i; i = i->next) {
                if (syntax_equal(&i->syntax, syntax)) {
                        return i;
                }
        }
        return NULL;
}

static int
add_iface(struct dcerpc_server *srv, const p_syntax_id_t *interface,
          const struct dcerpc_procedure *procs,
          const struct dcerpc_stub *stubs,
          dcerpc_server_dispatch_fn fn, void *private_data,
          uint32_t flavors)
{
        struct server_iface *i;

        if (interface == NULL || find_iface(srv, interface)) {
                return -1;
        }
        i = calloc(1, sizeof(*i));
        if (i == NULL) {
                return -1;
        }
        i->syntax = *interface;
        i->procs = procs;
        i->stubs = stubs;
        i->fn = fn;
        i->private_data = private_data;
        i->flavors = flavors & DCERPC_SERVER_ALL_NDR;
        i->next = srv->ifaces;
        srv->ifaces = i;
        return 0;
}

int
dcerpc_server_add_interface(struct dcerpc_server *srv,
                            const p_syntax_id_t *interface,
                            const struct dcerpc_procedure *procs,
                            const struct dcerpc_stub *stubs,
                            uint32_t flavors)
{
        if (procs == NULL || stubs == NULL) {
                return -1;
        }
        return add_iface(srv, interface, procs, stubs, NULL, NULL, flavors);
}

int
dcerpc_server_add_raw_interface(struct dcerpc_server *srv,
                                const p_syntax_id_t *interface,
                                dcerpc_server_dispatch_fn fn,
                                void *private_data,
                                uint32_t flavors)
{
        if (fn == NULL) {
                return -1;
        }
        return add_iface(srv, interface, NULL, NULL, fn, private_data,
                         flavors);
}

/* ------------------------------------------------------------------ */
/* Pipes and output                                                    */
/* ------------------------------------------------------------------ */

struct dcerpc_server_pipe *
dcerpc_server_pipe_create(struct dcerpc_server *srv, void *private_data)
{
        struct dcerpc_server_pipe *pipe;

        pipe = calloc(1, sizeof(*pipe));
        if (pipe == NULL) {
                return NULL;
        }
        pipe->srv = srv;
        pipe->private_data = private_data;
        srv->npipes++;
        return pipe;
}

void
dcerpc_server_pipe_destroy(struct dcerpc_server_pipe *pipe)
{
        struct dcerpc_server_call *c;

        if (pipe == NULL) {
                return;
        }
        for (c = pipe->calls; c; c = c->next) {
                c->pipe = NULL;
        }
        pipe->srv->npipes--;
        free(pipe->contexts);
        free(pipe->in_buf);
        free(pipe->req_stub);
        free(pipe->out_buf);
        free(pipe);
}

void *
dcerpc_server_pipe_get_private(struct dcerpc_server_pipe *pipe)
{
        return pipe->private_data;
}

struct dcerpc_server *
dcerpc_server_pipe_get_server(struct dcerpc_server_pipe *pipe)
{
        return pipe->srv;
}

int
dcerpc_server_pipe_has_output(struct dcerpc_server_pipe *pipe)
{
        return pipe->out_pos < pipe->out_len;
}

int
dcerpc_server_pipe_calls_pending(struct dcerpc_server_pipe *pipe)
{
        struct dcerpc_server_call *c;
        int n = 0;

        for (c = pipe->calls; c; c = c->next) {
                n++;
        }
        return n;
}

size_t
dcerpc_server_pipe_read(struct dcerpc_server_pipe *pipe, uint8_t *buf,
                        size_t max, int *more)
{
        size_t len;

        *more = 0;
        if (pipe->out_pos >= pipe->out_len) {
                return 0;
        }
        if (pipe->out_frag_left == 0) {
                pipe->out_frag_left = get16(pipe->out_buf + pipe->out_pos + 8,
                                            1);
        }
        len = pipe->out_frag_left;
        if (len > max) {
                len = max;
                *more = 1;
        }
        memcpy(buf, pipe->out_buf + pipe->out_pos, len);
        pipe->out_pos += len;
        pipe->out_frag_left -= len;
        if (pipe->out_pos == pipe->out_len) {
                pipe->out_pos = 0;
                pipe->out_len = 0;
        }
        return len;
}

/* Room for len more output bytes; returns where they go */
static uint8_t *
out_reserve(struct dcerpc_server_pipe *pipe, size_t len)
{
        uint8_t *nb;

        if (pipe->out_pos > 0) {
                memmove(pipe->out_buf, pipe->out_buf + pipe->out_pos,
                        pipe->out_len - pipe->out_pos);
                pipe->out_len -= pipe->out_pos;
                pipe->out_pos = 0;
        }
        nb = realloc(pipe->out_buf, pipe->out_len + len);
        if (nb == NULL) {
                return NULL;
        }
        pipe->out_buf = nb;
        memset(nb + pipe->out_len, 0, len);
        pipe->out_len += len;
        return nb + pipe->out_len - len;
}

/* The common header of a little-endian output PDU */
static void
put_common(uint8_t *p, uint8_t ptype, uint8_t pfc, uint16_t frag_len,
           uint32_t call_id)
{
        p[0] = 5;
        p[1] = 0;
        p[2] = ptype;
        p[3] = pfc;
        p[4] = DREP_LITTLE_ENDIAN;
        put16(p + 8, frag_len);
        put16(p + 10, 0);
        put32(p + 12, call_id);
}

static int
queue_fault(struct dcerpc_server_pipe *pipe, uint32_t call_id,
            uint16_t context_id, uint32_t status)
{
        uint8_t *p = out_reserve(pipe, 32);

        if (p == NULL) {
                return -1;
        }
        put_common(p, PTYPE_FAULT, PFC_FIRST_FRAG | PFC_LAST_FRAG, 32,
                   call_id);
        put32(p + 16, 0);               /* alloc_hint */
        put16(p + 20, context_id);
        p[22] = 0;                      /* cancel_count */
        put32(p + 24, status);
        return 0;
}

/*
 * A RESPONSE in fragments of at most the negotiated size; the stub data
 * of all but the last is a multiple of 8.
 */
static int
queue_response(struct dcerpc_server_pipe *pipe, uint32_t call_id,
               uint16_t context_id, const uint8_t *stub, size_t stub_len)
{
        size_t max_xmit = pipe->max_xmit ? pipe->max_xmit : DEFAULT_FRAG;
        size_t max_stub = (max_xmit - COMMON_HDR - RESPONSE_HDR) & ~(size_t)7;
        size_t off = 0;

        do {
                size_t chunk = stub_len - off;
                uint8_t pfc = 0;
                uint8_t *p;

                if (chunk > max_stub) {
                        chunk = max_stub;
                }
                if (off == 0) {
                        pfc |= PFC_FIRST_FRAG;
                }
                if (off + chunk == stub_len) {
                        pfc |= PFC_LAST_FRAG;
                }
                p = out_reserve(pipe, COMMON_HDR + RESPONSE_HDR + chunk);
                if (p == NULL) {
                        return -1;
                }
                put_common(p, PTYPE_RESPONSE, pfc,
                           (uint16_t)(COMMON_HDR + RESPONSE_HDR + chunk),
                           call_id);
                put32(p + 16, (uint32_t)(stub_len - off));
                put16(p + 20, context_id);
                if (chunk) {
                        memcpy(p + COMMON_HDR + RESPONSE_HDR, stub + off,
                               chunk);
                }
                off += chunk;
        } while (off < stub_len);
        return 0;
}

/* ------------------------------------------------------------------ */
/* BIND and ALTER_CONTEXT                                              */
/* ------------------------------------------------------------------ */

static struct pres_context *
find_context(struct dcerpc_server_pipe *pipe, uint16_t id)
{
        int i;

        for (i = 0; i < pipe->ncontexts; i++) {
                if (pipe->contexts[i].id == id) {
                        return &pipe->contexts[i];
                }
        }
        return NULL;
}

static int
add_context(struct dcerpc_server_pipe *pipe, uint16_t id,
            struct server_iface *iface, int ndr64)
{
        struct pres_context *c = find_context(pipe, id);

        if (c == NULL) {
                c = realloc(pipe->contexts,
                            (pipe->ncontexts + 1) * sizeof(*c));
                if (c == NULL) {
                        return -1;
                }
                pipe->contexts = c;
                c = &pipe->contexts[pipe->ncontexts++];
        }
        c->id = id;
        c->iface = iface;
        c->ndr64 = ndr64;
        return 0;
}

/*
 * The result for one presentation context: accept the interface with
 * NDR64 if it allows that and the client offers it, else with NDR32.
 */
static void
negotiate_context(struct dcerpc_server_pipe *pipe, const uint8_t *ctx,
                  uint8_t n_ts, int le, uint8_t *res)
{
        p_syntax_id_t abstract, ts;
        struct server_iface *iface;
        uint32_t ndr32 = le ? DCERPC_SERVER_NDR32_LE : DCERPC_SERVER_NDR32_BE;
        uint32_t ndr64 = le ? DCERPC_SERVER_NDR64_LE : DCERPC_SERVER_NDR64_BE;
        int j, found32 = -1, found64 = -1;

        get_syntax(ctx + 4, le, &abstract);
        for (j = 0; j < n_ts; j++) {
                get_syntax(ctx + 24 + 20 * j, le, &ts);
                if (ts.uuid.v1 == BTFN_V1 && ts.uuid.v2 == BTFN_V2 &&
                    ts.uuid.v3 == BTFN_V3 && ts.vers == 1) {
                        /* we support none of the features */
                        put16(res, RESULT_NEGOTIATE_ACK);
                        put16(res + 2, 0);
                        return;
                }
                if (syntax_equal(&ts, &ndr32_syntax)) {
                        found32 = j;
                }
                if (syntax_equal(&ts, &ndr64_syntax)) {
                        found64 = j;
                }
        }

        put16(res, RESULT_PROVIDER_REJECTION);
        iface = find_iface(pipe->srv, &abstract);
        if (iface == NULL) {
                put16(res + 2, REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED);
                return;
        }
        if (found64 >= 0 && (iface->flavors & ndr64)) {
                if (add_context(pipe, get16(ctx, le), iface, 1) == 0) {
                        put16(res, RESULT_ACCEPTANCE);
                        put_syntax(res + 4, &ndr64_syntax);
                }
                return;
        }
        if (found32 >= 0 && (iface->flavors & ndr32)) {
                if (add_context(pipe, get16(ctx, le), iface, 0) == 0) {
                        put16(res, RESULT_ACCEPTANCE);
                        put_syntax(res + 4, &ndr32_syntax);
                }
                return;
        }
        put16(res + 2, REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED);
}

static int
process_bind(struct dcerpc_server_pipe *pipe, const uint8_t *pdu, size_t len,
             int le)
{
        int alter = pdu[2] == PTYPE_ALTER_CONTEXT;
        uint32_t call_id = get32(pdu + 12, le);
        uint16_t max_xmit, max_recv;
        uint32_t assoc;
        uint8_t n_ctx;
        size_t pos, o, sec_len;
        char sec_addr[128];
        uint8_t *p;
        int i;

        if (len < COMMON_HDR + 12) {
                return -1;
        }
        /*
         * Our max_xmit may not exceed the client's max_recv, and our
         * max_recv need not exceed its max_xmit.
         */
        max_xmit = get16(pdu + COMMON_HDR + 2, le);
        max_recv = get16(pdu + COMMON_HDR, le);
        if (max_xmit < COMMON_HDR + RESPONSE_HDR + 8 || max_xmit > MAX_FRAG) {
                max_xmit = MAX_FRAG;
        }
        if (max_recv == 0 || max_recv > MAX_FRAG) {
                max_recv = MAX_FRAG;
        }
        if (pipe->srv->max_xmit && max_xmit > pipe->srv->max_xmit) {
                max_xmit = pipe->srv->max_xmit;
        }
        assoc = get32(pdu + COMMON_HDR + 4, le);
        n_ctx = pdu[COMMON_HDR + 8];

        if (alter) {
                sec_addr[0] = '\0';
                sec_len = 0;
        } else {
                snprintf(sec_addr, sizeof(sec_addr), "\\PIPE\\%s",
                         pipe->srv->pipe_name);
                sec_len = strlen(sec_addr) + 1;
        }
        /* header, frag sizes, assoc, sec_addr, pad, n_results, results */
        o = COMMON_HDR + 8 + 2 + sec_len;
        o = (o + 3) & ~(size_t)3;
        p = out_reserve(pipe, o + 4 + 24 * (size_t)n_ctx);
        if (p == NULL) {
                return -1;
        }
        if (!alter) {
                pipe->max_xmit = max_xmit;
        }
        put_common(p, alter ? PTYPE_ALTER_CONTEXT_RESP : PTYPE_BIND_ACK,
                   PFC_FIRST_FRAG | PFC_LAST_FRAG,
                   (uint16_t)(o + 4 + 24 * n_ctx), call_id);
        put16(p + COMMON_HDR, pipe->max_xmit ? pipe->max_xmit : max_xmit);
        put16(p + COMMON_HDR + 2, max_recv);
        put32(p + COMMON_HDR + 4, assoc ? assoc : ASSOC_GROUP);
        put16(p + COMMON_HDR + 8, (uint16_t)sec_len);
        memcpy(p + COMMON_HDR + 10, sec_addr, sec_len);
        p[o] = n_ctx;

        pos = COMMON_HDR + 12;
        for (i = 0; i < n_ctx; i++) {
                uint8_t *res = p + o + 4 + 24 * i;
                uint8_t n_ts;

                if (pos + 24 > len) {
                        put16(res, RESULT_PROVIDER_REJECTION);
                        continue;
                }
                n_ts = pdu[pos + 2];
                if (pos + 24 + 20 * (size_t)n_ts > len) {
                        put16(res, RESULT_PROVIDER_REJECTION);
                        pos = len;
                        continue;
                }
                negotiate_context(pipe, pdu + pos, n_ts, le, res);
                pos += 24 + 20 * (size_t)n_ts;
        }
        return 0;
}

/* ------------------------------------------------------------------ */
/* Calls                                                               */
/* ------------------------------------------------------------------ */

uint16_t
dcerpc_server_call_opnum(struct dcerpc_server_call *call)
{
        return call->opnum;
}

const p_syntax_id_t *
dcerpc_server_call_interface(struct dcerpc_server_call *call)
{
        return &call->iface->syntax;
}

const uint8_t *
dcerpc_server_call_stub(struct dcerpc_server_call *call, size_t *len)
{
        *len = call->stub_len;
        return call->stub;
}

uint32_t
dcerpc_server_call_flags(struct dcerpc_server_call *call)
{
        return call->flags;
}

uint32_t
dcerpc_server_call_reply_flags(struct dcerpc_server_call *call)
{
        return call->reply_flags;
}

struct dcerpc_server_pipe *
dcerpc_server_call_get_pipe(struct dcerpc_server_call *call)
{
        return call->pipe;
}

static void
call_free(struct dcerpc_server_call *call)
{
        struct dcerpc_server_call **cp;

        if (call->pipe) {
                for (cp = &call->pipe->calls; *cp; cp = &(*cp)->next) {
                        if (*cp == call) {
                                *cp = call->next;
                                break;
                        }
                }
        }
        free(call->stub);
        free(call);
}

int
dcerpc_server_call_reply(struct dcerpc_server_call *call,
                         const uint8_t *stub, size_t len)
{
        int rc = 0;

        if (call->pipe) {
                rc = queue_response(call->pipe, call->call_id,
                                    call->context_id, stub, len);
        }
        call_free(call);
        return rc;
}

int
dcerpc_server_call_fault(struct dcerpc_server_call *call, uint32_t status)
{
        int rc = 0;

        if (call->pipe) {
                rc = queue_fault(call->pipe, call->call_id, call->context_id,
                                 status);
        }
        call_free(call);
        return rc;
}

static const struct dcerpc_procedure *
find_proc(const struct dcerpc_procedure *procs, uint16_t opnum)
{
        for (; procs->name && procs->opnum >= 0; procs++) {
                if (procs->opnum == opnum) {
                        return procs;
                }
        }
        return NULL;
}

static const struct dcerpc_stub *
find_stub(const struct dcerpc_stub *stubs, uint16_t opnum)
{
        for (; stubs->name && stubs->opnum >= 0; stubs++) {
                if (stubs->opnum == opnum) {
                        return stubs;
                }
        }
        return NULL;
}

/*
 * Decode the request with the interface's coder, run the stub and encode
 * its reply.
 */
static int
dispatch_coders(struct dcerpc_server_call *call)
{
        struct dcerpc_server *srv = call->pipe->srv;
        struct dcerpc_context *dce = srv->dce;
        const struct dcerpc_procedure *proc;
        const struct dcerpc_stub *stub;
        struct dcerpc_pdu *req_pdu, *rep_pdu;
        struct dcerpc_iovec iov;
        void *req, *rep;
        int rc, status;

        proc = find_proc(call->iface->procs, call->opnum);
        stub = find_stub(call->iface->stubs, call->opnum);
        if (proc == NULL || stub == NULL || stub->fn == NULL) {
                return dcerpc_server_call_fault(call,
                                                DCERPC_FAULT_OP_RNG_ERROR);
        }

        req_pdu = dcerpc_allocate_pdu(dce, DCERPC_DECODE | ENCODING_NDR |
                                      call->flags, proc->req_size);
        if (req_pdu == NULL) {
                return dcerpc_server_call_fault(call, DCERPC_FAULT_OTHER);
        }
        dcerpc_pdu_set_server_call(req_pdu, call);
        req = dcerpc_get_pdu_payload(req_pdu);
        iov = (struct dcerpc_iovec){
                .buf = call->stub,
                .max_offset = call->stub_len,
        };
        if (dcerpc_do_coder("Request", dce, req_pdu, &iov, req,
                            proc->req_coder)) {
                dcerpc_free_pdu(dce, req_pdu);
                return dcerpc_server_call_fault(call, DCERPC_FAULT_NDR);
        }

        rep = calloc(1, proc->rep_size);
        if (rep == NULL) {
                dcerpc_free_pdu(dce, req_pdu);
                return dcerpc_server_call_fault(call, DCERPC_FAULT_OTHER);
        }
        status = stub->fn(dce, req_pdu, req, rep);
        if (status) {
                free(rep);
                dcerpc_free_pdu(dce, req_pdu);
                return dcerpc_server_call_fault(call, status < 0 ?
                                                DCERPC_FAULT_OTHER :
                                                (uint32_t)status);
        }

        rep_pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE | ENCODING_NDR |
                                      call->reply_flags, 16);
        if (rep_pdu == NULL) {
                free(rep);
                dcerpc_free_pdu(dce, req_pdu);
                return dcerpc_server_call_fault(call, DCERPC_FAULT_OTHER);
        }
        dcerpc_set_request(rep_pdu, req);
        /* the reply's full pointers continue after the request's */
        dcerpc_set_full_pointer_id(rep_pdu,
                                   dcerpc_get_full_pointer_id(req_pdu));
        iov = (struct dcerpc_iovec){0};
        if (dcerpc_do_coder("Response", dce, rep_pdu, &iov, rep,
                            proc->rep_coder)) {
                rc = dcerpc_server_call_fault(call, DCERPC_FAULT_NDR);
        } else {
                rc = dcerpc_server_call_reply(call, iov.buf, iov.offset);
        }
        dcerpc_free_iovec(&iov);
        dcerpc_free_pdu(dce, rep_pdu);
        free(rep);
        dcerpc_free_pdu(dce, req_pdu);
        return rc;
}

/* Dispatch a reassembled REQUEST; takes the stub */
static int
dispatch(struct dcerpc_server_pipe *pipe, uint32_t call_id,
         struct pres_context *ctx, uint16_t opnum, int le,
         uint8_t *stub, size_t stub_len)
{
        struct dcerpc_server_call *call;
        uint32_t flavor;

        flavor = ctx->ndr64 ?
                (le ? DCERPC_SERVER_NDR64_LE : DCERPC_SERVER_NDR64_BE) :
                (le ? DCERPC_SERVER_NDR32_LE : DCERPC_SERVER_NDR32_BE);
        if (!(ctx->iface->flavors & flavor)) {
                free(stub);
                return queue_fault(pipe, call_id, ctx->id,
                                   DCERPC_FAULT_PROTO_ERROR);
        }

        call = calloc(1, sizeof(*call));
        if (call == NULL) {
                free(stub);
                return queue_fault(pipe, call_id, ctx->id,
                                   DCERPC_FAULT_OTHER);
        }
        call->pipe = pipe;
        call->iface = ctx->iface;
        call->call_id = call_id;
        call->context_id = ctx->id;
        call->opnum = opnum;
        call->flags = (ctx->ndr64 ? DCERPC_NDR64 : 0) |
                      (le ? 0 : DCERPC_BIG_ENDIAN);
        call->reply_flags = ctx->ndr64 ? DCERPC_NDR64 : 0;
        call->stub = stub;
        call->stub_len = stub_len;
        call->next = pipe->calls;
        pipe->calls = call;

        if (ctx->iface->fn == NULL) {
                return dispatch_coders(call);
        }
        /* a raw dispatcher may finish the call later */
        if (ctx->iface->fn(call, ctx->iface->private_data)) {
                struct dcerpc_server_call *c;

                for (c = pipe->calls; c; c = c->next) {
                        if (c == call) {
                                return dcerpc_server_call_fault(
                                        call, DCERPC_FAULT_OTHER);
                        }
                }
        }
        return 0;
}

/* One REQUEST fragment; the stub is dispatched at PFC_LAST_FRAG */
static int
process_request(struct dcerpc_server_pipe *pipe, const uint8_t *pdu,
                size_t len, int le)
{
        uint8_t pfc = pdu[3];
        uint16_t auth_len = get16(pdu + 10, le);
        uint32_t call_id = get32(pdu + 12, le);
        uint16_t context_id;
        size_t hdr = COMMON_HDR + REQUEST_HDR;
        size_t end = len;
        size_t stub_len;
        struct pres_context *ctx;
        uint8_t *ns;

        if (len < hdr) {
                return queue_fault(pipe, call_id, 0,
                                   DCERPC_FAULT_PROTO_ERROR);
        }
        context_id = get16(pdu + COMMON_HDR + 4, le);
        if (pfc & PFC_OBJECT_UUID) {
                hdr += 16;
        }
        if (auth_len) {
                /* drop the sec_trailer, the auth value and the padding */
                if (len < hdr + 8 + (size_t)auth_len) {
                        return queue_fault(pipe, call_id, context_id,
                                           DCERPC_FAULT_PROTO_ERROR);
                }
                end = len - 8 - auth_len;
                if (pdu[end + 2] > end - hdr) {
                        return queue_fault(pipe, call_id, context_id,
                                           DCERPC_FAULT_PROTO_ERROR);
                }
                end -= pdu[end + 2];
        }
        if (end < hdr) {
                return queue_fault(pipe, call_id, context_id,
                                   DCERPC_FAULT_PROTO_ERROR);
        }
        stub_len = end - hdr;

        if (pfc & PFC_FIRST_FRAG) {
                pipe->req_active = 1;
                pipe->req_call_id = call_id;
                pipe->req_context_id = context_id;
                pipe->req_opnum = get16(pdu + COMMON_HDR + 6, le);
                pipe->req_little_endian = le;
                pipe->req_stub_len = 0;
        } else if (!pipe->req_active || call_id != pipe->req_call_id) {
                pipe->req_active = 0;
                return queue_fault(pipe, call_id, context_id,
                                   DCERPC_FAULT_PROTO_ERROR);
        }
        if (stub_len > MAX_REQUEST_STUB - pipe->req_stub_len) {
                pipe->req_active = 0;
                return queue_fault(pipe, call_id, context_id,
                                   DCERPC_FAULT_PROTO_ERROR);
        }
        if (stub_len) {
                ns = realloc(pipe->req_stub, pipe->req_stub_len + stub_len);
                if (ns == NULL) {
                        pipe->req_active = 0;
                        return -1;
                }
                pipe->req_stub = ns;
                memcpy(ns + pipe->req_stub_len, pdu + hdr, stub_len);
                pipe->req_stub_len += stub_len;
        }
        if (!(pfc & PFC_LAST_FRAG)) {
                return 0;
        }
        pipe->req_active = 0;

        if (pipe->ncontexts == 0) {
                return queue_fault(pipe, call_id, context_id,
                                   DCERPC_FAULT_PROTO_ERROR);
        }
        ctx = find_context(pipe, pipe->req_context_id);
        if (ctx == NULL) {
                return queue_fault(pipe, call_id, context_id,
                                   DCERPC_FAULT_CONTEXT_MISMATCH);
        }
        /* the call takes the stub */
        ns = pipe->req_stub;
        pipe->req_stub = NULL;
        stub_len = pipe->req_stub_len;
        pipe->req_stub_len = 0;
        return dispatch(pipe, call_id, ctx, pipe->req_opnum,
                        pipe->req_little_endian, ns, stub_len);
}

static int
process_pdu(struct dcerpc_server_pipe *pipe, const uint8_t *pdu, size_t len)
{
        int le = (pdu[4] & DREP_LITTLE_ENDIAN) != 0;

        switch (pdu[2]) {
        case PTYPE_BIND:
        case PTYPE_ALTER_CONTEXT:
                return process_bind(pipe, pdu, len, le);
        case PTYPE_REQUEST:
                return process_request(pipe, pdu, len, le);
        case PTYPE_AUTH3:
        case PTYPE_CO_CANCEL:
        case PTYPE_ORPHANED:
                return 0;
        default:
                return -1;
        }
}

int
dcerpc_server_pipe_write(struct dcerpc_server_pipe *pipe, const uint8_t *buf,
                         size_t len)
{
        size_t pos = 0;
        uint8_t *nb;

        if (len) {
                nb = realloc(pipe->in_buf, pipe->in_len + len);
                if (nb == NULL) {
                        return -1;
                }
                pipe->in_buf = nb;
                memcpy(nb + pipe->in_len, buf, len);
                pipe->in_len += len;
        }

        while (pipe->in_len - pos >= COMMON_HDR) {
                const uint8_t *pdu = pipe->in_buf + pos;
                uint16_t frag_len = get16(pdu + 8,
                                          pdu[4] & DREP_LITTLE_ENDIAN);

                if (pdu[0] != 5 || pdu[1] > 1 || frag_len < COMMON_HDR) {
                        pipe->in_len = 0;
                        return -1;
                }
                if (pipe->in_len - pos < frag_len) {
                        break;
                }
                if (process_pdu(pipe, pdu, frag_len)) {
                        pipe->in_len = 0;
                        return -1;
                }
                pos += frag_len;
        }
        if (pos) {
                memmove(pipe->in_buf, pipe->in_buf + pos, pipe->in_len - pos);
                pipe->in_len -= pos;
        }
        return 0;
}
