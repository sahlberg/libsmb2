/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Tests for the server runtime (<dcerpc/server.h>) without a transport:
 * PDUs are built here, written to a server pipe, and what it reads back
 * is checked, replies decoded with the client coders.
 *
 * The pipe "lsarpc" serves lsa (raw dispatcher, answered later) and
 * dssetup (coders and a stub), as Windows does on \pipe\lsarpc.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/server.h>
#include <dcerpc/dssetup.h>

static int failures;

#define CHECK(cond) do {                                                \
                if (!(cond)) {                                          \
                        printf("  FAIL %s:%d: %s\n", __FILE__,          \
                               __LINE__, #cond);                        \
                        failures++;                                     \
                }                                                       \
        } while (0)

/* ------------------------------------------------------------------ */
/* PDU building, in either byte order                                  */
/* ------------------------------------------------------------------ */

struct buf {
        uint8_t data[65536];
        size_t len;
        int le;
};

static void
b8(struct buf *b, uint8_t v)
{
        b->data[b->len++] = v;
}

static void
b16(struct buf *b, uint16_t v)
{
        if (b->le) {
                b8(b, (uint8_t)v);
                b8(b, (uint8_t)(v >> 8));
        } else {
                b8(b, (uint8_t)(v >> 8));
                b8(b, (uint8_t)v);
        }
}

static void
b32(struct buf *b, uint32_t v)
{
        if (b->le) {
                b16(b, (uint16_t)v);
                b16(b, (uint16_t)(v >> 16));
        } else {
                b16(b, (uint16_t)(v >> 16));
                b16(b, (uint16_t)v);
        }
}

static void
bsyntax(struct buf *b, const p_syntax_id_t *s)
{
        b32(b, s->uuid.v1);
        b16(b, s->uuid.v2);
        b16(b, s->uuid.v3);
        memcpy(b->data + b->len, s->uuid.v4, 8);
        b->len += 8;
        /* if_version: major in the low 16 bits, minor in the high 16 */
        b32(b, (uint32_t)s->vers | ((uint32_t)s->vers_minor << 16));
}

static void
bcommon(struct buf *b, uint8_t ptype, uint8_t pfc, uint32_t call_id)
{
        b->len = 0;
        b8(b, 5);
        b8(b, 0);
        b8(b, ptype);
        b8(b, pfc);
        b8(b, b->le ? 0x10 : 0x00);
        b8(b, 0);
        b8(b, 0);
        b8(b, 0);
        b16(b, 0);              /* frag_length, set by bdone() */
        b16(b, 0);
        b32(b, call_id);
}

static void
bdone(struct buf *b)
{
        size_t len = b->len;

        b->len = 8;
        b16(b, (uint16_t)len);
        b->len = len;
}

struct ctx_def {
        uint16_t id;
        const p_syntax_id_t *abstract;
        const p_syntax_id_t *transfer;
};

static const p_syntax_id_t btfn_syntax = {
        { 0x6cb71c2c, 0x9812, 0x4540, { 3, 0, 0, 0, 0, 0, 0, 0 } }, 1, 0
};

static const p_syntax_id_t unknown_syntax = {
        { 0x01020304, 0x0506, 0x0708, { 9, 10, 11, 12, 13, 14, 15, 16 } }, 1, 0
};

static void
build_bind(struct buf *b, uint8_t ptype, uint16_t max_recv,
           const struct ctx_def *ctx, int n)
{
        int i;

        bcommon(b, ptype, 3, 1);
        b16(b, 4280);           /* max_xmit_frag */
        b16(b, max_recv);       /* max_recv_frag */
        b32(b, 0);              /* assoc_group_id */
        b8(b, (uint8_t)n);
        b8(b, 0);
        b16(b, 0);
        for (i = 0; i < n; i++) {
                b16(b, ctx[i].id);
                b8(b, 1);
                b8(b, 0);
                bsyntax(b, ctx[i].abstract);
                bsyntax(b, ctx[i].transfer);
        }
        bdone(b);
}

static void
build_request(struct buf *b, uint8_t pfc, uint32_t call_id, uint16_t ctx_id,
              uint16_t opnum, const uint8_t *stub, size_t stub_len,
              size_t alloc_hint)
{
        bcommon(b, 0, pfc, call_id);
        b32(b, (uint32_t)alloc_hint);
        b16(b, ctx_id);
        b16(b, opnum);
        memcpy(b->data + b->len, stub, stub_len);
        b->len += stub_len;
        bdone(b);
}

/* ------------------------------------------------------------------ */
/* Reading what the server answers (little-endian)                     */
/* ------------------------------------------------------------------ */

static uint16_t
le16(const uint8_t *p)
{
        return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t
le32(const uint8_t *p)
{
        return (uint32_t)le16(p) | ((uint32_t)le16(p + 2) << 16);
}

/* One output PDU, read in pieces of at most max bytes */
static size_t
read_pdu(struct dcerpc_server_pipe *pipe, uint8_t *out, size_t max)
{
        size_t len = 0, n;
        int more;

        do {
                n = dcerpc_server_pipe_read(pipe, out + len, max, &more);
                len += n;
        } while (more && n);
        return len;
}

/*
 * The stub of a (possibly fragmented) RESPONSE, or the status of a FAULT
 * in *fault.
 */
static size_t
read_response(struct dcerpc_server_pipe *pipe, uint8_t *stub,
              uint32_t *fault, int *nfrags)
{
        uint8_t pdu[65536];
        size_t len, stub_len = 0;

        *fault = 0;
        *nfrags = 0;
        for (;;) {
                len = read_pdu(pipe, pdu, sizeof(pdu));
                if (len < 24) {
                        *fault = 0xffffffff;
                        return 0;
                }
                (*nfrags)++;
                CHECK(pdu[4] == 0x10);
                CHECK(le16(pdu + 8) == len);
                if (pdu[2] == 3) {
                        *fault = le32(pdu + 24);
                        return 0;
                }
                CHECK(pdu[2] == 2);
                memcpy(stub + stub_len, pdu + 24, len - 24);
                stub_len += len - 24;
                if (pdu[3] & 2) {
                        return stub_len;
                }
        }
}

/* ------------------------------------------------------------------ */
/* The served interfaces                                               */
/* ------------------------------------------------------------------ */

static const char *flat_name = "EXAMPLE";

static int
dssetup_stub(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, void *req_p,
             void *rep_p)
{
        struct dssetup_GetPrimaryDomainInformation_req *req = req_p;
        struct dssetup_GetPrimaryDomainInformation_rep *rep = rep_p;
        struct dcerpc_server_call *call = dcerpc_pdu_server_call(pdu);
        union dssetup_DSROLER_PRIMARY_DOMAIN_INFORMATION *u;

        (void)dce;
        if (call == NULL || dcerpc_server_call_opnum(call) != 0) {
                return -1;
        }
        if (req->InfoLevel == 99) {
                return (int)DCERPC_FAULT_ACCESS_DENIED;
        }
        u = dcerpc_alloc_data(pdu, sizeof(*u));
        if (u == NULL) {
                return -1;
        }
        switch (req->InfoLevel) {
        case DSSETUP_DsRolePrimaryDomainInfoBasic:
                u->DomainInfoBasic.MachineRole =
                        DSSETUP_DsRole_RoleStandaloneServer;
                u->DomainInfoBasic.DomainNameFlat = (char *)flat_name;
                break;
        case DSSETUP_DsRoleOperationState:
                u->OperationStateInfo.OperationState =
                        DSSETUP_DsRoleOperationNeedReboot;
                break;
        default:
                rep->status = 124;
                return 0;
        }
        rep->DomainInfo = u;
        return 0;
}

static const struct dcerpc_stub dssetup_stubs[] = {
        { 0, "GetPrimaryDomainInformation", dssetup_stub },
        { -1, NULL, NULL }
};

/* lsa: every call is parked here and answered by the test */
static struct dcerpc_server_call *parked;

static int
lsa_dispatch(struct dcerpc_server_call *call, void *private_data)
{
        (void)private_data;
        if (dcerpc_server_call_opnum(call) == 99) {
                return -1;
        }
        parked = call;
        return 0;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static struct dcerpc_server *
make_server(void)
{
        struct dcerpc_server *srv = dcerpc_server_create("lsarpc");

        CHECK(srv != NULL);
        CHECK(dcerpc_server_add_interface(srv, &dssetup_interface,
                                          dssetup_procs, dssetup_stubs,
                                          DCERPC_SERVER_ALL_NDR) == 0);
        CHECK(dcerpc_server_add_interface(srv, &dssetup_interface,
                                          dssetup_procs, dssetup_stubs,
                                          DCERPC_SERVER_ALL_NDR) == -1);
        CHECK(dcerpc_server_add_raw_interface(srv, &lsa_interface,
                                              lsa_dispatch, NULL,
                                              DCERPC_SERVER_NDR32_LE) == 0);
        return srv;
}

/* BIND results: one per context, ndr is the expected transfer syntax */
static void
check_results(const uint8_t *pdu, size_t len, int n, const int *result,
              const int *reason, const p_syntax_id_t **ts)
{
        size_t o = 16 + 8;
        int i;

        o += 2 + le16(pdu + o);
        o = (o + 3) & ~(size_t)3;
        CHECK(pdu[o] == n);
        o += 4;
        CHECK(o + 24 * (size_t)n == len);
        for (i = 0; i < n && o + 24 <= len; i++, o += 24) {
                CHECK(le16(pdu + o) == result[i]);
                CHECK(le16(pdu + o + 2) == reason[i]);
                if (ts[i]) {
                        CHECK(le32(pdu + o + 4) == ts[i]->uuid.v1);
                        CHECK(le16(pdu + o + 20) == ts[i]->vers);
                }
        }
}

static void
test_bind(void)
{
        struct dcerpc_server *srv = make_server();
        struct dcerpc_server_pipe *pipe = dcerpc_server_pipe_create(srv, NULL);
        struct buf b = { .le = 1 };
        uint8_t out[1024];
        size_t len;
        struct ctx_def ctx[] = {
                { 0, &dssetup_interface, &ndr32_syntax },
                { 1, &dssetup_interface, &ndr64_syntax },
                { 2, &dssetup_interface, &btfn_syntax },
                { 3, &unknown_syntax, &ndr32_syntax },
                { 4, &lsa_interface, &ndr64_syntax },  /* lsa: NDR32 only */
        };
        int result[] = { 0, 0, 3, 2, 2 };
        int reason[] = { 0, 0, 0, 1, 2 };
        const p_syntax_id_t *ts[] = { &ndr32_syntax, &ndr64_syntax,
                                      NULL, NULL, NULL };

        printf("BIND: results per context, sec_addr, fragment size\n");
        build_bind(&b, 11, 1024, ctx, 5);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        len = read_pdu(pipe, out, sizeof(out));
        CHECK(out[2] == 12);
        CHECK(le32(out + 12) == 1);
        CHECK(le16(out + 16) == 1024);         /* our max_xmit */
        CHECK(le16(out + 24) == strlen("\\PIPE\\lsarpc") + 1);
        CHECK(memcmp(out + 26, "\\PIPE\\lsarpc", 13) == 0);
        check_results(out, len, 5, result, reason, ts);
        CHECK(!dcerpc_server_pipe_has_output(pipe));

        printf("BIND, big-endian client: same results, reply little-endian\n");
        b.le = 0;
        build_bind(&b, 11, 1024, ctx, 5);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        len = read_pdu(pipe, out, sizeof(out));
        CHECK(out[4] == 0x10);
        check_results(out, len, 5, result, reason, ts);

        printf("BIND: max_xmit capped by dcerpc_server_set_max_xmit_frag\n");
        CHECK(dcerpc_server_set_max_xmit_frag(srv, 16) == -1);
        CHECK(dcerpc_server_set_max_xmit_frag(srv, 1003) == 0);
        build_bind(&b, 11, 1024, ctx, 1);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        len = read_pdu(pipe, out, sizeof(out));
        CHECK(out[2] == 12);
        CHECK(le16(out + 16) == 1000);
        build_bind(&b, 11, 512, ctx, 1);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        len = read_pdu(pipe, out, sizeof(out));
        CHECK(le16(out + 16) == 512);

        printf("ALTER_CONTEXT: lsa added on the same pipe, no sec_addr\n");
        b.le = 1;
        build_bind(&b, 14, 1024, &(struct ctx_def){ 7, &lsa_interface,
                                                    &ndr32_syntax }, 1);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        len = read_pdu(pipe, out, sizeof(out));
        CHECK(out[2] == 15);
        CHECK(le16(out + 24) == 0);
        check_results(out, len, 1, (int[]){ 0 }, (int[]){ 0 },
                      (const p_syntax_id_t *[]){ &ndr32_syntax });

        dcerpc_server_pipe_destroy(pipe);
        dcerpc_server_destroy(srv);
}

/* Bind dssetup with one transfer syntax as context 0 */
static struct dcerpc_server_pipe *
bound_pipe(struct dcerpc_server *srv, int le, const p_syntax_id_t *ts,
           uint16_t max_recv)
{
        struct dcerpc_server_pipe *pipe = dcerpc_server_pipe_create(srv, NULL);
        struct buf b = { .le = le };
        struct ctx_def ctx[] = {
                { 0, &dssetup_interface, ts },
                { 1, &lsa_interface, &ndr32_syntax },
        };
        uint8_t out[1024];

        build_bind(&b, 11, max_recv, ctx, 2);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        CHECK(read_pdu(pipe, out, sizeof(out)) > 0);
        return pipe;
}

/* Encode a dssetup request with the client coder */
static size_t
encode_req(uint32_t flags, uint16_t level, uint8_t *out)
{
        struct dcerpc_context *dce = dcerpc_create_context(NULL);
        struct dssetup_GetPrimaryDomainInformation_req req = {
                .InfoLevel = level,
        };
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov = {0};
        size_t len;

        pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE | ENCODING_NDR | flags,
                                  16);
        CHECK(dcerpc_do_coder("Request", dce, pdu, &iov, &req,
                              dssetup_GetPrimaryDomainInformation_req_coder) == 0);
        memcpy(out, iov.buf, iov.offset);
        len = iov.offset;
        dcerpc_free_iovec(&iov);
        dcerpc_free_pdu(dce, pdu);
        dcerpc_destroy_context(dce);
        return len;
}

/* Decode a dssetup reply with the client coder; returns the YAML-less check */
static void
check_reply(uint32_t flags, uint16_t level, const uint8_t *stub,
            size_t len)
{
        struct dcerpc_context *dce = dcerpc_create_context(NULL);
        struct dssetup_GetPrimaryDomainInformation_req req = {
                .InfoLevel = level,
        };
        struct dssetup_GetPrimaryDomainInformation_rep *rep;
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov = { .buf = (uint8_t *)stub, .max_offset = len };

        pdu = dcerpc_allocate_pdu(dce, DCERPC_DECODE | ENCODING_NDR | flags,
                                  sizeof(*rep));
        dcerpc_set_request(pdu, &req);
        rep = dcerpc_get_pdu_payload(pdu);
        CHECK(dcerpc_do_coder("Response", dce, pdu, &iov, rep,
                              dssetup_GetPrimaryDomainInformation_rep_coder) == 0);
        CHECK(iov.offset == len);
        CHECK(rep->status == 0);
        CHECK(rep->DomainInfo != NULL);
        if (rep->DomainInfo && level == 1) {
                CHECK(rep->DomainInfo->DomainInfoBasic.MachineRole ==
                      DSSETUP_DsRole_RoleStandaloneServer);
                CHECK(rep->DomainInfo->DomainInfoBasic.DomainNameFlat &&
                      !strcmp(rep->DomainInfo->DomainInfoBasic.DomainNameFlat,
                              flat_name));
                CHECK(rep->DomainInfo->DomainInfoBasic.DomainNameDns == NULL);
        }
        if (rep->DomainInfo && level == 3) {
                CHECK(rep->DomainInfo->OperationStateInfo.OperationState ==
                      DSSETUP_DsRoleOperationNeedReboot);
        }
        dcerpc_free_pdu(dce, pdu);
        dcerpc_destroy_context(dce);
}

static void
test_coder_calls(void)
{
        static const struct {
                const char *name;
                int le;
                const p_syntax_id_t *ts;
                uint32_t req_flags, rep_flags;
        } fl[] = {
                { "NDR32 LE", 1, &ndr32_syntax, 0, 0 },
                { "NDR32 BE", 0, &ndr32_syntax, DCERPC_BIG_ENDIAN, 0 },
                { "NDR64 LE", 1, &ndr64_syntax, DCERPC_NDR64, DCERPC_NDR64 },
                { "NDR64 BE", 0, &ndr64_syntax,
                  DCERPC_NDR64 | DCERPC_BIG_ENDIAN, DCERPC_NDR64 },
        };
        struct dcerpc_server *srv = make_server();
        size_t i;
        uint16_t level;

        for (i = 0; i < sizeof(fl) / sizeof(fl[0]); i++) {
                struct dcerpc_server_pipe *pipe;
                struct buf b = { .le = fl[i].le };
                uint8_t stub[256], out[65536];
                size_t len;
                uint32_t fault;
                int nfrags;

                printf("coder call, %s: request decoded, stub run, reply "
                       "little-endian\n", fl[i].name);
                pipe = bound_pipe(srv, fl[i].le, fl[i].ts, 4280);
                for (level = 1; level <= 3; level += 2) {
                        len = encode_req(fl[i].req_flags, level, stub);
                        build_request(&b, 3, 10 + level, 0, 0, stub, len, len);
                        CHECK(dcerpc_server_pipe_write(pipe, b.data,
                                                       b.len) == 0);
                        len = read_response(pipe, out, &fault, &nfrags);
                        CHECK(fault == 0);
                        CHECK(nfrags == 1);
                        check_reply(fl[i].rep_flags, level, out, len);
                }

                /* a stub's FAULT status, and one without a stub */
                len = encode_req(fl[i].req_flags, 99, stub);
                build_request(&b, 3, 20, 0, 0, stub, len, len);
                CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
                read_response(pipe, out, &fault, &nfrags);
                CHECK(fault == DCERPC_FAULT_ACCESS_DENIED);
                build_request(&b, 3, 21, 0, 5, stub, len, len);
                CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
                read_response(pipe, out, &fault, &nfrags);
                CHECK(fault == DCERPC_FAULT_OP_RNG_ERROR);
                CHECK(dcerpc_server_pipe_calls_pending(pipe) == 0);
                dcerpc_server_pipe_destroy(pipe);
        }
        dcerpc_server_destroy(srv);
}

static void
test_fragments(void)
{
        struct dcerpc_server *srv = make_server();
        struct dcerpc_server_pipe *pipe;
        struct buf b = { .le = 1 };
        uint8_t stub[256], out[65536], all[512];
        size_t len, half, n;
        uint32_t fault;
        int nfrags, more;
        char *long_name;

        printf("fragments: a REQUEST in two fragments and two writes\n");
        pipe = bound_pipe(srv, 1, &ndr32_syntax, 40);
        len = encode_req(0, 1, stub);
        /* the stub as two fragments, the second written a byte at a time */
        half = 1;
        build_request(&b, 1, 30, 0, 0, stub, half, len);
        memcpy(all, b.data, b.len);
        n = b.len;
        build_request(&b, 2, 30, 0, 0, stub + half, len - half, len - half);
        memcpy(all + n, b.data, b.len);
        n += b.len;
        CHECK(dcerpc_server_pipe_write(pipe, all, n - 1) == 0);
        CHECK(!dcerpc_server_pipe_has_output(pipe));
        CHECK(dcerpc_server_pipe_write(pipe, all + n - 1, 1) == 0);
        n = read_response(pipe, out, &fault, &nfrags);
        CHECK(fault == 0);
        check_reply(0, 1, out, n);

        printf("fragments: a RESPONSE larger than max_xmit (40)\n");
        long_name = malloc(200);
        memset(long_name, 'A', 199);
        long_name[199] = '\0';
        flat_name = long_name;
        dcerpc_server_pipe_destroy(pipe);
        pipe = bound_pipe(srv, 1, &ndr32_syntax, 40);
        build_request(&b, 3, 31, 0, 0, stub, len, len);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        len = read_response(pipe, out, &fault, &nfrags);
        CHECK(fault == 0);
        CHECK(nfrags > 10);
        check_reply(0, 1, out, len);

        printf("message reads: a fragment read in 7-byte pieces\n");
        build_request(&b, 3, 32, 0, 0, stub, encode_req(0, 3, stub), 0);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        n = dcerpc_server_pipe_read(pipe, out, 7, &more);
        CHECK(n == 7 && more);
        len = n;
        while (more) {
                n = dcerpc_server_pipe_read(pipe, out + len, 7, &more);
                len += n;
        }
        CHECK(len == le16(out + 8));
        CHECK(!dcerpc_server_pipe_has_output(pipe));
        CHECK(dcerpc_server_pipe_read(pipe, out, 7, &more) == 0 && !more);
        flat_name = "EXAMPLE";
        free(long_name);
        dcerpc_server_pipe_destroy(pipe);
        dcerpc_server_destroy(srv);
}

static void
test_errors(void)
{
        struct dcerpc_server *srv = make_server();
        struct dcerpc_server_pipe *pipe;
        struct buf b = { .le = 1 };
        uint8_t stub[64], out[1024];
        size_t len;
        uint32_t fault;
        int nfrags;

        printf("errors: REQUEST before BIND, unknown context, bad stub\n");
        pipe = dcerpc_server_pipe_create(srv, NULL);
        len = encode_req(0, 1, stub);
        build_request(&b, 3, 40, 0, 0, stub, len, len);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        CHECK(fault == DCERPC_FAULT_PROTO_ERROR);
        dcerpc_server_pipe_destroy(pipe);

        pipe = bound_pipe(srv, 1, &ndr32_syntax, 4280);
        build_request(&b, 3, 41, 9, 0, stub, len, len);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        CHECK(fault == DCERPC_FAULT_CONTEXT_MISMATCH);

        build_request(&b, 3, 42, 0, 0, stub, 1, 1);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        CHECK(fault == DCERPC_FAULT_NDR);

        printf("errors: a stream that is not DCE/RPC\n");
        memset(out, 0xff, 32);
        CHECK(dcerpc_server_pipe_write(pipe, out, 32) == -1);
        dcerpc_server_pipe_destroy(pipe);
        dcerpc_server_destroy(srv);
}

static void
test_raw_async(void)
{
        struct dcerpc_server *srv = make_server();
        struct dcerpc_server_pipe *pipe;
        struct buf b = { .le = 1 };
        static const uint8_t req_stub[] = { 1, 2, 3, 4 };
        static const uint8_t rep_stub[] = { 5, 6, 7, 8 };
        uint8_t out[1024];
        const uint8_t *s;
        size_t len;
        uint32_t fault;
        int nfrags;

        printf("raw interface: a call answered later\n");
        pipe = bound_pipe(srv, 1, &ndr32_syntax, 4280);
        build_request(&b, 3, 50, 1, 6, req_stub, 4, 4);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        CHECK(parked != NULL);
        CHECK(!dcerpc_server_pipe_has_output(pipe));
        CHECK(dcerpc_server_pipe_calls_pending(pipe) == 1);
        CHECK(dcerpc_server_call_opnum(parked) == 6);
        CHECK(dcerpc_server_call_flags(parked) == 0);
        CHECK(dcerpc_server_call_get_pipe(parked) == pipe);
        s = dcerpc_server_call_stub(parked, &len);
        CHECK(len == 4 && !memcmp(s, req_stub, 4));
        CHECK(dcerpc_server_call_reply(parked, rep_stub, 4) == 0);
        parked = NULL;
        CHECK(dcerpc_server_pipe_calls_pending(pipe) == 0);
        len = read_response(pipe, out, &fault, &nfrags);
        CHECK(fault == 0 && len == 4 && !memcmp(out, rep_stub, 4));

        printf("raw interface: a dispatcher error is a FAULT\n");
        build_request(&b, 3, 51, 1, 99, req_stub, 4, 4);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        CHECK(fault == DCERPC_FAULT_OTHER);

        printf("raw interface: lsa is NDR32 LE only, a BE call is refused\n");
        b.le = 0;
        build_request(&b, 3, 52, 1, 6, req_stub, 4, 4);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        CHECK(fault == DCERPC_FAULT_PROTO_ERROR);
        CHECK(parked == NULL);

        printf("raw interface: the pipe is destroyed while a call is out\n");
        b.le = 1;
        build_request(&b, 3, 53, 1, 6, req_stub, 4, 4);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        CHECK(parked != NULL);
        dcerpc_server_pipe_destroy(pipe);
        if (parked) {
                CHECK(dcerpc_server_call_get_pipe(parked) == NULL);
                CHECK(dcerpc_server_call_reply(parked, rep_stub, 4) == 0);
        }
        parked = NULL;
        dcerpc_server_destroy(srv);
}

/* What the log hook was called with */
static int nlog;
static int log_levels[256];
static char log_msgs[256][512];

static void
collect_log(void *private_data, int level, const char *msg)
{
        CHECK(private_data == &nlog);
        CHECK(strncmp(msg, "lsarpc: ", 8) == 0);
        if (nlog < 256) {
                log_levels[nlog] = level;
                snprintf(log_msgs[nlog], sizeof(log_msgs[nlog]), "%s", msg);
        }
        nlog++;
}

/* A message at level containing s was logged */
static int
logged(int level, const char *s)
{
        int i;

        for (i = 0; i < nlog && i < 256; i++) {
                if (log_levels[i] == level && strstr(log_msgs[i], s)) {
                        return 1;
                }
        }
        return 0;
}

/* How many messages at level were logged */
static int
nlogged(int level)
{
        int i, n = 0;

        for (i = 0; i < nlog && i < 256; i++) {
                n += log_levels[i] == level;
        }
        return n;
}

static void
print_log(void)
{
        int i;

        for (i = 0; i < nlog && i < 256; i++) {
                printf("  %d %s\n", log_levels[i], log_msgs[i]);
        }
        nlog = 0;
}

static void
test_log(void)
{
        struct dcerpc_server *srv = make_server();
        struct dcerpc_server_pipe *pipe;
        struct buf b = { .le = 1 };
        struct ctx_def unknown = { 5, &unknown_syntax, &ndr32_syntax };
        uint8_t stub[64], out[1024];
        uint32_t fault;
        size_t len;
        int nfrags;

        printf("log: no messages without a log function\n");
        pipe = bound_pipe(srv, 1, &ndr32_syntax, 4280);
        CHECK(nlog == 0);
        dcerpc_server_pipe_destroy(pipe);

        printf("log: BIND results\n");
        dcerpc_server_set_log(srv, DCERPC_SERVER_LOG_DEBUG, collect_log,
                              &nlog);
        pipe = bound_pipe(srv, 1, &ndr32_syntax, 4280);
        CHECK(nlog == 2);
        CHECK(logged(DCERPC_SERVER_LOG_DEBUG, "BIND: interface 3919286a-"
                     "b10c-11d0-9ba8-00c04fd92ef5 v0.0, NDR32"));
        print_log();
        build_bind(&b, 14, 4280, &unknown, 1);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        CHECK(read_pdu(pipe, out, sizeof(out)) > 0);
        CHECK(nlog == 1);
        CHECK(logged(DCERPC_SERVER_LOG_INFO, "is not served"));
        print_log();

        printf("log: a call, its request and reply dumped and as YAML\n");
        len = encode_req(0, 1, stub);
        build_request(&b, 3, 50, 0, 0, stub, len, len);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        CHECK(logged(DCERPC_SERVER_LOG_DEBUG,
                     "lsarpc: GetPrimaryDomainInformation (opnum 0)"));
        CHECK(logged(DCERPC_SERVER_LOG_DEBUG,
                     "GetPrimaryDomainInformation request, 2 bytes of "
                     "NDR32:"));
        CHECK(logged(DCERPC_SERVER_LOG_DEBUG, "lsarpc:   0000  01 00"));
        CHECK(logged(DCERPC_SERVER_LOG_DEBUG,
                     "lsarpc:   GetPrimaryDomainInformation: Request"));
        CHECK(logged(DCERPC_SERVER_LOG_DEBUG,
                     "    InfoLevel: DsRolePrimaryDomainInfoBasic"));
        CHECK(logged(DCERPC_SERVER_LOG_DEBUG,
                     "GetPrimaryDomainInformation reply,"));
        CHECK(logged(DCERPC_SERVER_LOG_DEBUG,
                     "lsarpc:   GetPrimaryDomainInformation: Response"));
        CHECK(nlogged(DCERPC_SERVER_LOG_INFO) == 0);
        CHECK(nlogged(DCERPC_SERVER_LOG_ERROR) == 0);
        print_log();

        build_request(&b, 3, 51, 0, 7, stub, len, len);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        CHECK(fault == DCERPC_FAULT_OP_RNG_ERROR);
        CHECK(nlog == 1);
        CHECK(logged(DCERPC_SERVER_LOG_INFO, "opnum 7 is not implemented"));
        print_log();

        build_request(&b, 3, 52, 0, 0, stub, 1, 1);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        CHECK(logged(DCERPC_SERVER_LOG_ERROR, "does not decode"));
        CHECK(logged(DCERPC_SERVER_LOG_DEBUG, "lsarpc:   0000  01"));
        print_log();

        printf("log: protocol errors\n");
        build_request(&b, 3, 53, 9, 0, stub, len, len);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        CHECK(nlog == 1);
        CHECK(logged(DCERPC_SERVER_LOG_ERROR,
                     "context 9, which is not bound"));
        print_log();
        memset(out, 0xff, 32);
        CHECK(dcerpc_server_pipe_write(pipe, out, 32) == -1);
        CHECK(nlog == 1);
        CHECK(logged(DCERPC_SERVER_LOG_ERROR, "not DCE/RPC"));
        print_log();
        dcerpc_server_pipe_destroy(pipe);

        printf("log: at INFO, no debug messages and no dumps\n");
        dcerpc_server_set_log(srv, DCERPC_SERVER_LOG_INFO, collect_log,
                              &nlog);
        pipe = bound_pipe(srv, 1, &ndr32_syntax, 4280);
        build_request(&b, 3, 54, 0, 0, stub, len, len);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        build_request(&b, 3, 55, 0, 7, stub, len, len);
        CHECK(dcerpc_server_pipe_write(pipe, b.data, b.len) == 0);
        read_response(pipe, out, &fault, &nfrags);
        CHECK(nlog == 1);
        CHECK(logged(DCERPC_SERVER_LOG_INFO, "opnum 7 is not implemented"));
        print_log();

        dcerpc_server_pipe_destroy(pipe);
        dcerpc_server_destroy(srv);
}

int main(void)
{
        test_bind();
        test_coder_calls();
        test_fragments();
        test_errors();
        test_raw_async();
        test_log();
        if (failures) {
                printf("%d check(s) failed\n", failures);
                return 1;
        }
        printf("all checks passed\n");
        return 0;
}
