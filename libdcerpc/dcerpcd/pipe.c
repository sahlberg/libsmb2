/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Named-pipe + DCERPC server side for dcerpcd.
 * Supports CREATE/CLOSE of \\pipe\\epmapper, and FSCTL_PIPE_TRANSCEIVE,
 * READ and WRITE carrying DCERPC BIND and REQUEST (ept_* via the epm
 * registry). Requests are reassembled from fragments and responses are
 * fragmented to the negotiated max_xmit.
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
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

#include <dcerpc/dcerpc.h>
#include <dcerpc/epm.h>

#include "dcerpcd.h"

#ifndef _U_
#define _U_ __attribute__((unused))
#endif

/* DCERPC PDU types / flags (C706) — keep private to this file */
#define PDU_TYPE_REQUEST   0
#define PDU_TYPE_RESPONSE  2
#define PDU_TYPE_FAULT     3
#define PDU_TYPE_BIND      11
#define PDU_TYPE_BIND_ACK  12
#define PDU_TYPE_BIND_NAK  13

#define PFC_FIRST_FRAG     0x01
#define PFC_LAST_FRAG      0x02
#define PFC_OBJECT_UUID    0x80

#define ACK_RESULT_ACCEPTANCE 0
#define ACK_REASON_NOT_SPECIFIED 0
#define ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED 1
#define ACK_REASON_TRANSFER_SYNTAX_NOT_SUPPORTED 2

#define NDR32_UUID_V1 0x8a885d04
#define NDR32_UUID_V2 0x1ceb
#define NDR32_UUID_V3 0x11c9

#define DCERPC_COMMON_HDR 16
#define DCERPC_REQ_HDR    8   /* after common */
#define DCERPC_RSP_HDR    8

/*
 * Largest fragment we can advertise: frag_length is a uint16, rounded
 * down to a multiple of 8 so stub data in non-final fragments stays
 * 8-byte aligned.
 */
#define DCERPCD_MAX_FRAG 0xfff8

/* Fragment size to use before a BIND has negotiated one. */
#define DCERPCD_DEFAULT_FRAG 4280

/* Upper bound on a reassembled multi-fragment REQUEST stub. */
#define DCERPCD_MAX_REQ_STUB (4 * 1024 * 1024)

/* NDR32 transfer syntax uuid bytes (little-endian layout as on wire) */
static const uint8_t ndr32_uuid_bytes[16] = {
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
};

/*
 * Builtin services run in-process. EXTERNAL services are registered at
 * runtime when a worker connects on the control UDS (external.c).
 */
static const struct dcerpcd_service builtin_services[] = {
        {
                .pipe_name = "epmapper",
                .kind = DCERPCD_SVC_BUILTIN_EPM,
                .annotation = "Endpoint Mapper",
                .uds_path = NULL,
                .conn_fd = -1,
                .has_iface = 0,
        },
        { NULL, DCERPCD_SVC_NONE, NULL, NULL, -1, { 0 }, 0, 0, 0 }
};

/* Dynamically registered EXTERNAL services (owned strings). */
struct dcerpcd_ext_svc {
        struct dcerpcd_ext_svc *next;
        struct dcerpcd_service svc;
        char *pipe_name_owned;
        char *annotation_owned;
};

static struct dcerpcd_ext_svc *ext_services;
static pthread_mutex_t svc_lock = PTHREAD_MUTEX_INITIALIZER;

struct dcerpcd_pipe {
        struct dcerpcd_pipe *next;
        smb2_file_id file_id;
        char *name;                 /* baseless pipe name, e.g. "epmapper" */
        const struct dcerpcd_service *service; /* which service this open refers to */
        int bound;
        uint16_t context_id;        /* accepted presentation context */
        uint8_t packed_drep[4];
        uint16_t max_xmit;          /* negotiated at BIND */

        /* Bytes from WRITE/TRANSCEIVE not yet forming a complete PDU. */
        uint8_t *in_buf;
        size_t in_len;

        /* Multi-fragment REQUEST being reassembled. */
        int req_active;
        uint32_t req_call_id;
        uint16_t req_opnum;
        uint8_t req_drep0;
        uint8_t *req_stub;
        size_t req_stub_len;

        /*
         * Outgoing PDUs, back to back. Each fragment is one pipe message:
         * a READ/TRANSCEIVE returns at most one fragment, and if the
         * fragment does not fit, the rest is returned by the next READ.
         */
        uint8_t *out_buf;
        size_t out_len;
        size_t out_pos;
        size_t out_frag_left;       /* unread bytes of fragment at out_pos */

        int calls_pending;          /* EXTERNAL calls in flight */

        /* TRANSCEIVE or READ waiting for an EXTERNAL reply. */
        uint8_t wait_cmd;           /* 0, SMB2_IOCTL or SMB2_READ */
        uint64_t wait_msgid;
        uint32_t wait_max;
        uint32_t wait_flags;
};

static uint64_t next_fid = 1;

const struct dcerpcd_service *
dcerpcd_service_lookup(const char *pipe_name)
{
        const struct dcerpcd_service *s;
        struct dcerpcd_ext_svc *e;

        if (pipe_name == NULL || pipe_name[0] == '\0') {
                return NULL;
        }
        for (s = builtin_services; s->pipe_name; s++) {
                if (strcasecmp(s->pipe_name, pipe_name) == 0) {
                        return s;
                }
        }
        pthread_mutex_lock(&svc_lock);
        for (e = ext_services; e; e = e->next) {
                if (e->svc.pipe_name &&
                    strcasecmp(e->svc.pipe_name, pipe_name) == 0) {
                        pthread_mutex_unlock(&svc_lock);
                        return &e->svc;
                }
        }
        pthread_mutex_unlock(&svc_lock);
        return NULL;
}

int
dcerpcd_service_add_external(const char *pipe_name,
                             const char *annotation,
                             int conn_fd,
                             const dcerpc_uuid_t *iface,
                             uint16_t vers_major,
                             uint16_t vers_minor)
{
        struct dcerpcd_ext_svc *e;

        if (pipe_name == NULL || pipe_name[0] == '\0' || conn_fd < 0) {
                return -1;
        }
        /* Refuse shadowing a builtin pipe name. */
        {
                const struct dcerpcd_service *s;

                for (s = builtin_services; s->pipe_name; s++) {
                        if (strcasecmp(s->pipe_name, pipe_name) == 0) {
                                fprintf(stderr,
                                        "service: cannot override builtin "
                                        "pipe %s\n", pipe_name);
                                return -1;
                        }
                }
        }

        e = calloc(1, sizeof(*e));
        if (e == NULL) {
                return -1;
        }
        e->pipe_name_owned = strdup(pipe_name);
        e->annotation_owned = strdup(annotation ? annotation : "");
        if (e->pipe_name_owned == NULL || e->annotation_owned == NULL) {
                free(e->pipe_name_owned);
                free(e->annotation_owned);
                free(e);
                return -1;
        }
        e->svc.pipe_name = e->pipe_name_owned;
        e->svc.kind = DCERPCD_SVC_EXTERNAL;
        e->svc.annotation = e->annotation_owned;
        e->svc.uds_path = NULL;
        e->svc.conn_fd = conn_fd;
        if (iface) {
                e->svc.iface = *iface;
                e->svc.vers_major = vers_major;
                e->svc.vers_minor = vers_minor;
                e->svc.has_iface = 1;
        }

        pthread_mutex_lock(&svc_lock);
        /* Replace any previous registration for this pipe or fd. */
        {
                struct dcerpcd_ext_svc **pp = &ext_services;

                while (*pp) {
                        struct dcerpcd_ext_svc *cur = *pp;

                        if (cur->svc.conn_fd == conn_fd ||
                            (cur->svc.pipe_name &&
                             strcasecmp(cur->svc.pipe_name, pipe_name) == 0)) {
                                *pp = cur->next;
                                free(cur->pipe_name_owned);
                                free(cur->annotation_owned);
                                free(cur);
                                continue;
                        }
                        pp = &cur->next;
                }
        }
        e->next = ext_services;
        ext_services = e;
        pthread_mutex_unlock(&svc_lock);

        printf("service: registered EXTERNAL pipe=%s conn_fd=%d (%s)\n",
               pipe_name, conn_fd, annotation ? annotation : "");
        return 0;
}

void
dcerpcd_service_remove_by_fd(int conn_fd)
{
        struct dcerpcd_ext_svc **pp;
        int removed = 0;

        if (conn_fd < 0) {
                return;
        }
        pthread_mutex_lock(&svc_lock);
        pp = &ext_services;
        while (*pp) {
                struct dcerpcd_ext_svc *cur = *pp;

                if (cur->svc.conn_fd == conn_fd) {
                        *pp = cur->next;
                        printf("service: unregistered EXTERNAL pipe=%s "
                               "conn_fd=%d\n",
                               cur->svc.pipe_name ? cur->svc.pipe_name : "?",
                               conn_fd);
                        free(cur->pipe_name_owned);
                        free(cur->annotation_owned);
                        free(cur);
                        removed++;
                        continue;
                }
                pp = &cur->next;
        }
        pthread_mutex_unlock(&svc_lock);
        (void)removed;
}

static const char *
service_kind_str(enum dcerpcd_service_kind kind)
{
        switch (kind) {
        case DCERPCD_SVC_BUILTIN_EPM:
                return "builtin-epm";
        case DCERPCD_SVC_EXTERNAL:
                return "external";
        default:
                return "none";
        }
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static void
put_le16(uint8_t *p, uint16_t v)
{
        p[0] = (uint8_t)(v & 0xff);
        p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void
put_le32(uint8_t *p, uint32_t v)
{
        p[0] = (uint8_t)(v & 0xff);
        p[1] = (uint8_t)((v >> 8) & 0xff);
        p[2] = (uint8_t)((v >> 16) & 0xff);
        p[3] = (uint8_t)((v >> 24) & 0xff);
}

static uint16_t
get_le16(const uint8_t *p)
{
        return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
get_le32(const uint8_t *p)
{
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int
fid_equal(const smb2_file_id a, const smb2_file_id b)
{
        return memcmp(a, b, SMB2_FD_SIZE) == 0;
}

static void
fid_assign(smb2_file_id dst, uint64_t persistent, uint64_t volatile_id)
{
        put_le32(dst, (uint32_t)(persistent & 0xffffffff));
        put_le32(dst + 4, (uint32_t)(persistent >> 32));
        put_le32(dst + 8, (uint32_t)(volatile_id & 0xffffffff));
        put_le32(dst + 12, (uint32_t)(volatile_id >> 32));
}

/*
 * Create name is typically "epmapper" (relative to IPC$). Accept common
 * variants and return a malloc'd base name, or NULL if not a pipe we serve.
 */
static char *
pipe_basename(const char *name)
{
        const char *p;

        if (name == NULL || name[0] == '\0') {
                return NULL;
        }
        p = name;
        /* strip leading slashes / backslashes and optional "pipe\" */
        while (*p == '\\' || *p == '/') {
                p++;
        }
        if (!strncasecmp(p, "pipe", 4) && (p[4] == '\\' || p[4] == '/')) {
                p += 5;
                while (*p == '\\' || *p == '/') {
                        p++;
                }
        }
        if (*p == '\0') {
                return NULL;
        }
        return strdup(p);
}

static struct dcerpcd_pipe *
pipe_find(struct dcerpcd_conn *conn, const smb2_file_id fid)
{
        struct dcerpcd_pipe *p;

        if (conn == NULL) {
                return NULL;
        }
        for (p = conn->pipes; p; p = p->next) {
                if (fid_equal(p->file_id, fid)) {
                        return p;
                }
        }
        return NULL;
}

static void
pipe_free(struct dcerpcd_pipe *p)
{
        if (p == NULL) {
                return;
        }
        free(p->name);
        free(p->in_buf);
        free(p->req_stub);
        free(p->out_buf);
        free(p);
}

void
dcerpcd_pipe_conn_cleanup(struct dcerpcd_conn *conn)
{
        struct dcerpcd_pipe *p;

        if (conn == NULL) {
                return;
        }
        while (conn->pipes) {
                p = conn->pipes;
                conn->pipes = p->next;
                pipe_free(p);
        }
}

/* ------------------------------------------------------------------ */
/* NDR stub encode/decode via libdcerpc                                */
/* ------------------------------------------------------------------ */

/*
 * Decode an NDR request stub. PDU memory (pointer targets) stays alive
 * until dcerpc_free_pdu — caller must finish using *obj before free_out.
 */
static int
ndr_decode_stub(struct smb2_context *smb2,
                const uint8_t *stub, size_t stub_len,
                void *obj, int obj_size, dcerpc_coder coder,
                struct dcerpc_context **dce_out,
                struct dcerpc_pdu **pdu_out)
{
        struct dcerpc_context *dce;
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov;

        *dce_out = NULL;
        *pdu_out = NULL;

        dce = dcerpc_create_context(smb2);
        if (dce == NULL) {
                return -1;
        }
        /* Little-endian NDR32 */
        pdu = dcerpc_allocate_pdu(dce, DCERPC_DECODE | ENCODING_NDR, obj_size);
        if (pdu == NULL) {
                dcerpc_destroy_context(dce);
                return -1;
        }
        memset(obj, 0, (size_t)obj_size);
        iov = (struct dcerpc_iovec){
                .buf = (uint8_t *)(uintptr_t)stub,
                .max_offset = stub_len,
        };
        if (dcerpc_do_coder("Request", dce, pdu, &iov, obj, coder)) {
                fprintf(stderr, "pipe: NDR decode failed: %s\n",
                        dcerpc_get_error(dce));
                dcerpc_free_pdu(dce, pdu);
                dcerpc_destroy_context(dce);
                return -1;
        }
        *dce_out = dce;
        *pdu_out = pdu;
        return 0;
}

static void
ndr_decode_done(struct dcerpc_context *dce, struct dcerpc_pdu *pdu)
{
        if (pdu) {
                dcerpc_free_pdu(dce, pdu);
        }
        if (dce) {
                dcerpc_destroy_context(dce);
        }
}

/*
 * Encode a reply structure to an NDR stub. *out_buf is malloc'd; the caller
 * frees it. request is optional (some coders use size_is from the request).
 */
static int
ndr_encode_stub(struct smb2_context *smb2,
                void *request,
                void *reply,
                dcerpc_coder coder,
                uint8_t **out_buf,
                size_t *out_len)
{
        struct dcerpc_context *dce;
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov = {0};
        int rc = -1;

        *out_buf = NULL;
        *out_len = 0;

        dce = dcerpc_create_context(smb2);
        if (dce == NULL) {
                return -1;
        }
        /* Little-endian NDR32 */
        pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE | ENCODING_NDR, 16);
        if (pdu == NULL) {
                dcerpc_destroy_context(dce);
                return -1;
        }
        if (request) {
                dcerpc_set_request(pdu, request);
        }
        /* A growable iovec: the buffer is malloc'd and grows as needed */
        if (dcerpc_do_coder("Response", dce, pdu, &iov, reply, coder)) {
                fprintf(stderr, "pipe: NDR encode failed: %s\n",
                        dcerpc_get_error(dce));
                dcerpc_free_iovec(&iov);
                goto out;
        }
        *out_buf = iov.buf;
        *out_len = iov.offset;
        rc = 0;
out:
        dcerpc_free_pdu(dce, pdu);
        dcerpc_destroy_context(dce);
        return rc;
}

/* ------------------------------------------------------------------ */
/* DCERPC BIND / REQUEST                                               */
/* ------------------------------------------------------------------ */

static int
uuid_match_epm(const uint8_t *wire_uuid, uint16_t vers, uint16_t vers_minor)
{
        /* epm_interface: e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0 */
        static const uint8_t epm_uuid[16] = {
                0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
                0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa
        };
        return memcmp(wire_uuid, epm_uuid, 16) == 0 && vers == 3 &&
               vers_minor == 0;
}

static int
uuid_match_ndr32(const uint8_t *wire_uuid, uint16_t vers)
{
        return memcmp(wire_uuid, ndr32_uuid_bytes, 16) == 0 && vers == 2;
}

static void
uuid_to_wire_le(const dcerpc_uuid_t *u, uint8_t out[16])
{
        out[0] = (uint8_t)(u->v1 & 0xff);
        out[1] = (uint8_t)((u->v1 >> 8) & 0xff);
        out[2] = (uint8_t)((u->v1 >> 16) & 0xff);
        out[3] = (uint8_t)((u->v1 >> 24) & 0xff);
        out[4] = (uint8_t)(u->v2 & 0xff);
        out[5] = (uint8_t)((u->v2 >> 8) & 0xff);
        out[6] = (uint8_t)(u->v3 & 0xff);
        out[7] = (uint8_t)((u->v3 >> 8) & 0xff);
        memcpy(out + 8, u->v4, 8);
}

static int
abstract_ok_for_service(const struct dcerpcd_service *svc,
                        const uint8_t *abs_uuid,
                        uint16_t abs_vers, uint16_t abs_min)
{
        uint8_t wire[16];

        if (svc == NULL) {
                return 0;
        }
        switch (svc->kind) {
        case DCERPCD_SVC_BUILTIN_EPM:
                return uuid_match_epm(abs_uuid, abs_vers, abs_min);
        case DCERPCD_SVC_EXTERNAL:
                if (!svc->has_iface || abs_uuid == NULL) {
                        return 0;
                }
                uuid_to_wire_le(&svc->iface, wire);
                return memcmp(abs_uuid, wire, 16) == 0 &&
                       abs_vers == svc->vers_major &&
                       abs_min == svc->vers_minor;
        default:
                return 0;
        }
}

static uint8_t *
build_bind_ack(struct smb2_context *smb2, struct dcerpcd_pipe *pipe,
               const uint8_t *in, size_t in_len,
               size_t *out_len)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        uint32_t session_id = conn ? conn->session_id : 0;
        uint32_t call_id;
        uint8_t n_ctx;
        size_t o;
        uint8_t *out;
        size_t cap = 512;
        uint8_t accepted = 0;
        uint16_t accept_ctx = 0;
        char sec_addr[128];
        size_t sec_len;
        size_t i, pos;
        uint8_t drep0;
        uint16_t max_xmit, max_recv;

        if (in_len < DCERPC_COMMON_HDR + 12) {
                return NULL;
        }
        call_id = get_le32(in + 12);
        drep0 = in[4];
        /*
         * Negotiate fragment sizes: our max_xmit may not exceed the
         * client's max_recv, and our max_recv need not exceed the
         * client's max_xmit.
         */
        max_xmit = get_le16(in + DCERPC_COMMON_HDR + 2);
        max_recv = get_le16(in + DCERPC_COMMON_HDR);
        if (max_xmit == 0 || max_xmit > DCERPCD_MAX_FRAG) {
                max_xmit = DCERPCD_MAX_FRAG;
        }
        if (max_recv == 0 || max_recv > DCERPCD_MAX_FRAG) {
                max_recv = DCERPCD_MAX_FRAG;
        }
        n_ctx = in[DCERPC_COMMON_HDR + 8];
        pos = DCERPC_COMMON_HDR + 12; /* after n_ctx + 3 pad */

        /*
         * Scan presentation contexts: accept abstract syntax for this
         * pipe's service + NDR32 transfer syntax.
         */
        for (i = 0; i < n_ctx && pos + 4 + 20 < in_len; i++) {
                uint16_t p_cont_id = get_le16(in + pos);
                uint8_t n_ts = in[pos + 2];
                const uint8_t *abs_uuid;
                uint16_t abs_vers, abs_min;
                size_t j;

                pos += 4;
                if (pos + 20 > in_len) {
                        break;
                }
                abs_uuid = in + pos;
                abs_vers = get_le16(in + pos + 16);
                abs_min = get_le16(in + pos + 18);
                pos += 20;
                for (j = 0; j < n_ts && pos + 20 <= in_len; j++) {
                        const uint8_t *ts_uuid = in + pos;
                        uint16_t ts_vers = get_le16(in + pos + 16);

                        if (!accepted &&
                            abstract_ok_for_service(pipe->service, abs_uuid,
                                                    abs_vers, abs_min) &&
                            uuid_match_ndr32(ts_uuid, ts_vers)) {
                                accepted = 1;
                                accept_ctx = p_cont_id;
                        }
                        pos += 20;
                }
        }

        snprintf(sec_addr, sizeof(sec_addr), "\\PIPE\\%s",
                 pipe->name ? pipe->name : "epmapper");
        sec_len = strlen(sec_addr) + 1;
        cap = DCERPC_COMMON_HDR + 4 + 4 + 2 + sec_len + 4 + 4 + 24 + 16;
        out = calloc(1, cap);
        if (out == NULL) {
                return NULL;
        }
        o = 0;
        out[o++] = 5; /* rpc_vers */
        out[o++] = 0;
        out[o++] = PDU_TYPE_BIND_ACK;
        out[o++] = PFC_FIRST_FRAG | PFC_LAST_FRAG;
        out[o++] = drep0 ? drep0 : 0x10; /* little endian */
        out[o++] = 0;
        out[o++] = 0;
        out[o++] = 0;
        put_le16(out + 8, 0); /* frag_length fixup later */
        put_le16(out + 10, 0);
        put_le32(out + 12, call_id);
        o = DCERPC_COMMON_HDR;

        pipe->max_xmit = max_xmit;
        put_le16(out + o, max_xmit); o += 2;
        put_le16(out + o, max_recv); o += 2;
        put_le32(out + o, 0x1234); o += 4; /* assoc group */

        put_le16(out + o, (uint16_t)sec_len); o += 2;
        memcpy(out + o, sec_addr, sec_len); o += sec_len;
        while (o & 3) {
                out[o++] = 0;
        }

        out[o++] = 1; /* num_results */
        out[o++] = 0;
        out[o++] = 0;
        out[o++] = 0;

        if (accepted) {
                put_le16(out + o, ACK_RESULT_ACCEPTANCE); o += 2;
                put_le16(out + o, ACK_REASON_NOT_SPECIFIED); o += 2;
                memcpy(out + o, ndr32_uuid_bytes, 16); o += 16;
                put_le32(out + o, 2); o += 4; /* syntax version */
                pipe->bound = 1;
                pipe->context_id = accept_ctx;
                pipe->packed_drep[0] = drep0 ? drep0 : 0x10;
                printf("pipe: BIND_ACK session=%u %s kind=%s context_id=%u "
                       "accepted\n",
                       session_id,
                       pipe->name ? pipe->name : "?",
                       pipe->service ? service_kind_str(pipe->service->kind)
                                     : "?",
                       (unsigned)accept_ctx);
        } else {
                put_le16(out + o, 2); o += 2; /* provider rejection */
                put_le16(out + o,
                         ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED); o += 2;
                memset(out + o, 0, 16); o += 16;
                put_le32(out + o, 0); o += 4;
                pipe->bound = 0;
                printf("pipe: BIND_ACK session=%u %s rejected "
                       "(no matching syntax)\n",
                       session_id,
                       pipe->name ? pipe->name : "?");
        }

        put_le16(out + 8, (uint16_t)o);
        *out_len = o;
        return out;
}

static uint8_t *
build_fault(uint32_t call_id, uint8_t drep0, uint32_t status, size_t *out_len)
{
        uint8_t *out = calloc(1, 32);
        size_t o = 0;

        if (out == NULL) {
                return NULL;
        }
        out[o++] = 5;
        out[o++] = 0;
        out[o++] = PDU_TYPE_FAULT;
        out[o++] = PFC_FIRST_FRAG | PFC_LAST_FRAG;
        out[o++] = drep0 ? drep0 : 0x10;
        out[o++] = 0;
        out[o++] = 0;
        out[o++] = 0;
        put_le16(out + 8, 32);
        put_le16(out + 10, 0);
        put_le32(out + 12, call_id);
        o = 16;
        put_le32(out + o, 0); o += 4; /* alloc_hint */
        put_le16(out + o, 0); o += 2; /* context */
        out[o++] = 0; /* cancel */
        out[o++] = 0;
        put_le32(out + o, status); o += 4;
        *out_len = 32;
        return out;
}

static uint8_t *
build_response_frag(uint8_t drep0, uint16_t context_id, uint32_t call_id,
                    uint8_t pfc_flags, uint32_t alloc_hint,
                    const uint8_t *stub, size_t stub_len, size_t *out_len)
{
        size_t total = DCERPC_COMMON_HDR + DCERPC_RSP_HDR + stub_len;
        uint8_t *out = calloc(1, total);
        size_t o = 0;

        if (out == NULL) {
                return NULL;
        }
        out[o++] = 5;
        out[o++] = 0;
        out[o++] = PDU_TYPE_RESPONSE;
        out[o++] = pfc_flags;
        out[o++] = drep0 ? drep0 : 0x10;
        out[o++] = 0;
        out[o++] = 0;
        out[o++] = 0;
        put_le16(out + 8, (uint16_t)total);
        put_le16(out + 10, 0);
        put_le32(out + 12, call_id);
        o = DCERPC_COMMON_HDR;
        put_le32(out + o, alloc_hint); o += 4;
        put_le16(out + o, context_id); o += 2;
        out[o++] = 0; /* cancel_count */
        out[o++] = 0;
        if (stub_len) {
                memcpy(out + o, stub, stub_len);
        }
        *out_len = total;
        return out;
}

/* ------------------------------------------------------------------ */
/* Pipe output queue                                                   */
/* ------------------------------------------------------------------ */

static int
out_append(struct dcerpcd_pipe *pipe, const uint8_t *buf, size_t len)
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
                return -1;
        }
        pipe->out_buf = nb;
        memcpy(nb + pipe->out_len, buf, len);
        pipe->out_len += len;
        return 0;
}

/* Queue a complete single-fragment PDU and free it. */
static int
out_queue_pdu(struct dcerpcd_pipe *pipe, uint8_t *pdu, size_t len)
{
        int rc;

        if (pdu == NULL) {
                return -1;
        }
        rc = out_append(pipe, pdu, len);
        free(pdu);
        return rc;
}

static int
queue_fault(struct dcerpcd_pipe *pipe, uint32_t call_id, uint8_t drep0,
            uint32_t status)
{
        size_t len = 0;
        uint8_t *pdu = build_fault(call_id, drep0, status, &len);

        return out_queue_pdu(pipe, pdu, len);
}

/*
 * Queue a RESPONSE split into fragments of at most the negotiated
 * max_xmit. Stub data in all but the last fragment is a multiple of 8.
 */
static int
queue_response_ex(struct dcerpcd_pipe *pipe, uint8_t drep0,
                  uint16_t context_id, uint32_t call_id,
                  const uint8_t *stub, size_t stub_len)
{
        size_t max_xmit = pipe->max_xmit ? pipe->max_xmit
                                         : DCERPCD_DEFAULT_FRAG;
        size_t max_stub = 8;
        size_t off = 0;

        if (max_xmit >= DCERPC_COMMON_HDR + DCERPC_RSP_HDR + 8) {
                max_stub = (max_xmit - DCERPC_COMMON_HDR - DCERPC_RSP_HDR) &
                           ~(size_t)7;
        }
        do {
                size_t chunk = stub_len - off;
                uint8_t pfc = 0;
                uint8_t *out;
                size_t out_len = 0;

                if (chunk > max_stub) {
                        chunk = max_stub;
                }
                if (off == 0) {
                        pfc |= PFC_FIRST_FRAG;
                }
                if (off + chunk == stub_len) {
                        pfc |= PFC_LAST_FRAG;
                }
                out = build_response_frag(drep0, context_id, call_id, pfc,
                                          (uint32_t)(stub_len - off),
                                          chunk ? stub + off : NULL, chunk,
                                          &out_len);
                if (out_queue_pdu(pipe, out, out_len)) {
                        return -1;
                }
                off += chunk;
        } while (off < stub_len);
        return 0;
}

static int
queue_response(struct dcerpcd_pipe *pipe, uint32_t call_id,
               const uint8_t *stub, size_t stub_len)
{
        return queue_response_ex(pipe, pipe->packed_drep[0],
                                 pipe->context_id, call_id, stub, stub_len);
}

static void
pipe_send_error(struct smb2_context *smb2, uint8_t cmd, uint64_t msgid,
                uint32_t status)
{
        struct smb2_error_reply err;
        struct smb2_pdu *pdu;

        memset(&err, 0, sizeof(err));
        pdu = smb2_cmd_error_reply_async(smb2, &err, cmd, (int)status,
                                         NULL, NULL);
        if (pdu == NULL) {
                return;
        }
        smb2_set_pdu_message_id(smb2, pdu, msgid);
        smb2_queue_pdu(smb2, pdu);
}

/*
 * Reply to a TRANSCEIVE (SMB2_IOCTL) or READ with the next pipe message:
 * the rest of the current fragment, truncated to max bytes with
 * STATUS_BUFFER_OVERFLOW if it does not fit.
 */
static int
pipe_send_message(struct smb2_context *smb2, struct dcerpcd_pipe *pipe,
                  uint8_t cmd, uint64_t msgid, uint32_t max, uint32_t flags)
{
        struct smb2_pdu *pdu;
        uint8_t *data = NULL;
        size_t len = 0;
        int overflow = 0;

        if (pipe->out_pos < pipe->out_len) {
                if (pipe->out_frag_left == 0) {
                        pipe->out_frag_left =
                                get_le16(pipe->out_buf + pipe->out_pos + 8);
                }
                len = pipe->out_frag_left;
                if (len > max) {
                        len = max;
                        overflow = 1;
                }
                data = malloc(len ? len : 1);
                if (data == NULL) {
                        return -1;
                }
                memcpy(data, pipe->out_buf + pipe->out_pos, len);
                pipe->out_pos += len;
                pipe->out_frag_left -= len;
        }

        if (cmd == SMB2_READ) {
                struct smb2_read_reply rep;

                memset(&rep, 0, sizeof(rep));
                rep.data = data;
                rep.data_length = (uint32_t)len;
                /* the encoder takes ownership of data when len > 0 */
                pdu = smb2_cmd_read_reply_async(smb2, &rep, NULL, NULL);
                if (len == 0) {
                        free(data);
                }
        } else {
                struct smb2_ioctl_reply rep;

                memset(&rep, 0, sizeof(rep));
                rep.ctl_code = SMB2_FSCTL_PIPE_TRANSCEIVE;
                memcpy(rep.file_id, pipe->file_id, SMB2_FD_SIZE);
                rep.output = data;
                rep.output_count = (uint32_t)len;
                rep.flags = flags;
                /* the encoder copies output */
                pdu = smb2_cmd_ioctl_reply_async(smb2, &rep, NULL, NULL);
                free(data);
        }
        if (pdu == NULL) {
                return -1;
        }
        if (overflow) {
                smb2_set_pdu_status(smb2, pdu, SMB2_STATUS_BUFFER_OVERFLOW);
        }
        smb2_set_pdu_message_id(smb2, pdu, msgid);
        smb2_queue_pdu(smb2, pdu);
        return 0;
}

/* Complete a TRANSCEIVE/READ that was waiting for an EXTERNAL reply. */
static void
pipe_complete_wait(struct smb2_context *smb2, struct dcerpcd_pipe *pipe)
{
        uint8_t cmd = pipe->wait_cmd;

        if (cmd == 0) {
                return;
        }
        if (pipe->out_pos == pipe->out_len && pipe->calls_pending) {
                return;
        }
        pipe->wait_cmd = 0;
        if (pipe->out_pos == pipe->out_len ||
            pipe_send_message(smb2, pipe, cmd, pipe->wait_msgid,
                              pipe->wait_max, pipe->wait_flags)) {
                pipe_send_error(smb2, cmd, pipe->wait_msgid,
                                SMB2_STATUS_PIPE_BROKEN);
        }
}

/*
 * State for an in-flight EXTERNAL proxy RPC. Completed when the worker
 * replies (or on timeout/cancel); then we queue the DCERPC reply on the
 * pipe and complete any TRANSCEIVE/READ waiting for it.
 */
struct external_pending {
        struct smb2_context *smb2;
        smb2_file_id file_id;
        uint32_t call_id;
        uint8_t drep0;
        uint16_t context_id;
        uint8_t packed_drep0;
        uint32_t session_id;
        uint32_t msgid;
        char service_name[64];
};

static void
external_rpc_done(void *cb_data, int err, int32_t status,
                  uint8_t *ndr, uint32_t ndr_len)
{
        struct external_pending *p = cb_data;
        struct dcerpcd_pipe *pipe;
        int rc;

        if (p == NULL) {
                free(ndr);
                return;
        }

        /* SMB client gone — drop the reply. */
        if (err == -2) {
                free(ndr);
                free(p);
                return;
        }

        /* Pipe closed while the call was in flight — drop the reply. */
        pipe = pipe_find(dcerpcd_auth_conn(p->smb2), p->file_id);
        if (pipe == NULL) {
                free(ndr);
                free(p);
                return;
        }
        pipe->calls_pending--;

        if (err != 0 || status != DCERPCD_RPC_STATUS_OK) {
                printf("pipe: EXTERNAL %s session=%u service=%s msgid=%u "
                       "err=%d status=%d\n",
                       err != 0 ? "failed" : "worker FAULT",
                       p->session_id, p->service_name, p->msgid,
                       err, (int)status);
                rc = queue_fault(pipe, p->call_id, p->drep0, 0x1c010002);
        } else {
                printf("pipe: EXTERNAL success session=%u service=%s "
                       "msgid=%u ndr_len=%u\n",
                       p->session_id, p->service_name, p->msgid, ndr_len);
                rc = queue_response_ex(pipe, p->packed_drep0, p->context_id,
                                       p->call_id, ndr, ndr_len);
        }
        free(ndr);
        if (rc) {
                fprintf(stderr, "pipe: session=%u failed to queue reply "
                        "for call_id=%u\n", p->session_id, p->call_id);
        }
        pipe_complete_wait(p->smb2, pipe);
        free(p);
}

/*
 * Dispatch a complete (reassembled) REQUEST. The reply is appended to the
 * pipe's output queue. Returns 0 when it is queued, 1 when an EXTERNAL
 * call is in flight and will queue it later, -1 on failure.
 */
static int
handle_request(struct smb2_context *smb2, struct dcerpcd_pipe *pipe,
               uint32_t call_id, uint16_t opnum, uint8_t drep0,
               const uint8_t *stub, size_t stub_len)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        uint32_t session_id = conn ? conn->session_id : 0;
        uint8_t *stub_out = NULL;
        size_t stub_out_len = 0;
        int rc;

        if (!pipe->bound) {
                fprintf(stderr,
                        "pipe: REQUEST session=%u before successful BIND\n",
                        session_id);
                return queue_fault(pipe, call_id, drep0, 0x1c01000b);
        }

        printf("pipe: REQUEST session=%u service=%s kind=%s opnum=%u "
               "call_id=%u stub_len=%zu\n",
               session_id,
               pipe->service ? pipe->service->pipe_name : "?",
               pipe->service ? service_kind_str(pipe->service->kind) : "?",
               (unsigned)opnum, call_id, stub_len);

        if (pipe->service == NULL) {
                return queue_fault(pipe, call_id, drep0, 0x1c010002);
        }

        switch (pipe->service->kind) {
        case DCERPCD_SVC_BUILTIN_EPM:
                break; /* dispatch ept_* below */
        case DCERPCD_SVC_EXTERNAL: {
                int32_t uid = DCERPCD_RPC_UID_GUEST;
                uint32_t msgid = 0;
                int cfd = pipe->service->conn_fd;
                struct external_pending *pend;

                if (conn && conn->auth_kind == DCERPCD_AUTH_USER) {
                        uid = (int32_t)conn->uid;
                }
                if (cfd < 0) {
                        fprintf(stderr,
                                "pipe: EXTERNAL session=%u %s has no control fd\n",
                                session_id, pipe->service->pipe_name);
                        return queue_fault(pipe, call_id, drep0, 0x1c010002);
                }

                pend = calloc(1, sizeof(*pend));
                if (pend == NULL) {
                        return queue_fault(pipe, call_id, drep0, 0x1c010002);
                }
                pend->smb2 = smb2;
                memcpy(pend->file_id, pipe->file_id, SMB2_FD_SIZE);
                pend->call_id = call_id;
                pend->drep0 = drep0;
                pend->context_id = pipe->context_id;
                pend->packed_drep0 = pipe->packed_drep[0]
                                             ? pipe->packed_drep[0] : 0x10;
                pend->session_id = session_id;
                snprintf(pend->service_name, sizeof(pend->service_name), "%s",
                         pipe->service->pipe_name
                                 ? pipe->service->pipe_name : "?");

                if (dcerpcd_external_call_async(cfd, smb2, session_id, uid,
                                                opnum, stub,
                                                (uint32_t)stub_len,
                                                external_rpc_done, pend,
                                                &msgid) != 0) {
                        fprintf(stderr,
                                "pipe: EXTERNAL forward failed session=%u "
                                "service=%s opnum=%u\n",
                                session_id, pipe->service->pipe_name,
                                (unsigned)opnum);
                        free(pend);
                        return queue_fault(pipe, call_id, drep0, 0x1c010002);
                }
                pend->msgid = msgid;
                printf("pipe: EXTERNAL forwarded session=%u service=%s "
                       "opnum=%u uid=%d msgid=%u ndr_len=%zu (async)\n",
                       session_id, pipe->service->pipe_name, (unsigned)opnum,
                       (int)uid, msgid, stub_len);
                pipe->calls_pending++;
                return 1; /* reply deferred */
        }
        default:
                return queue_fault(pipe, call_id, drep0, 0x1c010002);
        }

        /* --- builtin endpoint mapper --- */
        {
                int is_root = dcerpcd_conn_is_root(conn);

                /*
                 * Access control: ept_Lookup and ept_Map are open to any
                 * session (including guest). All other ept_* ops require
                 * an SMB session authenticated as local root (uid 0).
                 */
                if (opnum != EPM_LOOKUP && opnum != EPM_MAP && !is_root) {
                        fprintf(stderr,
                                "pipe: epm opnum %u denied session=%u "
                                "user=%s uid=%ld (root required)\n",
                                (unsigned)opnum, session_id,
                                conn && conn->username ? conn->username : "?",
                                conn ? (long)conn->uid : -1L);
                        /*
                         * Windows ERROR_ACCESS_DENIED as error_status_t in a
                         * normal RESPONSE is awkward without knowing the
                         * reply layout; use a DCERPC FAULT instead.
                         */
                        return queue_fault(pipe, call_id, drep0, 0x00000005);
                }
        }

        switch (opnum) {
        case EPM_LOOKUP: {
                struct epm_Lookup_req req;
                struct epm_Lookup_rep rep;
                struct dcerpc_context *dce = NULL;
                struct dcerpc_pdu *pdu = NULL;

                if (ndr_decode_stub(smb2, stub, stub_len, &req, sizeof(req),
                                    epm_Lookup_req_coder, &dce, &pdu)) {
                        return queue_fault(pipe, call_id, drep0, 0x1c010003);
                }
                if (dcerpcd_epm_Lookup(&req, &rep)) {
                        ndr_decode_done(dce, pdu);
                        return queue_fault(pipe, call_id, drep0, 0x1c010004);
                }
                if (ndr_encode_stub(smb2, &req, &rep, epm_Lookup_rep_coder,
                                    &stub_out, &stub_out_len)) {
                        dcerpcd_epm_Lookup_free_rep(&rep);
                        ndr_decode_done(dce, pdu);
                        return queue_fault(pipe, call_id, drep0, 0x1c010005);
                }
                dcerpcd_epm_Lookup_free_rep(&rep);
                ndr_decode_done(dce, pdu);
                break;
        }
        case EPM_MAP: {
                struct epm_Map_req req;
                struct epm_Map_rep rep;
                struct dcerpc_context *dce = NULL;
                struct dcerpc_pdu *pdu = NULL;

                if (ndr_decode_stub(smb2, stub, stub_len, &req, sizeof(req),
                                    epm_Map_req_coder, &dce, &pdu)) {
                        return queue_fault(pipe, call_id, drep0, 0x1c010003);
                }
                if (dcerpcd_epm_Map(&req, &rep)) {
                        ndr_decode_done(dce, pdu);
                        return queue_fault(pipe, call_id, drep0, 0x1c010004);
                }
                if (ndr_encode_stub(smb2, &req, &rep, epm_Map_rep_coder,
                                    &stub_out, &stub_out_len)) {
                        dcerpcd_epm_Map_free_rep(&rep);
                        ndr_decode_done(dce, pdu);
                        return queue_fault(pipe, call_id, drep0, 0x1c010005);
                }
                dcerpcd_epm_Map_free_rep(&rep);
                ndr_decode_done(dce, pdu);
                break;
        }
        case EPM_LOOKUPHANDLEFREE: {
                struct epm_LookupHandleFree_req req;
                struct epm_LookupHandleFree_rep rep;
                struct dcerpc_context *dce = NULL;
                struct dcerpc_pdu *pdu = NULL;

                if (ndr_decode_stub(smb2, stub, stub_len, &req, sizeof(req),
                                    epm_LookupHandleFree_req_coder, &dce, &pdu)) {
                        return queue_fault(pipe, call_id, drep0, 0x1c010003);
                }
                if (dcerpcd_epm_LookupHandleFree(&req, &rep)) {
                        ndr_decode_done(dce, pdu);
                        return queue_fault(pipe, call_id, drep0, 0x1c010004);
                }
                if (ndr_encode_stub(smb2, NULL, &rep,
                                    epm_LookupHandleFree_rep_coder,
                                    &stub_out, &stub_out_len)) {
                        ndr_decode_done(dce, pdu);
                        return queue_fault(pipe, call_id, drep0, 0x1c010005);
                }
                ndr_decode_done(dce, pdu);
                break;
        }
        default:
                fprintf(stderr, "pipe: unsupported epm opnum %u session=%u\n",
                        (unsigned)opnum, session_id);
                return queue_fault(pipe, call_id, drep0, 0x1c01000b);
        }

        rc = queue_response(pipe, call_id, stub_out, stub_out_len);
        free(stub_out);
        return rc;
}

/*
 * One REQUEST fragment. Stub data is accumulated until PFC_LAST_FRAG,
 * then the whole call is dispatched.
 */
static int
pipe_request_frag(struct smb2_context *smb2, struct dcerpcd_pipe *pipe,
                  const uint8_t *pdu, size_t len)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        uint32_t session_id = conn ? conn->session_id : 0;
        uint8_t pfc = pdu[3];
        uint8_t drep0 = pdu[4];
        uint16_t auth_len = get_le16(pdu + 10);
        uint32_t call_id = get_le32(pdu + 12);
        size_t hdr = DCERPC_COMMON_HDR + DCERPC_REQ_HDR;
        size_t end = len;
        size_t stub_len;
        uint8_t *ns;
        int rc;

        if (pfc & PFC_OBJECT_UUID) {
                hdr += 16;
        }
        if (auth_len) {
                /* strip sec_trailer, auth value and auth padding */
                if (len < hdr + 8 + (size_t)auth_len) {
                        return queue_fault(pipe, call_id, drep0, 0x1c01000b);
                }
                end = len - 8 - auth_len;
                if (pdu[end + 2] > end - hdr) {
                        return queue_fault(pipe, call_id, drep0, 0x1c01000b);
                }
                end -= pdu[end + 2];
        }
        if (len < hdr) {
                return queue_fault(pipe, call_id, drep0, 0x1c01000b);
        }
        stub_len = end - hdr;

        if (pfc & PFC_FIRST_FRAG) {
                if (pipe->req_active) {
                        fprintf(stderr,
                                "pipe: session=%u REQUEST call_id=%u "
                                "abandons partial call_id=%u\n",
                                session_id, call_id, pipe->req_call_id);
                }
                pipe->req_active = 1;
                pipe->req_call_id = call_id;
                pipe->req_opnum = get_le16(pdu + DCERPC_COMMON_HDR + 6);
                pipe->req_drep0 = drep0;
                pipe->req_stub_len = 0;
        } else if (!pipe->req_active || call_id != pipe->req_call_id) {
                fprintf(stderr,
                        "pipe: session=%u unexpected REQUEST fragment "
                        "call_id=%u\n", session_id, call_id);
                pipe->req_active = 0;
                return queue_fault(pipe, call_id, drep0, 0x1c01000b);
        }

        if (stub_len > DCERPCD_MAX_REQ_STUB - pipe->req_stub_len) {
                fprintf(stderr,
                        "pipe: session=%u REQUEST call_id=%u exceeds %u "
                        "bytes\n", session_id, call_id,
                        (unsigned)DCERPCD_MAX_REQ_STUB);
                pipe->req_active = 0;
                return queue_fault(pipe, call_id, drep0, 0x1c01000b);
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
        rc = handle_request(smb2, pipe, call_id, pipe->req_opnum,
                            pipe->req_drep0, pipe->req_stub,
                            pipe->req_stub_len);
        pipe->req_stub_len = 0;
        return rc < 0 ? -1 : 0;
}

static int
pipe_process_pdu(struct smb2_context *smb2, struct dcerpcd_pipe *pipe,
                 const uint8_t *pdu, size_t len)
{
        struct dcerpcd_conn *conn;
        uint8_t *out;
        size_t olen = 0;

        switch (pdu[2]) {
        case PDU_TYPE_BIND:
                out = build_bind_ack(smb2, pipe, pdu, len, &olen);
                return out_queue_pdu(pipe, out, olen);
        case PDU_TYPE_REQUEST:
                return pipe_request_frag(smb2, pipe, pdu, len);
        default:
                conn = dcerpcd_auth_conn(smb2);
                fprintf(stderr, "pipe: unhandled DCERPC PTYPE %u session=%u\n",
                        pdu[2], conn ? conn->session_id : 0);
                return -1;
        }
}

/*
 * Feed bytes written to the pipe (WRITE or TRANSCEIVE input). Every
 * complete PDU is processed; a trailing partial PDU is kept for the next
 * write. Returns -1 on a malformed stream.
 */
static int
pipe_input(struct smb2_context *smb2, struct dcerpcd_pipe *pipe,
           const uint8_t *data, size_t len)
{
        size_t pos = 0;
        uint8_t *nb;

        if (len) {
                nb = realloc(pipe->in_buf, pipe->in_len + len);
                if (nb == NULL) {
                        return -1;
                }
                pipe->in_buf = nb;
                memcpy(nb + pipe->in_len, data, len);
                pipe->in_len += len;
        }

        while (pipe->in_len - pos >= DCERPC_COMMON_HDR) {
                const uint8_t *pdu = pipe->in_buf + pos;
                uint16_t frag_len = get_le16(pdu + 8);

                if (pdu[0] != 5 || pdu[1] != 0 ||
                    frag_len < DCERPC_COMMON_HDR) {
                        pipe->in_len = 0;
                        return -1;
                }
                if (pipe->in_len - pos < frag_len) {
                        break;
                }
                if (pipe_process_pdu(smb2, pipe, pdu, frag_len)) {
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

/* ------------------------------------------------------------------ */
/* SMB2 server handlers                                                */
/* ------------------------------------------------------------------ */

int
dcerpcd_pipe_create(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                    struct smb2_create_request *req,
                    struct smb2_create_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        struct dcerpcd_pipe *p;
        const struct dcerpcd_service *svc;
        char *base;

        if (conn == NULL) {
                return -1;
        }
        base = pipe_basename(req->name);
        svc = dcerpcd_service_lookup(base);
        if (base == NULL || svc == NULL) {
                fprintf(stderr,
                        "pipe: CREATE rejected session=%u name=\"%s\" "
                        "(unknown service)\n",
                        conn->session_id,
                        req->name ? req->name : "(null)");
                free(base);
                return -1;
        }
        if (svc->kind == DCERPCD_SVC_EXTERNAL && svc->conn_fd < 0) {
                fprintf(stderr,
                        "pipe: CREATE session=%u %s: EXTERNAL service not "
                        "connected\n",
                        conn->session_id, base);
                free(base);
                return -1;
        }

        p = calloc(1, sizeof(*p));
        if (p == NULL) {
                free(base);
                return -1;
        }
        p->name = base;
        p->service = svc;
        fid_assign(p->file_id, next_fid, next_fid + 0x10000);
        next_fid++;
        p->next = conn->pipes;
        conn->pipes = p;

        memset(rep, 0, sizeof(*rep));
        rep->oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        rep->create_action = SMB2_FILE_OPEN; /* FILE_OPENED */
        rep->file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
        memcpy(rep->file_id, p->file_id, SMB2_FD_SIZE);

        printf("pipe: CREATE session=%u %s service=%s kind=%s\n",
               conn->session_id, p->name, svc->pipe_name,
               service_kind_str(svc->kind));
        return 0;
}

int
dcerpcd_pipe_close(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                   struct smb2_close_request *req,
                   struct smb2_close_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        struct dcerpcd_pipe **pp;

        memset(rep, 0, sizeof(*rep));
        if (conn == NULL) {
                return 0;
        }
        for (pp = &conn->pipes; *pp; pp = &(*pp)->next) {
                if (fid_equal((*pp)->file_id, req->file_id)) {
                        struct dcerpcd_pipe *p = *pp;

                        *pp = p->next;
                        if (p->wait_cmd) {
                                pipe_send_error(smb2, p->wait_cmd,
                                                p->wait_msgid,
                                                SMB2_STATUS_PIPE_BROKEN);
                        }
                        printf("pipe: CLOSE session=%u %s kind=%s\n",
                               conn->session_id,
                               p->name ? p->name : "?",
                               p->service ? service_kind_str(p->service->kind)
                                          : "?");
                        pipe_free(p);
                        return 0;
                }
        }
        return 0;
}

/*
 * Park a TRANSCEIVE/READ until an in-flight EXTERNAL call queues output.
 * Only one may wait at a time.
 */
static int
pipe_wait(struct smb2_context *smb2, struct dcerpcd_pipe *pipe, uint8_t cmd,
          uint32_t max, uint32_t flags)
{
        uint64_t msgid = smb2_get_last_request_message_id(smb2);

        if (pipe->wait_cmd) {
                pipe_send_error(smb2, cmd, msgid, SMB2_STATUS_PIPE_BUSY);
                return 1;
        }
        pipe->wait_cmd = cmd;
        pipe->wait_msgid = msgid;
        pipe->wait_max = max;
        pipe->wait_flags = flags;
        return 1;
}

int
dcerpcd_pipe_ioctl(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                   struct smb2_ioctl_request *req,
                   struct smb2_ioctl_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        struct dcerpcd_pipe *p;

        memset(rep, 0, sizeof(*rep));
        rep->ctl_code = req->ctl_code;
        memcpy(rep->file_id, req->file_id, SMB2_FD_SIZE);

        if (req->ctl_code == SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO) {
                /* library handles this before calling us, but be safe */
                return -1;
        }

        if (req->ctl_code != SMB2_FSCTL_PIPE_TRANSCEIVE) {
                fprintf(stderr, "pipe: unsupported ioctl session=%u 0x%08x\n",
                        conn ? conn->session_id : 0, req->ctl_code);
                return -1;
        }

        p = pipe_find(conn, req->file_id);
        if (p == NULL) {
                fprintf(stderr,
                        "pipe: TRANSCEIVE session=%u on unknown file_id\n",
                        conn ? conn->session_id : 0);
                return -1;
        }

        if (pipe_input(smb2, p, req->input, req->input_count)) {
                return -1;
        }
        if (p->out_pos == p->out_len && p->calls_pending) {
                /* EXTERNAL: reply deferred until worker responds */
                return pipe_wait(smb2, p, SMB2_IOCTL,
                                 req->max_output_response, req->flags);
        }
        if (pipe_send_message(smb2, p, SMB2_IOCTL,
                              smb2_get_last_request_message_id(smb2),
                              req->max_output_response, req->flags)) {
                return -1;
        }
        return 1;
}

int
dcerpcd_pipe_read(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                  struct smb2_read_request *req,
                  struct smb2_read_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        struct dcerpcd_pipe *p;

        memset(rep, 0, sizeof(*rep));
        p = pipe_find(conn, req->file_id);
        if (p == NULL) {
                fprintf(stderr, "pipe: READ session=%u on unknown file_id\n",
                        conn ? conn->session_id : 0);
                return -1;
        }
        if (p->out_pos == p->out_len) {
                if (p->calls_pending) {
                        return pipe_wait(smb2, p, SMB2_READ, req->length, 0);
                }
                pipe_send_error(smb2, SMB2_READ,
                                smb2_get_last_request_message_id(smb2),
                                SMB2_STATUS_PIPE_EMPTY);
                return 1;
        }
        if (pipe_send_message(smb2, p, SMB2_READ,
                              smb2_get_last_request_message_id(smb2),
                              req->length, 0)) {
                return -1;
        }
        return 1;
}

int
dcerpcd_pipe_write(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                   struct smb2_write_request *req,
                   struct smb2_write_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        struct dcerpcd_pipe *p;

        memset(rep, 0, sizeof(*rep));
        p = pipe_find(conn, req->file_id);
        if (p == NULL) {
                fprintf(stderr, "pipe: WRITE session=%u on unknown file_id\n",
                        conn ? conn->session_id : 0);
                return -1;
        }
        if (pipe_input(smb2, p, req->buf, req->length)) {
                return -1;
        }
        rep->count = req->length;
        return 0;
}
