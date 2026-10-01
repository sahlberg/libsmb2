/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2018 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
#include "portable-endian.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

/*
 * Share enumeration: a small, self-contained DCE/RPC client for
 * srvsvc NetrShareEnum ([MS-SRVS] 3.1.4.8) over the \srvsvc named pipe.
 * It binds with NDR32 only and supports SHARE_INFO levels 0, 1 and 2.
 * The general DCE/RPC implementation lives in libdcerpc; libsmb2 does not
 * depend on it.
 */

#define DCE_PTYPE_REQUEST   0
#define DCE_PTYPE_RESPONSE  2
#define DCE_PTYPE_FAULT     3
#define DCE_PTYPE_BIND      11
#define DCE_PTYPE_BIND_ACK  12
#define DCE_PTYPE_BIND_NAK  13

#define DCE_PFC_FIRST_FRAG  0x01
#define DCE_PFC_LAST_FRAG   0x02

#define DCE_DREP_LE         0x10

#define DCE_HDR_LEN         16
#define DCE_RESP_HDR_LEN    24

#define SRVSVC_OPNUM_NETRSHAREENUM 15

#define SE_FRAG_READ_SIZE   65536
#define SE_MAX_RESPONSE     (16 * 1024 * 1024)

/* srvsvc 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0 */
static const uint8_t srvsvc_abstract_syntax[20] = {
        0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
        0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
        0x03, 0x00, 0x00, 0x00
};

/* NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2 */
static const uint8_t ndr32_transfer_syntax[20] = {
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00
};

struct share_enum {
        struct smb2_context *smb2;
        smb2_command_cb cb;
        void *cb_data;
        uint32_t level;
        smb2_file_id file_id;
        int file_open;

        /* response fragments, appended as they arrive */
        uint8_t *rbuf;
        size_t rlen;
        size_t rcap;
        uint8_t *readbuf;
};

/*
 * Little helpers for building PDUs (always little-endian) and for
 * reading data in the byte order of the fragment that carries it.
 */
struct se_buf {
        uint8_t *buf;
        size_t len;
        size_t cap;
};

static int
se_put(struct se_buf *b, const void *data, size_t len)
{
        if (b->len + len > b->cap) {
                return -1;
        }
        memcpy(b->buf + b->len, data, len);
        b->len += len;
        return 0;
}

static int
se_put_u16(struct se_buf *b, uint16_t v)
{
        uint8_t d[2];

        d[0] = v & 0xff;
        d[1] = (v >> 8) & 0xff;
        return se_put(b, d, 2);
}

static int
se_put_u32(struct se_buf *b, uint32_t v)
{
        uint8_t d[4];

        d[0] = v & 0xff;
        d[1] = (v >> 8) & 0xff;
        d[2] = (v >> 16) & 0xff;
        d[3] = (v >> 24) & 0xff;
        return se_put(b, d, 4);
}

static int
se_align(struct se_buf *b, size_t align, size_t base)
{
        static const uint8_t zero[8];
        size_t pad = (align - ((b->len - base) % align)) % align;

        return se_put(b, zero, pad);
}

static uint16_t
se_get_u16(const uint8_t *p, int be)
{
        if (be) {
                return (uint16_t)((p[0] << 8) | p[1]);
        }
        return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t
se_get_u32(const uint8_t *p, int be)
{
        if (be) {
                return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                        ((uint32_t)p[2] << 8) | p[3];
        }
        return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
                ((uint32_t)p[3] << 24);
}

/* Common header of a request/bind PDU; frag_length is patched later. */
static int
se_put_header(struct se_buf *b, uint8_t ptype, uint32_t call_id)
{
        uint8_t hdr[8] = { 5, 0, 0, DCE_PFC_FIRST_FRAG | DCE_PFC_LAST_FRAG,
                           DCE_DREP_LE, 0, 0, 0 };

        hdr[2] = ptype;
        if (se_put(b, hdr, sizeof(hdr)) ||
            se_put_u16(b, 0) ||         /* frag_length */
            se_put_u16(b, 0) ||         /* auth_length */
            se_put_u32(b, call_id)) {
                return -1;
        }
        return 0;
}

static void
se_set_frag_length(struct se_buf *b)
{
        b->buf[8] = b->len & 0xff;
        b->buf[9] = (b->len >> 8) & 0xff;
}

static void
share_enum_free(struct share_enum *se)
{
        free(se->rbuf);
        free(se->readbuf);
        free(se);
}

static void
share_enum_close_cb(struct smb2_context *smb2 _U_, int status _U_,
                    void *command_data _U_, void *private_data _U_)
{
}

/*
 * Close the pipe (unless the context is shutting down), report the
 * result to the caller and free the state.
 */
static void
share_enum_done(struct share_enum *se, int status, int smb2_status,
                struct smb2_share_enum_reply *rep)
{
        struct smb2_context *smb2 = se->smb2;
        smb2_command_cb cb = se->cb;
        void *cb_data = se->cb_data;

        if (se->file_open && smb2_status != SMB2_STATUS_SHUTDOWN &&
            smb2_status != SMB2_STATUS_CANCELLED) {
                struct smb2_close_request req;
                struct smb2_pdu *pdu;

                memset(&req, 0, sizeof(req));
                memcpy(req.file_id, se->file_id, SMB2_FD_SIZE);
                pdu = smb2_cmd_close_async(smb2, &req, share_enum_close_cb,
                                           NULL);
                if (pdu) {
                        smb2_queue_pdu(smb2, pdu);
                }
        }
        share_enum_free(se);
        cb(smb2, status, rep, cb_data);
}

static void
share_enum_fail(struct share_enum *se, int smb2_status, int err)
{
        share_enum_done(se, err, smb2_status, NULL);
}

/*
 * NDR32 decoding of the NetrShareEnum response stub.
 */
struct se_ndr {
        const uint8_t *buf;
        size_t len;
        size_t off;
        int be;
};

static int
ndr_u32(struct se_ndr *n, uint32_t *v)
{
        n->off = (n->off + 3) & ~(size_t)3;
        if (n->off + 4 > n->len) {
                return -1;
        }
        *v = se_get_u32(n->buf + n->off, n->be);
        n->off += 4;
        return 0;
}

/* [string] wchar_t * body: max_count, offset, actual_count, UTF-16 data */
static int
ndr_string(struct se_ndr *n, struct smb2_context *smb2, void *memctx,
           char **out)
{
        uint32_t max_count, offset, count, i;
        uint16_t *u16;
        const char *utf8;
        size_t len;

        if (ndr_u32(n, &max_count) || ndr_u32(n, &offset) ||
            ndr_u32(n, &count)) {
                return -1;
        }
        if (offset != 0 || count > max_count ||
            count > (n->len - n->off) / 2) {
                return -1;
        }
        /* drop the terminating NUL */
        len = count;
        if (len && se_get_u16(n->buf + n->off + 2 * (len - 1), n->be) == 0) {
                len--;
        }
        u16 = malloc((len + 1) * sizeof(uint16_t));
        if (u16 == NULL) {
                return -1;
        }
        /* smb2_utf16_to_utf8() takes little-endian UTF-16 */
        for (i = 0; i < len; i++) {
                u16[i] = htole16(se_get_u16(n->buf + n->off + 2 * i, n->be));
        }
        n->off += 2 * (size_t)count;

        utf8 = smb2_utf16_to_utf8(u16, len);
        free(u16);
        if (utf8 == NULL) {
                return -1;
        }
        *out = smb2_alloc_data(smb2, memctx, strlen(utf8) + 1);
        if (*out == NULL) {
                free(discard_const(utf8));
                return -1;
        }
        strcpy(*out, utf8);
        free(discard_const(utf8));
        return 0;
}

/* A unique pointer to a string: the referent id now, the body deferred. */
#define SE_MAX_STRINGS 4

struct se_entry_ptrs {
        uint32_t ref[SE_MAX_STRINGS];
        char **dst[SE_MAX_STRINGS];
};

static int
ndr_string_ptr(struct se_ndr *n, struct se_entry_ptrs *p, int idx, char **dst)
{
        p->dst[idx] = dst;
        return ndr_u32(n, &p->ref[idx]);
}

static int
se_decode_stub(struct share_enum *se, struct se_ndr *n,
               struct smb2_share_enum_reply *rep, uint32_t *werror)
{
        struct smb2_context *smb2 = se->smb2;
        struct se_entry_ptrs *ptrs = NULL;
        uint32_t level, sw, ctr_ref, count, buf_ref, max_count;
        uint32_t total, resume_ref, resume;
        uint32_t i;
        int j, nptrs;
        size_t esize;
        void *array = NULL;

        /* [in,out] LPSHARE_ENUM_STRUCT InfoStruct (top-level ref) */
        if (ndr_u32(n, &level) || ndr_u32(n, &sw) || ndr_u32(n, &ctr_ref)) {
                return -1;
        }
        if (level != se->level || sw != level) {
                return -1;
        }
        rep->level = level;
        count = 0;
        if (ctr_ref) {
                if (ndr_u32(n, &count) || ndr_u32(n, &buf_ref)) {
                        return -1;
                }
                if (buf_ref == 0) {
                        count = 0;
                }
        }
        if (count) {
                if (ndr_u32(n, &max_count) || max_count != count) {
                        return -1;
                }
                /* each entry takes at least 4 bytes on the wire */
                if (count > (n->len - n->off) / 4) {
                        return -1;
                }
                switch (level) {
                case SMB2_SHARE_INFO_0:
                        esize = sizeof(struct smb2_share_info_0);
                        nptrs = 1;
                        break;
                case SMB2_SHARE_INFO_1:
                        esize = sizeof(struct smb2_share_info_1);
                        nptrs = 2;
                        break;
                default:
                        esize = sizeof(struct smb2_share_info_2);
                        nptrs = 4;
                        break;
                }
                array = smb2_alloc_data(smb2, rep, count * esize);
                ptrs = calloc(count, sizeof(*ptrs));
                if (array == NULL || ptrs == NULL) {
                        free(ptrs);
                        return -1;
                }
                /* the array: fixed part of every entry */
                for (i = 0; i < count; i++) {
                        int rc = 0;

                        switch (level) {
                        case SMB2_SHARE_INFO_0: {
                                struct smb2_share_info_0 *e =
                                        (struct smb2_share_info_0 *)array + i;

                                rc = ndr_string_ptr(n, &ptrs[i], 0,
                                                    &e->netname);
                                break;
                        }
                        case SMB2_SHARE_INFO_1: {
                                struct smb2_share_info_1 *e =
                                        (struct smb2_share_info_1 *)array + i;

                                rc = ndr_string_ptr(n, &ptrs[i], 0,
                                                    &e->netname) ||
                                        ndr_u32(n, &e->type) ||
                                        ndr_string_ptr(n, &ptrs[i], 1,
                                                       &e->remark);
                                break;
                        }
                        default: {
                                struct smb2_share_info_2 *e =
                                        (struct smb2_share_info_2 *)array + i;

                                rc = ndr_string_ptr(n, &ptrs[i], 0,
                                                    &e->netname) ||
                                        ndr_u32(n, &e->type) ||
                                        ndr_string_ptr(n, &ptrs[i], 1,
                                                       &e->remark) ||
                                        ndr_u32(n, &e->permissions) ||
                                        ndr_u32(n, &e->max_users) ||
                                        ndr_u32(n, &e->current_users) ||
                                        ndr_string_ptr(n, &ptrs[i], 2,
                                                       &e->path) ||
                                        ndr_string_ptr(n, &ptrs[i], 3,
                                                       &e->passwd);
                                break;
                        }
                        }
                        if (rc) {
                                free(ptrs);
                                return -1;
                        }
                }
                /* then the deferred strings, entry by entry, in order */
                for (i = 0; i < count; i++) {
                        for (j = 0; j < nptrs; j++) {
                                if (ptrs[i].ref[j] == 0) {
                                        continue;
                                }
                                if (ndr_string(n, smb2, rep,
                                               ptrs[i].dst[j])) {
                                        free(ptrs);
                                        return -1;
                                }
                        }
                }
                free(ptrs);
        }
        rep->entries_read = count;
        switch (level) {
        case SMB2_SHARE_INFO_0:
                rep->share_info.info_0 = array;
                break;
        case SMB2_SHARE_INFO_1:
                rep->share_info.info_1 = array;
                break;
        default:
                rep->share_info.info_2 = array;
                break;
        }

        /* [out] DWORD *TotalEntries, [in,out,unique] DWORD *ResumeHandle */
        if (ndr_u32(n, &total) || ndr_u32(n, &resume_ref)) {
                return -1;
        }
        if (resume_ref && ndr_u32(n, &resume)) {
                return -1;
        }
        rep->total_entries = total;
        return ndr_u32(n, werror);
}

/*
 * The complete response is in se->rbuf: check every fragment, join the
 * stubs and decode them.
 */
static void
share_enum_decode(struct share_enum *se)
{
        struct smb2_context *smb2 = se->smb2;
        struct smb2_share_enum_reply *rep;
        uint8_t *stub = NULL;
        size_t stub_len = 0, off = 0;
        struct se_ndr n;
        uint32_t werror = 0;
        int be = !(se->rbuf[4] & DCE_DREP_LE);

        if (se->rbuf[2] == DCE_PTYPE_FAULT) {
                uint32_t fault = 0;

                if (se->rlen >= 28) {
                        fault = se_get_u32(se->rbuf + 24, be);
                }
                smb2_set_error(smb2, "DCERPC FAULT status=0x%08x", fault);
                share_enum_fail(se, 0, -EACCES);
                return;
        }

        stub = malloc(se->rlen);
        if (stub == NULL) {
                smb2_set_error(smb2, "Failed to allocate share enum stub");
                share_enum_fail(se, 0, -ENOMEM);
                return;
        }
        while (off < se->rlen) {
                const uint8_t *frag = se->rbuf + off;
                uint16_t frag_len = se_get_u16(frag + 8, be);

                if (frag[2] != DCE_PTYPE_RESPONSE ||
                    se_get_u16(frag + 10, be) != 0 ||
                    frag_len < DCE_RESP_HDR_LEN) {
                        smb2_set_error(smb2, "Unexpected srvsvc response "
                                       "fragment");
                        free(stub);
                        share_enum_fail(se, 0, -EINVAL);
                        return;
                }
                memcpy(stub + stub_len, frag + DCE_RESP_HDR_LEN,
                       frag_len - DCE_RESP_HDR_LEN);
                stub_len += frag_len - DCE_RESP_HDR_LEN;
                off += frag_len;
        }

        rep = smb2_alloc_init(smb2, sizeof(*rep));
        if (rep == NULL) {
                free(stub);
                smb2_set_error(smb2, "Failed to allocate share enum reply");
                share_enum_fail(se, 0, -ENOMEM);
                return;
        }
        n.buf = stub;
        n.len = stub_len;
        n.off = 0;
        n.be = be;
        if (se_decode_stub(se, &n, rep, &werror)) {
                free(stub);
                smb2_free_data(smb2, rep);
                smb2_set_error(smb2, "Failed to decode NetrShareEnum reply");
                share_enum_fail(se, 0, -EINVAL);
                return;
        }
        free(stub);
        share_enum_done(se, (int)werror, 0, rep);
}

static int share_enum_read_more(struct share_enum *se);

/*
 * Append data to the response buffer; once the last fragment is complete
 * decode it, otherwise read more from the pipe.
 */
static void
share_enum_got_data(struct share_enum *se, const uint8_t *data, size_t len)
{
        struct smb2_context *smb2 = se->smb2;
        size_t off = 0;

        if (se->rlen + len > SE_MAX_RESPONSE) {
                smb2_set_error(smb2, "srvsvc response too large");
                share_enum_fail(se, 0, -EINVAL);
                return;
        }
        if (se->rlen + len > se->rcap) {
                size_t cap = se->rcap ? se->rcap : 4096;
                uint8_t *nbuf;

                while (cap < se->rlen + len) {
                        cap *= 2;
                }
                nbuf = realloc(se->rbuf, cap);
                if (nbuf == NULL) {
                        smb2_set_error(smb2, "Failed to grow srvsvc "
                                       "response buffer");
                        share_enum_fail(se, 0, -ENOMEM);
                        return;
                }
                se->rbuf = nbuf;
                se->rcap = cap;
        }
        memcpy(se->rbuf + se->rlen, data, len);
        se->rlen += len;

        /* walk the fragments received so far */
        while (1) {
                const uint8_t *frag = se->rbuf + off;
                uint16_t frag_len;
                int be;

                if (se->rlen - off < DCE_HDR_LEN) {
                        break;
                }
                be = !(frag[4] & DCE_DREP_LE);
                frag_len = se_get_u16(frag + 8, be);
                if (frag[0] != 5 || frag_len < DCE_HDR_LEN) {
                        smb2_set_error(smb2, "Invalid srvsvc response "
                                       "fragment");
                        share_enum_fail(se, 0, -EINVAL);
                        return;
                }
                if (se->rlen - off < frag_len) {
                        break;
                }
                if (frag[2] != DCE_PTYPE_RESPONSE ||
                    (frag[3] & DCE_PFC_LAST_FRAG)) {
                        if (off + frag_len != se->rlen) {
                                smb2_set_error(smb2, "Trailing data after "
                                               "srvsvc response");
                                share_enum_fail(se, 0, -EINVAL);
                                return;
                        }
                        share_enum_decode(se);
                        return;
                }
                off += frag_len;
        }

        if (share_enum_read_more(se)) {
                smb2_set_error(smb2, "Failed to read srvsvc response");
                share_enum_fail(se, 0, -ENOMEM);
        }
}

static void
share_enum_read_cb(struct smb2_context *smb2, int status,
                   void *command_data, void *private_data)
{
        struct share_enum *se = private_data;
        struct smb2_read_reply *rep = command_data;

        /* a fragment larger than our read buffer: take what we got */
        if (status == SMB2_STATUS_BUFFER_OVERFLOW) {
                status = SMB2_STATUS_SUCCESS;
        }
        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "srvsvc READ failed: %s",
                               nterror_to_str(status));
                share_enum_fail(se, status, -nterror_to_errno(status));
                return;
        }
        if (rep == NULL || rep->data_length == 0) {
                smb2_set_error(smb2, "srvsvc READ returned no data");
                share_enum_fail(se, 0, -EIO);
                return;
        }
        share_enum_got_data(se, se->readbuf, rep->data_length);
}

static int
share_enum_read_more(struct share_enum *se)
{
        struct smb2_read_request req;
        struct smb2_pdu *pdu;

        if (se->readbuf == NULL) {
                se->readbuf = malloc(SE_FRAG_READ_SIZE);
                if (se->readbuf == NULL) {
                        return -1;
                }
        }
        memset(&req, 0, sizeof(req));
        memcpy(req.file_id, se->file_id, SMB2_FD_SIZE);
        req.length = SE_FRAG_READ_SIZE;
        req.buf = se->readbuf;
        req.channel = SMB2_CHANNEL_NONE;
        pdu = smb2_cmd_read_async(se->smb2, &req, share_enum_read_cb, se);
        if (pdu == NULL) {
                return -1;
        }
        smb2_queue_pdu(se->smb2, pdu);
        return 0;
}

static void
share_enum_request_cb(struct smb2_context *smb2, int status,
                      void *command_data, void *private_data)
{
        struct share_enum *se = private_data;
        struct smb2_ioctl_reply *rep = command_data;

        /* the reply did not fit: the rest is read from the pipe */
        if (status == SMB2_STATUS_BUFFER_OVERFLOW) {
                status = SMB2_STATUS_SUCCESS;
        }
        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "srvsvc NetrShareEnum failed: %s",
                               nterror_to_str(status));
                share_enum_fail(se, status, -nterror_to_errno(status));
                return;
        }
        if (rep->output_count == 0) {
                smb2_free_data(smb2, rep->output);
                share_enum_got_data(se, NULL, 0);
                return;
        }
        share_enum_got_data(se, rep->output, rep->output_count);
        smb2_free_data(smb2, rep->output);
}

/* [string] wchar_t * as a top-level unique pointer */
static int
se_put_string_ptr(struct se_buf *b, size_t base, uint32_t ref,
                  const char *str)
{
        struct smb2_utf16 *u;
        uint32_t i, count;

        u = smb2_utf8_to_utf16(str);
        if (u == NULL) {
                return -1;
        }
        count = (uint32_t)u->len + 1;
        if (se_put_u32(b, ref) ||
            se_put_u32(b, count) || se_put_u32(b, 0) || se_put_u32(b, count)) {
                free(u);
                return -1;
        }
        for (i = 0; i < count; i++) {
                if (se_put_u16(b, i < (uint32_t)u->len ?
                               le16toh(u->val[i]) : 0)) {
                        free(u);
                        return -1;
                }
        }
        free(u);
        return se_align(b, 4, base);
}

static int
share_enum_send_request(struct share_enum *se)
{
        struct smb2_context *smb2 = se->smb2;
        struct smb2_ioctl_request req;
        struct smb2_pdu *pdu;
        uint8_t data[1024];
        struct se_buf b;
        char *server;
        size_t stub;
        int rc;

        b.buf = data;
        b.len = 0;
        b.cap = sizeof(data);

        server = malloc(strlen(smb2->server) + 3);
        if (server == NULL) {
                return -ENOMEM;
        }
        sprintf(server, "\\\\%s", smb2->server);

        stub = DCE_RESP_HDR_LEN;
        rc = se_put_header(&b, DCE_PTYPE_REQUEST, 2) ||
                se_put_u32(&b, 0) ||            /* alloc_hint, patched */
                se_put_u16(&b, 0) ||            /* context id */
                se_put_u16(&b, SRVSVC_OPNUM_NETRSHAREENUM) ||
                /* [in,string,unique] SRVSVC_HANDLE ServerName */
                se_put_string_ptr(&b, stub, 0x00020000, server) ||
                /* [in,out] LPSHARE_ENUM_STRUCT InfoStruct: Level, switch,
                 * unique pointer to an empty container */
                se_put_u32(&b, se->level) ||
                se_put_u32(&b, se->level) ||
                se_put_u32(&b, 0x00020004) ||
                se_put_u32(&b, 0) ||            /* EntriesRead */
                se_put_u32(&b, 0) ||            /* Buffer: NULL */
                /* [in] DWORD PreferedMaximumLength */
                se_put_u32(&b, 0xffffffff) ||
                /* [in,out,unique] DWORD *ResumeHandle */
                se_put_u32(&b, 0x00020008) ||
                se_put_u32(&b, 0);
        free(server);
        if (rc) {
                return -ENOMEM;
        }
        se_set_frag_length(&b);
        b.buf[16] = (b.len - stub) & 0xff;
        b.buf[17] = ((b.len - stub) >> 8) & 0xff;

        memset(&req, 0, sizeof(req));
        req.ctl_code = SMB2_FSCTL_PIPE_TRANSCEIVE;
        memcpy(req.file_id, se->file_id, SMB2_FD_SIZE);
        req.input_count = (uint32_t)b.len;
        req.input = b.buf;
        req.flags = SMB2_0_IOCTL_IS_FSCTL;
        pdu = smb2_cmd_ioctl_async(smb2, &req, share_enum_request_cb, se);
        if (pdu == NULL) {
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);
        return 0;
}

static void
share_enum_bind_cb(struct smb2_context *smb2, int status,
                   void *command_data, void *private_data)
{
        struct share_enum *se = private_data;
        struct smb2_ioctl_reply *rep = command_data;
        const uint8_t *p;
        uint16_t sec_addr_len;
        size_t off;
        int be, rc;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "srvsvc BIND failed: %s",
                               nterror_to_str(status));
                share_enum_fail(se, status, -nterror_to_errno(status));
                return;
        }

        /*
         * BIND_ACK: header, max_xmit/recv_frag, assoc_group, secondary
         * address, padding to 4, n_results, then the results; the first
         * (only) one is for our single presentation context.
         */
        p = rep->output;
        rc = -EINVAL;
        if (rep->output_count >= DCE_HDR_LEN + 10 &&
            p[2] == DCE_PTYPE_BIND_ACK) {
                be = !(p[4] & DCE_DREP_LE);
                sec_addr_len = se_get_u16(p + 24, be);
                off = (26 + sec_addr_len + 3) & ~(size_t)3;
                if (off + 8 <= rep->output_count && p[off] >= 1 &&
                    se_get_u16(p + off + 4, be) == 0) {
                        rc = 0;
                }
        }
        smb2_free_data(smb2, rep->output);
        if (rc) {
                smb2_set_error(smb2, "srvsvc BIND was rejected");
                share_enum_fail(se, 0, rc);
                return;
        }

        rc = share_enum_send_request(se);
        if (rc) {
                smb2_set_error(smb2, "Failed to send NetrShareEnum");
                share_enum_fail(se, 0, rc);
        }
}

static int
share_enum_send_bind(struct share_enum *se)
{
        struct smb2_ioctl_request req;
        struct smb2_pdu *pdu;
        uint8_t data[128];
        struct se_buf b;

        b.buf = data;
        b.len = 0;
        b.cap = sizeof(data);
        if (se_put_header(&b, DCE_PTYPE_BIND, 1) ||
            se_put_u16(&b, 32768) ||            /* max_xmit_frag */
            se_put_u16(&b, 32768) ||            /* max_recv_frag */
            se_put_u32(&b, 0) ||                /* assoc_group_id */
            se_put_u32(&b, 1) ||                /* n_context_elem + pad */
            se_put_u16(&b, 0) ||                /* p_cont_id */
            se_put_u16(&b, 1) ||                /* n_transfer_syn + pad */
            se_put(&b, srvsvc_abstract_syntax,
                   sizeof(srvsvc_abstract_syntax)) ||
            se_put(&b, ndr32_transfer_syntax,
                   sizeof(ndr32_transfer_syntax))) {
                return -ENOMEM;
        }
        se_set_frag_length(&b);

        memset(&req, 0, sizeof(req));
        req.ctl_code = SMB2_FSCTL_PIPE_TRANSCEIVE;
        memcpy(req.file_id, se->file_id, SMB2_FD_SIZE);
        req.input_count = (uint32_t)b.len;
        req.input = b.buf;
        req.flags = SMB2_0_IOCTL_IS_FSCTL;
        pdu = smb2_cmd_ioctl_async(se->smb2, &req, share_enum_bind_cb, se);
        if (pdu == NULL) {
                return -ENOMEM;
        }
        smb2_queue_pdu(se->smb2, pdu);
        return 0;
}

static void
share_enum_open_cb(struct smb2_context *smb2, int status,
                   void *command_data, void *private_data)
{
        struct share_enum *se = private_data;
        struct smb2_create_reply *rep = command_data;
        int rc;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Failed to open pipe srvsvc: %s",
                               nterror_to_str(status));
                share_enum_fail(se, status, -nterror_to_errno(status));
                return;
        }
        memcpy(se->file_id, rep->file_id, SMB2_FD_SIZE);
        se->file_open = 1;

        rc = share_enum_send_bind(se);
        if (rc) {
                smb2_set_error(smb2, "Failed to send srvsvc BIND");
                share_enum_fail(se, 0, rc);
        }
}

int
smb2_share_enum_async(struct smb2_context *smb2,
                      enum smb2_share_info_level level,
                      smb2_command_cb cb, void *cb_data)
{
        struct smb2_create_request req;
        struct smb2_pdu *pdu;
        struct share_enum *se;

        if (level != SMB2_SHARE_INFO_0 && level != SMB2_SHARE_INFO_1 &&
            level != SMB2_SHARE_INFO_2) {
                smb2_set_error(smb2, "Unsupported share info level %d",
                               (int)level);
                return -EINVAL;
        }
        if (smb2->server == NULL) {
                smb2_set_error(smb2, "Not connected to a server");
                return -EINVAL;
        }

        se = calloc(1, sizeof(*se));
        if (se == NULL) {
                smb2_set_error(smb2, "Failed to allocate share enum state");
                return -ENOMEM;
        }
        se->smb2 = smb2;
        se->cb = cb;
        se->cb_data = cb_data;
        se->level = level;

        memset(&req, 0, sizeof(req));
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        req.desired_access = SMB2_FILE_READ_DATA |
                SMB2_FILE_WRITE_DATA |
                SMB2_FILE_APPEND_DATA |
                SMB2_FILE_READ_EA |
                SMB2_FILE_READ_ATTRIBUTES |
                SMB2_FILE_WRITE_EA |
                SMB2_FILE_WRITE_ATTRIBUTES |
                SMB2_READ_CONTROL |
                SMB2_SYNCHRONIZE;
        req.share_access = SMB2_FILE_SHARE_READ |
                SMB2_FILE_SHARE_WRITE |
                SMB2_FILE_SHARE_DELETE;
        req.create_disposition = SMB2_FILE_OPEN;
        req.name = "srvsvc";

        pdu = smb2_cmd_create_async(smb2, &req, share_enum_open_cb, se);
        if (pdu == NULL) {
                share_enum_free(se);
                smb2_set_error(smb2, "Failed to create srvsvc open");
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);
        return 0;
}
