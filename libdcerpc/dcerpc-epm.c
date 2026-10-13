/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <stdio.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif


#include <dcerpc/dcerpc.h>
#include <dcerpc/epm.h>
#include "dcerpc-private.h"

/*
 * A conformance or variance value (max_count, offset, actual_count): 32
 * bits in NDR32, 64 bits in NDR64. Values above 32 bits are rejected.
 */
static int
epm_count_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov, uint32_t *count)
{
        uint64_t v = 0;

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                v = *count;
        }
        if (ndr_uint3264_coder(name, dce, pdu, iov, &v)) {
                return -1;
        }
        if (v > UINT32_MAX) {
                return -1;
        }
        *count = (uint32_t)v;
        return 0;
}

/**********************
 * twr_t
 *
 *   unsigned32 TowerLength;
 *   [size_is(TowerLength)] byte TowerOctetString[];
 *
 * A conformant structure, so in NDR its conformance comes first: max_count
 * (= TowerLength; 32 bits in NDR32, 64 in NDR64), then TowerLength,
 * then the bytes ([C706] 14.3.7.1). YAML/JSON show TowerLength and the
 * bytes as hex.
 **********************/
int
dcerpc_epm_twr_coder(char *name, struct dcerpc_context *dce,
              struct dcerpc_pdu *pdu,
              struct dcerpc_iovec *iov,
              void *ptr)
{
        struct epm_twr_t *twr = ptr;
        uint32_t max_count = 0;
        uint32_t len = 0;
        uint32_t i;
        struct dcerpc_bytes bytes;

        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                len = twr->TowerLength;
                if (dcerpc_uint32_coder("TowerLength", dce, pdu, iov,
                                        &len)) {
                        return -1;
                }
                if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                        twr->TowerLength = len;
                }
                bytes.len = twr->TowerLength;
                bytes.data = twr->TowerOctetString;
                if (dcerpc_bytes_coder("TowerOctetString", dce, pdu, iov, &bytes)) {
                        return -1;
                }
                if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                        twr->TowerLength = bytes.len;
                        twr->TowerOctetString = bytes.data;
                }
                return 0;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                max_count = twr->TowerLength;
                len = twr->TowerLength;
        }
        if (epm_count_coder("MaxCount", dce, pdu, iov, &max_count)) {
                return -1;
        }
        if (dcerpc_uint32_coder("TowerLength", dce, pdu, iov, &len)) {
                return -1;
        }
        if (dcerpc_get_cr(pdu)) {
                return 0;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                if (len != max_count || max_count > 0x10000 || iov->offset < 0 ||
                    (uint64_t)iov->offset + max_count > iov->max_offset) {
                        return -1;
                }
                twr->TowerLength = len;
                twr->TowerOctetString = NULL;
                if (max_count) {
                        twr->TowerOctetString = dcerpc_alloc_data(pdu,
                                                                    max_count);
                        if (twr->TowerOctetString == NULL) {
                                return -1;
                        }
                }
        }
        for (i = 0; i < max_count; i++) {
                if (ndr_uint8_coder("TowerOctetString", dce, pdu, iov,
                                    &twr->TowerOctetString[i])) {
                        return -1;
                }
        }
        return 0;
}

int
dcerpc_epm_twr_struct_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov,
                     void *ptr)
{
        /* TowerLength and bytes; the hoisted max_count is not a member */
        return dcerpc_aligned_struct_coder(name, dce, pdu, iov, ptr,
                                           dcerpc_epm_twr_coder, 4, 4);
}

/**********************
 * Annotation: [string] char annotation[64]
 * Wire (MIDL/Windows): varying string — offset, actual_count, bytes
 **********************/
int
dcerpc_epm_annotation_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov,
                     void *ptr)
{
        char **ann = ptr;
        uint32_t off = 0;
        uint32_t actual = 0;
        uint32_t i;
        const char *s;
        char *out;

        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                return dcerpc_utf16z_coder(name, dce, pdu, iov, ann);
        }

        if (dcerpc_get_cr(pdu)) {
                return 0;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                s = *ann ? *ann : "";
                actual = (uint32_t)strlen(s) + 1;
                if (actual > EPM_MAX_ANNOTATION_SIZE) {
                        actual = EPM_MAX_ANNOTATION_SIZE;
                }
                if (epm_count_coder("Offset", dce, pdu, iov, &off)) {
                        return -1;
                }
                if (epm_count_coder("ActualCount", dce, pdu, iov,
                                        &actual)) {
                        return -1;
                }
                for (i = 0; i < actual; i++) {
                        uint8_t ch = (i + 1 == actual) ? 0 : (uint8_t)s[i];

                        if (ndr_uint8_coder("Annotation", dce, pdu, iov,
                                            &ch)) {
                                return -1;
                        }
                }
                return 0;
        }

        /* DECODE */
        if (epm_count_coder("Offset", dce, pdu, iov, &off)) {
                return -1;
        }
        if (epm_count_coder("ActualCount", dce, pdu, iov, &actual)) {
                return -1;
        }
        if (actual == 0) {
                *ann = NULL;
                return 0;
        }
        if (actual > EPM_MAX_ANNOTATION_SIZE || iov->offset < 0 ||
            (uint64_t)iov->offset + actual > iov->max_offset) {
                return -1;
        }
        out = dcerpc_alloc_data(pdu, actual);
        if (out == NULL) {
                return -1;
        }
        for (i = 0; i < actual; i++) {
                if (ndr_uint8_coder("Annotation", dce, pdu, iov,
                                    (uint8_t *)&out[i])) {
                        return -1;
                }
        }
        out[actual - 1] = '\0';
        *ann = out;
        return 0;
}

/**********************
 * Tower parsing helpers (C706 Appendix L encoding, little-endian counts)
 **********************/
static uint16_t
epm_get_le16(const uint8_t *p)
{
        return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint16_t
epm_get_be16(const uint8_t *p)
{
        return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/*
 * Walk floors: each floor is lhs_count(2) + lhs + rhs_count(2) + rhs
 */
static int
epm_tower_floor_at(const uint8_t *data, uint32_t len, int index,
                   const uint8_t **lhs, uint16_t *lhs_len,
                   const uint8_t **rhs, uint16_t *rhs_len)
{
        uint16_t nfloors;
        uint32_t o = 0;
        int i;

        if (len < 2) {
                return -1;
        }
        nfloors = epm_get_le16(data);
        o = 2;
        for (i = 0; i < nfloors; i++) {
                uint16_t lh, rh;

                if (o + 2 > len) {
                        return -1;
                }
                lh = epm_get_le16(data + o);
                o += 2;
                if (o + lh + 2 > len) {
                        return -1;
                }
                if (i == index) {
                        *lhs = data + o;
                        *lhs_len = lh;
                        o += lh;
                        rh = epm_get_le16(data + o);
                        o += 2;
                        if (o + rh > len) {
                                return -1;
                        }
                        *rhs = data + o;
                        *rhs_len = rh;
                        return 0;
                }
                o += lh;
                rh = epm_get_le16(data + o);
                o += 2 + rh;
        }
        return -1;
}

int
dcerpc_epm_tower_get_ncacn_np(const struct epm_twr_t *twr,
                       char **pipe_out, char **host_out)
{
        const uint8_t *lhs, *rhs;
        uint16_t lh, rh;
        char *pipe = NULL, *host = NULL;

        if (twr == NULL || twr->TowerOctetString == NULL) {
                return -1;
        }
        /* Floor 3 (0-based index 3): SMB / pipe name */
        if (epm_tower_floor_at(twr->TowerOctetString, twr->TowerLength,
                               3, &lhs, &lh, &rhs, &rh)) {
                return -1;
        }
        if (lh < 1 || (lhs[0] != EPM_PROTOCOL_SMB &&
                       lhs[0] != EPM_PROTOCOL_NAMED_PIPE)) {
                return -1;
        }
        pipe = malloc(rh ? rh : 1);
        if (pipe == NULL) {
                return -1;
        }
        if (rh) {
                memcpy(pipe, rhs, rh);
                pipe[rh - 1] = '\0';
        } else {
                pipe[0] = '\0';
        }
        /* Floor 4: NetBIOS host */
        if (epm_tower_floor_at(twr->TowerOctetString, twr->TowerLength,
                               4, &lhs, &lh, &rhs, &rh) == 0 &&
            lh >= 1 && lhs[0] == EPM_PROTOCOL_NETBIOS) {
                host = malloc(rh ? rh : 1);
                if (host == NULL) {
                        free(pipe);
                        return -1;
                }
                if (rh) {
                        memcpy(host, rhs, rh);
                        host[rh - 1] = '\0';
                } else {
                        host[0] = '\0';
                }
        }
        if (pipe_out) {
                *pipe_out = pipe;
        } else {
                free(pipe);
        }
        if (host_out) {
                *host_out = host;
        } else {
                free(host);
        }
        return 0;
}

int
dcerpc_epm_tower_get_ncacn_ip_tcp(const struct epm_twr_t *twr,
                           char **ipv4_out, uint16_t *port_out)
{
        const uint8_t *lhs, *rhs;
        uint16_t lh, rh;
        uint16_t port;
        char ipbuf[INET_ADDRSTRLEN];

        if (twr == NULL || twr->TowerOctetString == NULL) {
                return -1;
        }
        if (epm_tower_floor_at(twr->TowerOctetString, twr->TowerLength,
                               3, &lhs, &lh, &rhs, &rh)) {
                return -1;
        }
        if (lh < 1 || lhs[0] != EPM_PROTOCOL_TCP || rh < 2) {
                return -1;
        }
        port = epm_get_be16(rhs);
        if (port_out) {
                *port_out = port;
        }
        if (epm_tower_floor_at(twr->TowerOctetString, twr->TowerLength,
                               4, &lhs, &lh, &rhs, &rh)) {
                return -1;
        }
        if (lh < 1 || lhs[0] != EPM_PROTOCOL_IP || rh < 4) {
                return -1;
        }
        if (inet_ntop(AF_INET, rhs, ipbuf, sizeof(ipbuf)) == NULL) {
                return -1;
        }
        if (ipv4_out) {
                *ipv4_out = strdup(ipbuf);
                if (*ipv4_out == NULL) {
                        return -1;
                }
        }
        return 0;
}
