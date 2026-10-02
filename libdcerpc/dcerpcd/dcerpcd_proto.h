/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Control-channel RPC proxy framing between dcerpcd and external services.
 * Layout (all multi-byte integers little-endian):
 *   struct dcerpcd_rpc_hdr hdr;   // exactly 64 bytes
 *   uint32_t               ndr_len;
 *   uint8_t                ndr[ndr_len];
 *   uint8_t                pad[0..3];   // pad so (4 + ndr_len + pad) % 4 == 0
 * Request (dcerpcd → worker):
 *   hdr.uid_or_status = POSIX uid, or DCERPCD_RPC_UID_GUEST (-1)
 *   hdr.session_id    = dcerpcd SMB client session id
 *   hdr.msgid         = id for matching the reply (per dcerpcd process)
 *   hdr.opnum         = DCERPC operation number
 *   ndr               = request stub
 * Response (worker → dcerpcd):
 *   hdr.uid_or_status = status (DCERPCD_RPC_STATUS_OK / _FAIL / …)
 *   hdr.session_id    = same session_id as the request
 *   hdr.msgid         = same id as the request
 *   hdr.opnum         = same opnum as the request
 *   ndr_len           = 0 on failure; NDR reply length on success (later)
 *   ndr               = empty when status != OK
 *
 * Replies are matched on (session_id, msgid) so concurrent SMB sessions
 * can share the worker connection without confusing correlation ids.
 *
 */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _DCERPCD_PROTO_H_
#define _DCERPCD_PROTO_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ASCII magic at the start of every RPC proxy message */
#define DCERPCD_RPC_MAGIC0  'D'
#define DCERPCD_RPC_MAGIC1  'C'
#define DCERPCD_RPC_MAGIC2  'E'
#define DCERPCD_RPC_MAGIC3  'R'

#define DCERPCD_RPC_HDR_SIZE  64

/* Request: guest / nobody uid */
#define DCERPCD_RPC_UID_GUEST   ((int32_t)-1)

/* Response status codes (stored in uid_or_status) */
#define DCERPCD_RPC_STATUS_OK   0
#define DCERPCD_RPC_STATUS_FAIL 1

/*
 * 64-byte header.
 *
 * uid_or_status:
 *   Request  — caller uid or DCERPCD_RPC_UID_GUEST
 *   Response — DCERPCD_RPC_STATUS_OK / DCERPCD_RPC_STATUS_FAIL / …
 * session_id:
 *   dcerpcd client session id (echoed on the response)
 * msgid:
 *   correlation id (echoed on the response; unique together with session_id)
 */
struct dcerpcd_rpc_hdr {
        char     magic[4];       /* "DCER" */
        int32_t  uid_or_status;
        uint32_t session_id;     /* immediately before msgid */
        uint32_t msgid;
        uint32_t opnum;
        uint8_t  reserved[44];   /* must be zero; total sizeof == 64 */
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct dcerpcd_rpc_hdr) == DCERPCD_RPC_HDR_SIZE,
               "dcerpcd_rpc_hdr must be 64 bytes");
#endif

static inline int
dcerpcd_rpc_hdr_ok(const struct dcerpcd_rpc_hdr *h)
{
        return h != NULL &&
               h->magic[0] == DCERPCD_RPC_MAGIC0 &&
               h->magic[1] == DCERPCD_RPC_MAGIC1 &&
               h->magic[2] == DCERPCD_RPC_MAGIC2 &&
               h->magic[3] == DCERPCD_RPC_MAGIC3;
}

/* Bytes of zero pad so (4 + ndr_len + pad) is a multiple of 4. */
static inline unsigned
dcerpcd_rpc_ndr_pad(uint32_t ndr_len)
{
        return (4u - (ndr_len & 3u)) & 3u;
}

#ifdef __cplusplus
}
#endif

#endif /* !_DCERPCD_PROTO_H_ */
