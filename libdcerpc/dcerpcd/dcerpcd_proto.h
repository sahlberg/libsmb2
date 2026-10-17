/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Named-pipe proxy framing between dcerpcd and external services, used
 * after the registration (see external.c).
 *
 * dcerpcd is only the SMB2 end of the pipe: it forwards what a client
 * writes to the pipe to the service, and queues what the service sends
 * back for the client to read. Everything DCE/RPC (BIND, auth, fragments,
 * the interfaces served on the pipe) is up to the service.
 *
 * Every message, in both directions:
 *   uint8_t  magic[4];   "DCEP"
 *   uint32_t type;       DCERPCD_MSG_*
 *   uint32_t pipe_id;    chosen by dcerpcd at OPEN
 *   uint32_t len;        payload length, at most DCERPCD_MSG_MAX
 *   uint8_t  payload[len];
 * Integers are little-endian.
 *
 * dcerpcd -> service
 *   OPEN    a client opened the pipe; the payload is
 *             uint32_t session_id;  dcerpcd's SMB session
 *             int32_t  uid;         local uid, or DCERPCD_UID_GUEST
 *             char     user[];      local user name, the rest of the
 *                                   payload, not NUL terminated
 *   WRITE   bytes the client wrote (a WRITE, or a TRANSCEIVE's input)
 *   CLOSE   the client closed the pipe; no payload
 * service -> dcerpcd
 *   OUTPUT  one pipe message (a DCE/RPC fragment) for the client to read
 *   CLOSE   the service closed the pipe; the client's I/O on it fails
 *           with STATUS_PIPE_BROKEN from now on; no payload
 *
 * A message for a pipe_id the receiver does not know (it was closed by
 * the other end meanwhile) is ignored.
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

#define DCERPCD_MSG_MAGIC     "DCEP"
#define DCERPCD_MSG_HDR_SIZE  16
#define DCERPCD_MSG_MAX       (16 * 1024 * 1024)

#define DCERPCD_MSG_OPEN      1
#define DCERPCD_MSG_WRITE     2
#define DCERPCD_MSG_OUTPUT    3
#define DCERPCD_MSG_CLOSE     4

/* OPEN: the uid of a guest session */
#define DCERPCD_UID_GUEST     ((int32_t)-1)
/* OPEN: the fixed part of the payload, before the user name */
#define DCERPCD_OPEN_SIZE     8

struct dcerpcd_msg_hdr {
        uint32_t type;
        uint32_t pipe_id;
        uint32_t len;
};

static inline void
dcerpcd_put_le32(uint8_t *p, uint32_t v)
{
        p[0] = (uint8_t)v;
        p[1] = (uint8_t)(v >> 8);
        p[2] = (uint8_t)(v >> 16);
        p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t
dcerpcd_get_le32(const uint8_t *p)
{
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void
dcerpcd_msg_hdr_encode(uint8_t *buf, uint32_t type, uint32_t pipe_id,
                       uint32_t len)
{
        buf[0] = DCERPCD_MSG_MAGIC[0];
        buf[1] = DCERPCD_MSG_MAGIC[1];
        buf[2] = DCERPCD_MSG_MAGIC[2];
        buf[3] = DCERPCD_MSG_MAGIC[3];
        dcerpcd_put_le32(buf + 4, type);
        dcerpcd_put_le32(buf + 8, pipe_id);
        dcerpcd_put_le32(buf + 12, len);
}

/* Returns 0, or -1 if buf is not a message header */
static inline int
dcerpcd_msg_hdr_decode(const uint8_t *buf, struct dcerpcd_msg_hdr *hdr)
{
        if (buf[0] != DCERPCD_MSG_MAGIC[0] || buf[1] != DCERPCD_MSG_MAGIC[1] ||
            buf[2] != DCERPCD_MSG_MAGIC[2] || buf[3] != DCERPCD_MSG_MAGIC[3]) {
                return -1;
        }
        hdr->type = dcerpcd_get_le32(buf + 4);
        hdr->pipe_id = dcerpcd_get_le32(buf + 8);
        hdr->len = dcerpcd_get_le32(buf + 12);
        return hdr->len > DCERPCD_MSG_MAX ? -1 : 0;
}

#ifdef __cplusplus
}
#endif

#endif /* !_DCERPCD_PROTO_H_ */
