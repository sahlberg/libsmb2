/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

/*
 * SMB2 over SMB Direct [MS-SMBD] (Linux only).
 *
 * The transport is an RDMA reliable connection set up with librdmacm and
 * driven with libibverbs send/receive. SMBD is message based: every SMB2
 * message is split into data transfer messages no larger than what the
 * peer can receive, and flow control is done with credits, one per
 * posted receive buffer.
 *
 * To keep this out of the SMB2 code we present SMBD as a byte stream with
 * the same 4 byte length framing as Direct TCP:
 *  - smb2_rdma_writev() takes the SPL framed message that
 *    smb2_write_to_socket() hands it, drops the SPL and sends the message
 *    as one or more fragments.
 *  - received fragments are reassembled into a buffer, prefixed with an
 *    SPL, and smb2_rdma_readv() reads from that buffer, so the normal
 *    receive state machine works as is.
 *
 * The rdma_cm event channel and the completion channel are two fds, so
 * both are put in an epoll fd that becomes smb2->fd. It only ever polls
 * readable; credits and send buffers come back on completions, so pending
 * output is flushed whenever we service the fd.
 *
 * Only send/receive is used. RDMA read/write channels for SMB2 READ and
 * WRITE are not, so I/O sizes are limited by the fragmented message size.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LIBRDMACM

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

#define SMBD_VERSION               0x0100
#define SMBD_RESOLVE_TIMEOUT_MS    2000

/* What we ask for and offer */
#define SMBD_RECV_COUNT            128
#define SMBD_SEND_COUNT            32
#define SMBD_MAX_RECV_SIZE         8192
#define SMBD_PREFERRED_SEND_SIZE   8192
#define SMBD_MAX_FRAGMENTED_SIZE   (1024 * 1024)
#define SMBD_CREDITS_REQUESTED     255

#define SMBD_NEGOTIATE_REQ_SIZE    20
#define SMBD_NEGOTIATE_REP_SIZE    32
#define SMBD_DATA_HDR_SIZE         20
#define SMBD_DATA_OFFSET           24

#define SMBD_FLAG_RESPONSE_REQUESTED 0x0001

#define SMBD_WR_SEND               0x100000000ULL

enum smbd_state {
        SMBD_RESOLVING_ADDR,
        SMBD_RESOLVING_ROUTE,
        SMBD_CONNECTING,
        SMBD_NEGOTIATING,
        SMBD_CONNECTED,
        SMBD_DISCONNECTED,
};

struct smb2_rdma {
        enum smbd_state state;
        int epfd;

        struct rdma_event_channel *cm_ch;
        struct rdma_cm_id *id;
        struct ibv_pd *pd;
        struct ibv_comp_channel *comp_ch;
        struct ibv_cq *cq;
        int qp_created;

        uint8_t *recv_bufs;
        struct ibv_mr *recv_mr;
        uint8_t *send_bufs;
        struct ibv_mr *send_mr;
        int send_free[SMBD_SEND_COUNT];
        int send_free_count;

        /* from the negotiate response */
        uint32_t max_send_size;
        uint32_t max_fragmented_send_size;

        /* credits we may spend sending */
        int send_credits;
        /* receive credits the peer holds */
        int receive_credits;
        /* reposted receives not yet granted to the peer */
        int new_credits;
        int response_requested;

        /* the SMB2 message being sent, without its SPL */
        uint8_t *tx_buf;
        size_t tx_alloc, tx_len, tx_pos;

        /* reassembled SPL framed messages, read by smb2_rdma_readv() */
        uint8_t *rx_buf;
        size_t rx_alloc, rx_len, rx_pos;
        /* bytes still to come for the message being reassembled */
        uint32_t rx_remaining;
};

static void
put_le16(uint8_t *p, uint16_t v)
{
        p[0] = v & 0xff;
        p[1] = (v >> 8) & 0xff;
}

static void
put_le32(uint8_t *p, uint32_t v)
{
        p[0] = v & 0xff;
        p[1] = (v >> 8) & 0xff;
        p[2] = (v >> 16) & 0xff;
        p[3] = (v >> 24) & 0xff;
}

static uint16_t
get_le16(const uint8_t *p)
{
        return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t
get_le32(const uint8_t *p)
{
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int
set_nonblock(int fd)
{
        int v = fcntl(fd, F_GETFL, 0);

        if (v < 0) {
                return -1;
        }
        return fcntl(fd, F_SETFL, v | O_NONBLOCK);
}

static int
epoll_add(struct smb2_rdma *r, int fd)
{
        struct epoll_event ev;

        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        return epoll_ctl(r->epfd, EPOLL_CTL_ADD, fd, &ev);
}

/* Free everything except the epoll fd, which is smb2->fd */
static void
smb2_rdma_free(struct smb2_rdma *r)
{
        if (r->id && r->qp_created) {
                if (r->state == SMBD_NEGOTIATING ||
                    r->state == SMBD_CONNECTED) {
                        rdma_disconnect(r->id);
                }
                rdma_destroy_qp(r->id);
        }
        if (r->recv_mr) {
                ibv_dereg_mr(r->recv_mr);
        }
        if (r->send_mr) {
                ibv_dereg_mr(r->send_mr);
        }
        if (r->cq) {
                ibv_destroy_cq(r->cq);
        }
        if (r->comp_ch) {
                ibv_destroy_comp_channel(r->comp_ch);
        }
        if (r->pd) {
                ibv_dealloc_pd(r->pd);
        }
        if (r->id) {
                rdma_destroy_id(r->id);
        }
        if (r->cm_ch) {
                rdma_destroy_event_channel(r->cm_ch);
        }
        free(r->recv_bufs);
        free(r->send_bufs);
        free(r->tx_buf);
        free(r->rx_buf);
        free(r);
}

void
smb2_rdma_reset(struct smb2_context *smb2)
{
        if (smb2->rdma_conn == NULL) {
                return;
        }
        smb2_rdma_free(smb2->rdma_conn);
        smb2->rdma_conn = NULL;
}

static int
smb2_rdma_post_recv(struct smb2_context *smb2, int idx)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        struct ibv_sge sge;
        struct ibv_recv_wr wr, *bad;

        sge.addr = (uintptr_t)&r->recv_bufs[idx * SMBD_MAX_RECV_SIZE];
        sge.length = SMBD_MAX_RECV_SIZE;
        sge.lkey = r->recv_mr->lkey;

        memset(&wr, 0, sizeof(wr));
        wr.wr_id = (uint64_t)idx;
        wr.sg_list = &sge;
        wr.num_sge = 1;

        if (ibv_post_recv(r->id->qp, &wr, &bad) != 0) {
                smb2_set_error(smb2, "SMB Direct: ibv_post_recv failed");
                return -1;
        }
        return 0;
}

/* Send len bytes from send buffer idx */
static int
smb2_rdma_post_send(struct smb2_context *smb2, int idx, uint32_t len)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        struct ibv_sge sge;
        struct ibv_send_wr wr, *bad;

        sge.addr = (uintptr_t)&r->send_bufs[idx * SMBD_PREFERRED_SEND_SIZE];
        sge.length = len;
        sge.lkey = r->send_mr->lkey;

        memset(&wr, 0, sizeof(wr));
        wr.wr_id = SMBD_WR_SEND | (uint64_t)idx;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        wr.opcode = IBV_WR_SEND;
        wr.send_flags = IBV_SEND_SIGNALED;

        if (ibv_post_send(r->id->qp, &wr, &bad) != 0) {
                r->send_free[r->send_free_count++] = idx;
                smb2_set_error(smb2, "SMB Direct: ibv_post_send failed");
                return -1;
        }
        return 0;
}

/*
 * Send one data transfer message carrying len bytes of data (0 for a
 * message that only grants credits). The caller has checked that there
 * is a send credit and a free send buffer.
 */
static int
smb2_rdma_send_data(struct smb2_context *smb2, const uint8_t *data,
                    uint32_t len, uint32_t remaining)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        uint16_t flags = 0;
        uint8_t *buf;
        int idx;

        idx = r->send_free[--r->send_free_count];
        buf = &r->send_bufs[idx * SMBD_PREFERRED_SEND_SIZE];

        r->send_credits--;
        /* ask the peer to grant us more before we run dry */
        if (r->send_credits < 2) {
                flags |= SMBD_FLAG_RESPONSE_REQUESTED;
        }

        memset(buf, 0, SMBD_DATA_OFFSET);
        put_le16(&buf[0], SMBD_CREDITS_REQUESTED);
        put_le16(&buf[2], (uint16_t)r->new_credits);
        put_le16(&buf[4], flags);
        put_le32(&buf[8], remaining);
        put_le32(&buf[12], len ? SMBD_DATA_OFFSET : 0);
        put_le32(&buf[16], len);
        if (len) {
                memcpy(&buf[SMBD_DATA_OFFSET], data, len);
        }
        r->receive_credits += r->new_credits;
        r->new_credits = 0;
        r->response_requested = 0;

        return smb2_rdma_post_send(smb2, idx,
                                   len ? SMBD_DATA_OFFSET + len :
                                   SMBD_DATA_HDR_SIZE);
}

/*
 * The last send credit is only spent if it hands the peer credits back,
 * or the peer still has some of ours, else neither side could send.
 */
static int
smb2_rdma_can_send(struct smb2_rdma *r)
{
        if (r->state != SMBD_CONNECTED || r->send_free_count == 0 ||
            r->send_credits == 0) {
                return 0;
        }
        if (r->send_credits == 1 && r->new_credits == 0 &&
            r->receive_credits == 0) {
                return 0;
        }
        return 1;
}

/* Send as much of the pending message as credits and buffers allow */
static int
smb2_rdma_flush(struct smb2_context *smb2)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        uint32_t chunk;

        while (r->tx_pos < r->tx_len && smb2_rdma_can_send(r)) {
                chunk = r->max_send_size - SMBD_DATA_OFFSET;
                if (chunk > r->tx_len - r->tx_pos) {
                        chunk = (uint32_t)(r->tx_len - r->tx_pos);
                }
                if (smb2_rdma_send_data(smb2, &r->tx_buf[r->tx_pos], chunk,
                                        (uint32_t)(r->tx_len - r->tx_pos - chunk)) < 0) {
                        return -1;
                }
                r->tx_pos += chunk;
        }
        if (r->tx_pos == r->tx_len) {
                r->tx_pos = r->tx_len = 0;
        }

        /* Answer a keepalive / credit request, or top up the peer's
         * credits when it is running low and we have nothing to send. */
        if (r->tx_len == 0 && smb2_rdma_can_send(r) &&
            (r->response_requested ||
             (r->new_credits > 0 &&
              r->receive_credits <= SMBD_RECV_COUNT / 4))) {
                if (smb2_rdma_send_data(smb2, NULL, 0, 0) < 0) {
                        return -1;
                }
        }
        return 0;
}

static int
smb2_rdma_rx_append(struct smb2_context *smb2, const uint8_t *data,
                    size_t len)
{
        struct smb2_rdma *r = smb2->rdma_conn;

        if (r->rx_pos == r->rx_len) {
                r->rx_pos = r->rx_len = 0;
        } else if (r->rx_pos > 0 && r->rx_len + len > r->rx_alloc) {
                memmove(r->rx_buf, &r->rx_buf[r->rx_pos],
                        r->rx_len - r->rx_pos);
                r->rx_len -= r->rx_pos;
                r->rx_pos = 0;
        }
        if (r->rx_len + len > r->rx_alloc) {
                size_t n = r->rx_alloc ? r->rx_alloc : 65536;
                uint8_t *p;

                while (n < r->rx_len + len) {
                        n *= 2;
                }
                p = realloc(r->rx_buf, n);
                if (p == NULL) {
                        smb2_set_error(smb2, "SMB Direct: out of memory");
                        return -1;
                }
                r->rx_buf = p;
                r->rx_alloc = n;
        }
        memcpy(&r->rx_buf[r->rx_len], data, len);
        r->rx_len += len;
        return 0;
}

static int
smb2_rdma_negotiate_rep(struct smb2_context *smb2, const uint8_t *buf,
                        uint32_t len)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        uint32_t status, max_recv, max_frag, pref_send;

        if (len < SMBD_NEGOTIATE_REP_SIZE) {
                smb2_set_error(smb2, "SMB Direct: short negotiate "
                               "response (%u bytes)", len);
                return -1;
        }
        status = get_le32(&buf[12]);
        if (status != 0) {
                smb2_set_error(smb2, "SMB Direct: negotiate failed, "
                               "status 0x%08x", status);
                return -1;
        }
        if (get_le16(&buf[4]) != SMBD_VERSION) {
                smb2_set_error(smb2, "SMB Direct: server negotiated "
                               "unsupported version 0x%04x",
                               get_le16(&buf[4]));
                return -1;
        }
        pref_send = get_le32(&buf[20]);
        max_recv = get_le32(&buf[24]);
        max_frag = get_le32(&buf[28]);
        if (pref_send > SMBD_MAX_RECV_SIZE ||
            max_recv <= SMBD_DATA_OFFSET || max_frag < 131072) {
                smb2_set_error(smb2, "SMB Direct: invalid negotiate "
                               "response sizes send:%u recv:%u frag:%u",
                               pref_send, max_recv, max_frag);
                return -1;
        }
        r->max_send_size = max_recv < SMBD_PREFERRED_SEND_SIZE ?
                max_recv : SMBD_PREFERRED_SEND_SIZE;
        r->max_fragmented_send_size = max_frag;
        r->send_credits = get_le16(&buf[10]);
        if (r->send_credits == 0) {
                smb2_set_error(smb2, "SMB Direct: server granted no "
                               "credits");
                return -1;
        }
        r->state = SMBD_CONNECTED;
        return 0;
}

static int
smb2_rdma_data_rep(struct smb2_context *smb2, const uint8_t *buf,
                   uint32_t len)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        uint32_t remaining, offset, data_len;
        uint8_t spl[4];

        if (len < SMBD_DATA_HDR_SIZE) {
                smb2_set_error(smb2, "SMB Direct: short data transfer "
                               "message (%u bytes)", len);
                return -1;
        }
        r->receive_credits--;
        r->send_credits += get_le16(&buf[2]);
        if (get_le16(&buf[4]) & SMBD_FLAG_RESPONSE_REQUESTED) {
                r->response_requested = 1;
        }
        remaining = get_le32(&buf[8]);
        offset = get_le32(&buf[12]);
        data_len = get_le32(&buf[16]);
        if (data_len == 0) {
                return 0;
        }
        if (offset < SMBD_DATA_HDR_SIZE || offset > len ||
            data_len > len - offset) {
                smb2_set_error(smb2, "SMB Direct: invalid data transfer "
                               "message offset:%u length:%u size:%u",
                               offset, data_len, len);
                return -1;
        }

        if (r->rx_remaining == 0) {
                /* first fragment of a new message */
                if ((uint64_t)data_len + remaining >
                    SMBD_MAX_FRAGMENTED_SIZE) {
                        smb2_set_error(smb2, "SMB Direct: message too "
                                       "large (%u bytes)",
                                       data_len + remaining);
                        return -1;
                }
                r->rx_remaining = data_len + remaining;
                spl[0] = (r->rx_remaining >> 24) & 0xff;
                spl[1] = (r->rx_remaining >> 16) & 0xff;
                spl[2] = (r->rx_remaining >> 8) & 0xff;
                spl[3] = r->rx_remaining & 0xff;
                if (smb2_rdma_rx_append(smb2, spl, 4) < 0) {
                        return -1;
                }
        }
        if (data_len > r->rx_remaining ||
            r->rx_remaining - data_len != remaining) {
                smb2_set_error(smb2, "SMB Direct: inconsistent fragment, "
                               "expected %u more bytes, got %u + %u",
                               r->rx_remaining, data_len, remaining);
                return -1;
        }
        r->rx_remaining -= data_len;
        return smb2_rdma_rx_append(smb2, &buf[offset], data_len);
}

/* Returns 1 if the SMBD negotiate completed, 0, or -1 on error */
static int
smb2_rdma_poll_cq(struct smb2_context *smb2)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        struct ibv_wc wc[16];
        struct ibv_cq *ev_cq;
        void *ev_ctx;
        int i, n, idx, ret = 0;

        if (r->cq == NULL) {
                return 0;
        }
        while (ibv_get_cq_event(r->comp_ch, &ev_cq, &ev_ctx) == 0) {
                ibv_ack_cq_events(ev_cq, 1);
        }
        if (ibv_req_notify_cq(r->cq, 0) != 0) {
                smb2_set_error(smb2, "SMB Direct: ibv_req_notify_cq "
                               "failed");
                return -1;
        }

        while ((n = ibv_poll_cq(r->cq, 16, wc)) > 0) {
                for (i = 0; i < n; i++) {
                        if (wc[i].status != IBV_WC_SUCCESS) {
                                smb2_set_error(smb2, "SMB Direct: %s "
                                               "failed: %s",
                                               (wc[i].wr_id & SMBD_WR_SEND) ?
                                               "send" : "receive",
                                               ibv_wc_status_str(wc[i].status));
                                return -1;
                        }
                        idx = (int)(wc[i].wr_id & 0xffffffff);
                        if (wc[i].wr_id & SMBD_WR_SEND) {
                                r->send_free[r->send_free_count++] = idx;
                                continue;
                        }

                        if (r->state == SMBD_NEGOTIATING) {
                                if (smb2_rdma_negotiate_rep(smb2,
                                        &r->recv_bufs[idx * SMBD_MAX_RECV_SIZE],
                                        wc[i].byte_len) < 0) {
                                        return -1;
                                }
                                if (smb2_rdma_post_recv(smb2, idx) < 0) {
                                        return -1;
                                }
                                /* the negotiate itself carries no
                                 * credits, so grant every posted receive
                                 * with the first message we send */
                                r->new_credits = SMBD_RECV_COUNT;
                                ret = 1;
                                continue;
                        } else if (smb2_rdma_data_rep(smb2,
                                        &r->recv_bufs[idx * SMBD_MAX_RECV_SIZE],
                                        wc[i].byte_len) < 0) {
                                return -1;
                        }
                        if (smb2_rdma_post_recv(smb2, idx) < 0) {
                                return -1;
                        }
                        r->new_credits++;
                }
        }
        if (n < 0) {
                smb2_set_error(smb2, "SMB Direct: ibv_poll_cq failed");
                return -1;
        }
        return ret;
}

static int
smb2_rdma_setup_qp(struct smb2_context *smb2)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        struct ibv_qp_init_attr attr;
        int i;

        r->pd = ibv_alloc_pd(r->id->verbs);
        if (r->pd == NULL) {
                smb2_set_error(smb2, "SMB Direct: ibv_alloc_pd failed");
                return -1;
        }
        r->comp_ch = ibv_create_comp_channel(r->id->verbs);
        if (r->comp_ch == NULL) {
                smb2_set_error(smb2, "SMB Direct: "
                               "ibv_create_comp_channel failed");
                return -1;
        }
        if (set_nonblock(r->comp_ch->fd) < 0 ||
            epoll_add(r, r->comp_ch->fd) < 0) {
                smb2_set_error(smb2, "SMB Direct: failed to set up the "
                               "completion channel: %s", strerror(errno));
                return -1;
        }
        r->cq = ibv_create_cq(r->id->verbs,
                              SMBD_RECV_COUNT + SMBD_SEND_COUNT, NULL,
                              r->comp_ch, 0);
        if (r->cq == NULL) {
                smb2_set_error(smb2, "SMB Direct: ibv_create_cq failed");
                return -1;
        }
        if (ibv_req_notify_cq(r->cq, 0) != 0) {
                smb2_set_error(smb2, "SMB Direct: ibv_req_notify_cq "
                               "failed");
                return -1;
        }

        memset(&attr, 0, sizeof(attr));
        attr.send_cq = r->cq;
        attr.recv_cq = r->cq;
        attr.qp_type = IBV_QPT_RC;
        attr.cap.max_send_wr = SMBD_SEND_COUNT;
        attr.cap.max_recv_wr = SMBD_RECV_COUNT;
        attr.cap.max_send_sge = 1;
        attr.cap.max_recv_sge = 1;
        if (rdma_create_qp(r->id, r->pd, &attr) != 0) {
                smb2_set_error(smb2, "SMB Direct: rdma_create_qp failed: "
                               "%s", strerror(errno));
                return -1;
        }
        r->qp_created = 1;

        r->recv_bufs = malloc(SMBD_RECV_COUNT * SMBD_MAX_RECV_SIZE);
        r->send_bufs = malloc(SMBD_SEND_COUNT * SMBD_PREFERRED_SEND_SIZE);
        if (r->recv_bufs == NULL || r->send_bufs == NULL) {
                smb2_set_error(smb2, "SMB Direct: out of memory");
                return -1;
        }
        r->recv_mr = ibv_reg_mr(r->pd, r->recv_bufs,
                                SMBD_RECV_COUNT * SMBD_MAX_RECV_SIZE,
                                IBV_ACCESS_LOCAL_WRITE);
        r->send_mr = ibv_reg_mr(r->pd, r->send_bufs,
                                SMBD_SEND_COUNT * SMBD_PREFERRED_SEND_SIZE,
                                IBV_ACCESS_LOCAL_WRITE);
        if (r->recv_mr == NULL || r->send_mr == NULL) {
                smb2_set_error(smb2, "SMB Direct: ibv_reg_mr failed: %s",
                               strerror(errno));
                return -1;
        }
        for (i = 0; i < SMBD_SEND_COUNT; i++) {
                r->send_free[i] = i;
        }
        r->send_free_count = SMBD_SEND_COUNT;

        /* the negotiate response needs a posted receive */
        for (i = 0; i < SMBD_RECV_COUNT; i++) {
                if (smb2_rdma_post_recv(smb2, i) < 0) {
                        return -1;
                }
        }
        return 0;
}

static int
smb2_rdma_send_negotiate(struct smb2_context *smb2)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        uint8_t *buf;
        int idx;

        idx = r->send_free[--r->send_free_count];
        buf = &r->send_bufs[idx * SMBD_PREFERRED_SEND_SIZE];

        memset(buf, 0, SMBD_NEGOTIATE_REQ_SIZE);
        put_le16(&buf[0], SMBD_VERSION);
        put_le16(&buf[2], SMBD_VERSION);
        put_le16(&buf[6], SMBD_CREDITS_REQUESTED);
        put_le32(&buf[8], SMBD_PREFERRED_SEND_SIZE);
        put_le32(&buf[12], SMBD_MAX_RECV_SIZE);
        put_le32(&buf[16], SMBD_MAX_FRAGMENTED_SIZE);

        return smb2_rdma_post_send(smb2, idx, SMBD_NEGOTIATE_REQ_SIZE);
}

static int
smb2_rdma_cm_events(struct smb2_context *smb2)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        struct rdma_cm_event *ev;
        struct rdma_conn_param param;
        enum rdma_cm_event_type type;
        int status;

        while (rdma_get_cm_event(r->cm_ch, &ev) == 0) {
                type = ev->event;
                status = ev->status;
                rdma_ack_cm_event(ev);

                switch (type) {
                case RDMA_CM_EVENT_ADDR_RESOLVED:
                        r->state = SMBD_RESOLVING_ROUTE;
                        if (rdma_resolve_route(r->id,
                                               SMBD_RESOLVE_TIMEOUT_MS) != 0) {
                                smb2_set_error(smb2, "SMB Direct: "
                                               "rdma_resolve_route failed: "
                                               "%s", strerror(errno));
                                return -1;
                        }
                        break;
                case RDMA_CM_EVENT_ROUTE_RESOLVED:
                        if (smb2_rdma_setup_qp(smb2) < 0) {
                                return -1;
                        }
                        memset(&param, 0, sizeof(param));
                        param.retry_count = 6;
                        param.rnr_retry_count = 0;
                        r->state = SMBD_CONNECTING;
                        if (rdma_connect(r->id, &param) != 0) {
                                smb2_set_error(smb2, "SMB Direct: "
                                               "rdma_connect failed: %s",
                                               strerror(errno));
                                return -1;
                        }
                        break;
                case RDMA_CM_EVENT_ESTABLISHED:
                        r->state = SMBD_NEGOTIATING;
                        if (smb2_rdma_send_negotiate(smb2) < 0) {
                                return -1;
                        }
                        break;
                case RDMA_CM_EVENT_ADDR_ERROR:
                        smb2_set_error(smb2, "SMB Direct: could not "
                                       "resolve the address to an RDMA "
                                       "device (%s), is there an RDMA "
                                       "link on this interface?",
                                       strerror(-status));
                        return -1;
                case RDMA_CM_EVENT_ROUTE_ERROR:
                        smb2_set_error(smb2, "SMB Direct: route "
                                       "resolution failed (%s)",
                                       strerror(-status));
                        return -1;
                case RDMA_CM_EVENT_REJECTED:
                        smb2_set_error(smb2, "SMB Direct: connection "
                                       "rejected, no SMB Direct server "
                                       "listening?");
                        return -1;
                case RDMA_CM_EVENT_CONNECT_ERROR:
                case RDMA_CM_EVENT_UNREACHABLE:
                        smb2_set_error(smb2, "SMB Direct: connect failed "
                                       "(%s)", strerror(-status));
                        return -1;
                case RDMA_CM_EVENT_DISCONNECTED:
                        r->state = SMBD_DISCONNECTED;
                        smb2_set_error(smb2, "SMB Direct: connection "
                                       "closed by the server");
                        return -1;
                case RDMA_CM_EVENT_DEVICE_REMOVAL:
                        r->state = SMBD_DISCONNECTED;
                        smb2_set_error(smb2, "SMB Direct: RDMA device "
                                       "removed");
                        return -1;
                default:
                        break;
                }
        }
        return 0;
}

int
smb2_rdma_connect(struct smb2_context *smb2, const struct addrinfo *ai)
{
        struct smb2_rdma *r;

        r = calloc(1, sizeof(*r));
        if (r == NULL) {
                smb2_set_error(smb2, "SMB Direct: out of memory");
                return -ENOMEM;
        }
        smb2->rdma_conn = r;
        r->state = SMBD_RESOLVING_ADDR;

        r->epfd = epoll_create1(EPOLL_CLOEXEC);
        if (r->epfd < 0) {
                smb2_set_error(smb2, "SMB Direct: epoll_create1 failed: "
                               "%s", strerror(errno));
                goto failed;
        }
        r->cm_ch = rdma_create_event_channel();
        if (r->cm_ch == NULL) {
                smb2_set_error(smb2, "SMB Direct: failed to create the "
                               "rdma_cm event channel: %s, is rdma_ucm "
                               "loaded?", strerror(errno));
                goto failed;
        }
        if (set_nonblock(r->cm_ch->fd) < 0 ||
            epoll_add(r, r->cm_ch->fd) < 0) {
                smb2_set_error(smb2, "SMB Direct: failed to set up the "
                               "rdma_cm event channel: %s",
                               strerror(errno));
                goto failed;
        }
        if (rdma_create_id(r->cm_ch, &r->id, NULL, RDMA_PS_TCP) != 0) {
                smb2_set_error(smb2, "SMB Direct: rdma_create_id failed: "
                               "%s", strerror(errno));
                goto failed;
        }
        if (rdma_resolve_addr(r->id, NULL, ai->ai_addr,
                              SMBD_RESOLVE_TIMEOUT_MS) != 0) {
                smb2_set_error(smb2, "SMB Direct: rdma_resolve_addr "
                               "failed: %s", strerror(errno));
                goto failed;
        }

        smb2->fd = r->epfd;
        if (smb2->change_fd) {
                smb2->change_fd(smb2, smb2->fd, SMB2_ADD_FD);
        }
        smb2_change_events(smb2, smb2->fd, POLLIN);
        return 0;

 failed:
        if (r->epfd >= 0) {
                close(r->epfd);
        }
        smb2_rdma_reset(smb2);
        return -EIO;
}

int
smb2_rdma_connected(struct smb2_context *smb2)
{
        return smb2->rdma_conn != NULL &&
                smb2->rdma_conn->state == SMBD_CONNECTED;
}

int
smb2_rdma_service(struct smb2_context *smb2)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        int ret;

        if (r == NULL) {
                smb2_set_error(smb2, "SMB Direct: not connected");
                return -1;
        }
        if (smb2_rdma_cm_events(smb2) < 0) {
                return -1;
        }
        ret = smb2_rdma_poll_cq(smb2);
        if (ret < 0) {
                return -1;
        }
        if (smb2_rdma_flush(smb2) < 0) {
                return -1;
        }
        return ret;
}

int
smb2_rdma_flush_output(struct smb2_context *smb2)
{
        if (!smb2_rdma_connected(smb2)) {
                return 0;
        }
        return smb2_rdma_flush(smb2);
}

ssize_t
smb2_rdma_writev(struct smb2_context *smb2, const struct iovec *iov,
                 int iovcnt)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        size_t total = 0;
        uint32_t spl;
        int i;

        if (!smb2_rdma_connected(smb2)) {
                errno = EPIPE;
                return -1;
        }
        /* one message at a time */
        if (r->tx_len) {
                if (smb2_rdma_flush(smb2) < 0) {
                        errno = EIO;
                        return -1;
                }
                if (r->tx_len) {
                        errno = EAGAIN;
                        return -1;
                }
        }

        for (i = 0; i < iovcnt; i++) {
                total += iov[i].iov_len;
        }
        /* smb2_write_to_socket() hands us the rest of the message
         * including the SPL, and we always take all of it, so this is
         * always a whole message. */
        if (total < 4 || iov[0].iov_len < 4) {
                errno = EINVAL;
                return -1;
        }
        spl = ((uint32_t)((uint8_t *)iov[0].iov_base)[0] << 24) |
                ((uint32_t)((uint8_t *)iov[0].iov_base)[1] << 16) |
                ((uint32_t)((uint8_t *)iov[0].iov_base)[2] << 8) |
                ((uint8_t *)iov[0].iov_base)[3];
        if (spl != total - 4) {
                errno = EINVAL;
                return -1;
        }
        if (spl > r->max_fragmented_send_size) {
                smb2_set_error(smb2, "SMB Direct: message of %u bytes is "
                               "larger than the server accepts (%u)",
                               spl, r->max_fragmented_send_size);
                errno = EMSGSIZE;
                return -1;
        }

        if (spl > r->tx_alloc) {
                uint8_t *p = realloc(r->tx_buf, spl);

                if (p == NULL) {
                        errno = ENOMEM;
                        return -1;
                }
                r->tx_buf = p;
                r->tx_alloc = spl;
        }
        memcpy(r->tx_buf, (uint8_t *)iov[0].iov_base + 4,
               iov[0].iov_len - 4);
        r->tx_len = iov[0].iov_len - 4;
        for (i = 1; i < iovcnt; i++) {
                memcpy(&r->tx_buf[r->tx_len], iov[i].iov_base,
                       iov[i].iov_len);
                r->tx_len += iov[i].iov_len;
        }
        r->tx_pos = 0;

        if (smb2_rdma_flush(smb2) < 0) {
                errno = EIO;
                return -1;
        }
        return (ssize_t)total;
}

ssize_t
smb2_rdma_readv(struct smb2_context *smb2, const struct iovec *iov,
                int iovcnt)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        size_t len;
        ssize_t count = 0;
        int i;

        if (r == NULL) {
                return 0;
        }
        if (r->rx_pos == r->rx_len) {
                errno = EAGAIN;
                return -1;
        }
        for (i = 0; i < iovcnt && r->rx_pos < r->rx_len; i++) {
                len = iov[i].iov_len;
                if (len > r->rx_len - r->rx_pos) {
                        len = r->rx_len - r->rx_pos;
                }
                memcpy(iov[i].iov_base, &r->rx_buf[r->rx_pos], len);
                r->rx_pos += len;
                count += (ssize_t)len;
        }
        return count;
}

/*
 * Without RDMA read/write channels a READ reply or WRITE request has to
 * fit in one fragmented message, so keep I/O below that, in whole 64k
 * credits.
 */
void
smb2_rdma_cap_io_sizes(struct smb2_context *smb2)
{
        struct smb2_rdma *r = smb2->rdma_conn;
        uint32_t recv_max, send_max;

        if (r == NULL) {
                return;
        }
        recv_max = (SMBD_MAX_FRAGMENTED_SIZE - 1024) & ~0xffffU;
        send_max = (r->max_fragmented_send_size - 1024) & ~0xffffU;
        if (smb2->max_read_size > recv_max) {
                smb2->max_read_size = recv_max;
        }
        if (smb2->max_transact_size > recv_max) {
                smb2->max_transact_size = recv_max;
        }
        if (smb2->max_write_size > send_max) {
                smb2->max_write_size = send_max;
        }
}

#endif /* HAVE_LIBRDMACM */
