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
 * SMB2 over QUIC (Linux only).
 *
 * The transport is the kernel QUIC module (IPPROTO_QUIC sockets). The
 * kernel does not do the TLS 1.3 handshake itself, so we drive it from
 * here with libquic's non-blocking step API on top of a gnutls session.
 * Once the handshake is done the socket carries a single bidirectional
 * stream with the same 4 byte length framing as Direct TCP, so readv()
 * works as is. Only sends need a cmsg naming the stream.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LIBQUIC

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/quic.h>

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

#define SMB2_QUIC_ALPN   "smb"
#define SMB2_QUIC_STREAM 0

struct smb2_quic_handshake {
        gnutls_certificate_credentials_t cred;
        gnutls_session_t session;
        struct quic_handshake_step *step;
        int events;
};

static void
smb2_quic_handshake_free(struct smb2_context *smb2)
{
        struct smb2_quic_handshake *hs = smb2->quic_hs;

        if (hs == NULL) {
                return;
        }
        if (hs->session) {
                quic_handshake_deinit(hs->session);
                gnutls_deinit(hs->session);
        }
        if (hs->cred) {
                gnutls_certificate_free_credentials(hs->cred);
        }
        free(hs);
        smb2->quic_hs = NULL;
}

void
smb2_quic_reset(struct smb2_context *smb2)
{
        smb2_quic_handshake_free(smb2);
        smb2->quic_stream_open = 0;
}

/* SNI is the DNS name from "host[:port]", IP literals are not sent */
static int
smb2_quic_set_server_name(struct smb2_context *smb2, gnutls_session_t session)
{
        unsigned char buf[sizeof(struct in6_addr)];
        char *host, *port;
        int ret = 0;

        if (smb2->server == NULL || smb2->server[0] == '[') {
                return 0;
        }
        host = strdup(smb2->server);
        if (host == NULL) {
                return GNUTLS_E_MEMORY_ERROR;
        }
        port = strchr(host, ':');
        if (port) {
                *port = 0;
        }
        if (inet_pton(AF_INET, host, buf) != 1) {
                ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS,
                                             host, strlen(host));
        }
        free(host);
        return ret;
}

/*
 * Called once the QUIC socket is connected. Returns 0 while the
 * handshake is in progress, 1 when it has completed and -1 on error.
 */
int
smb2_quic_handshake_start(struct smb2_context *smb2)
{
        struct smb2_quic_handshake *hs;
        int ret;

        hs = calloc(1, sizeof(*hs));
        if (hs == NULL) {
                smb2_set_error(smb2, "Failed to allocate QUIC handshake");
                return -1;
        }
        smb2->quic_hs = hs;

        /* The server certificate is not verified, same as libquic's own
         * quic_client_handshake(). SMB authentication, signing and
         * sealing still run on top. */
        ret = gnutls_certificate_allocate_credentials(&hs->cred);
        if (ret) {
                goto err;
        }
        ret = gnutls_init(&hs->session, GNUTLS_CLIENT);
        if (ret) {
                goto err;
        }
        ret = gnutls_credentials_set(hs->session, GNUTLS_CRD_CERTIFICATE,
                                     hs->cred);
        if (ret) {
                goto err;
        }
        ret = gnutls_priority_set_direct(hs->session, QUIC_PRIORITY, NULL);
        if (ret) {
                goto err;
        }
        ret = quic_session_set_alpn(hs->session, SMB2_QUIC_ALPN,
                                    strlen(SMB2_QUIC_ALPN));
        if (ret) {
                goto err;
        }
        ret = smb2_quic_set_server_name(smb2, hs->session);
        if (ret) {
                goto err;
        }
        gnutls_transport_set_int(hs->session, smb2->fd);

        ret = quic_handshake_init(hs->session, &hs->step);
        if (ret) {
                goto err;
        }

        return smb2_quic_handshake_service(smb2);

 err:
        smb2_set_error(smb2, "QUIC handshake setup failed: %d", ret);
        smb2_quic_handshake_free(smb2);
        return -1;
}

/*
 * Run handshake steps until the socket would block. Returns 0 while the
 * handshake is in progress, 1 when it has completed and -1 on error.
 */
int
smb2_quic_handshake_service(struct smb2_context *smb2)
{
        struct smb2_quic_handshake *hs = smb2->quic_hs;
        int ret;

        while (hs->step != NULL) {
                struct quic_handshake_step *step = hs->step;
                ssize_t count;

                if (step->op == QUIC_HANDSHAKE_STEP_OP_RECVMSG) {
                        count = recvmsg(smb2->fd, step->s_recvmsg.msg,
                                        step->s_recvmsg.flags);
                        hs->events = POLLIN;
                } else {
                        count = sendmsg(smb2->fd, step->s_sendmsg.msg,
                                        step->s_sendmsg.flags | MSG_NOSIGNAL);
                        hs->events = POLLOUT;
                }
                if (count == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                return 0;
                        }
                        if (errno == EINTR) {
                                continue;
                        }
                        count = -errno;
                }
                if (step->op == QUIC_HANDSHAKE_STEP_OP_RECVMSG) {
                        step->s_recvmsg.retval = count;
                } else {
                        step->s_sendmsg.retval = count;
                }

                ret = quic_handshake_step(hs->session, &hs->step);
                if (ret) {
                        smb2_set_error(smb2, "QUIC handshake failed: %d",
                                       ret);
                        smb2_quic_handshake_free(smb2);
                        return -1;
                }
        }

        /* The keys now live in the kernel, the TLS session is done. */
        smb2_quic_handshake_free(smb2);
        return 1;
}

int
smb2_quic_events(struct smb2_context *smb2)
{
        return smb2->quic_hs->events;
}

ssize_t
smb2_quic_writev(struct smb2_context *smb2,
                 const struct iovec *iov, int iovcnt)
{
        char cbuf[CMSG_SPACE(sizeof(struct quic_stream_info))];
        struct quic_stream_info *info;
        struct cmsghdr *cmsg;
        struct msghdr msg;
        ssize_t count;

        memset(cbuf, 0, sizeof(cbuf));
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = (struct iovec *)iov;
        msg.msg_iovlen = iovcnt;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_QUIC;
        cmsg->cmsg_type = QUIC_STREAM_INFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

        /* The first send opens the stream, later ones must not. */
        info = (struct quic_stream_info *)CMSG_DATA(cmsg);
        info->stream_id = SMB2_QUIC_STREAM;
        info->stream_flags = smb2->quic_stream_open ?
                0 : MSG_QUIC_STREAM_NEW;

        count = sendmsg(smb2->fd, &msg, MSG_NOSIGNAL);
        if (count >= 0) {
                smb2->quic_stream_open = 1;
        }
        return count;
}

#endif /* HAVE_LIBQUIC */
