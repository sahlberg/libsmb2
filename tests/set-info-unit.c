/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../lib/compat.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

static void received_set_info(struct smb2_context *smb2 _U_, int status, void *data, void *priv)
{
        struct smb2_set_info_request *req = data;
        int *received = priv;
        assert(!status && req->buffer_length == 1);
        assert(req->input_data && *(uint8_t *)req->input_data == 1);
        (*received)++;
}

static void padded_set_info(struct smb2_context *smb2)
{
        struct smb2_set_info_request req = {0};
        struct smb2_server server = {0};
        struct smb2_context *receiver = smb2_init_context();
        struct smb2_pdu *sent;
        uint8_t wire[4 + SMB2_HEADER_SIZE + 32 + 8 + 1] = {0};
        uint8_t *header = wire + 4, *fixed = header + SMB2_HEADER_SIZE;
        uint8_t disposition = 1;
        int pair[2], received = 0;

        req.info_type = SMB2_0_INFO_FILE;
        req.file_info_class = SMB2_FILE_DISPOSITION_INFORMATION;
        req.buffer_offset = SMB2_HEADER_SIZE + 32 + 8;
        req.buffer_length = 1;
        req.input_data = &disposition;
        smb2_set_passthrough(smb2, 1);
        sent = smb2_cmd_set_info_async(smb2, &req, NULL, NULL);
        assert(sent && sent->out.iov[1].len == 32);
        memcpy(fixed, sent->out.iov[1].buf, 32);
        assert(fixed[8] == SMB2_HEADER_SIZE + 32 && fixed[9] == 0);
        assert(sent->out.iov[2].buf[0] == disposition);
        smb2_free_pdu(smb2, sent);

        /* Receive the same request with eight bytes of optional padding. */
        assert(receiver && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        receiver->fd = pair[0];
        assert(!fcntl(pair[0], F_SETFL, O_NONBLOCK));
        receiver->owning_server = &server;
        smb2_set_passthrough(receiver, 1);
        receiver->pdu = smb2_cmd_echo_async(receiver, received_set_info, &received);
        assert(receiver->pdu);
        wire[3] = sizeof(wire) - 4;
        memcpy(header, "\xfeSMB", 4);
        header[4] = SMB2_HEADER_SIZE;
        header[12] = SMB2_SET_INFO;
        fixed[8] = req.buffer_offset;
        wire[sizeof(wire) - 1] = disposition;
        assert(write(pair[1], wire, sizeof(wire)) == sizeof(wire));
        assert(!smb2_service(receiver, POLLIN) && received == 1);
        smb2_free_pdu(receiver, receiver->waitqueue);
        smb2_destroy_context(receiver);
        close(pair[1]);
}

int main(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        assert(smb2);
        padded_set_info(smb2);
        smb2_destroy_context(smb2);
        return 0;
}
