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
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../lib/compat.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

struct result {
        int completed, released;
};

static void completed(struct smb2_context *smb2 _U_, int status, void *reply, void *data)
{
        struct result *result = data;
        assert(status == -ETIMEDOUT && !reply);
        result->completed++;
}

static void released(void *data)
{
        struct result *result = data;
        result->released++;
}

/* Let the real send path assign a MessageId and move CREATE to the waitqueue.
 * Supply the final decoded reply and inspect the CLOSE sent over the same fd. */
static void check_late_reply(int directory, int timeout, int caller_owns, int success)
{
        struct smb2_context *smb2 = smb2_init_context();
        struct smb2_create_reply reply = {0};
        struct result result = {0};
        struct smb2_pdu *pdu, *owner = NULL;
        int fd[2];

        assert(smb2 && socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
        smb2->fd = fd[0];
        smb2->credits = 10;
        assert(!smb2_connect_tree_id(smb2, 1));
        assert(!smb2_connect_tree_id(smb2, 2));
        assert(!smb2_select_tree_id(smb2, 1));
        if (directory && caller_owns) {
                owner = smb2_opendir_async_pdu(smb2, "", completed, &result, released);
        } else if (directory) {
                assert(!smb2_opendir_async(smb2, "", completed, &result));
        } else if (caller_owns) {
                owner = smb2_open_async_pdu(smb2, "file", O_RDONLY, completed, &result, released);
        } else {
                assert(!smb2_open_async(smb2, "file", O_RDONLY, completed, &result));
        }
        assert(!smb2_service(smb2, POLLOUT));
        pdu = smb2->waitqueue;
        assert(pdu && (!caller_owns || pdu == owner));
        assert(!smb2_select_tree_id(smb2, 2));
        pdu->header.flags |= SMB2_FLAGS_ASYNC_COMMAND;
        pdu->header.async.async_id = 0x12345678;
        if (timeout) {
                smb2_set_timeout(smb2, 30);
                pdu->timeout = time(NULL) - 1;
                assert(!smb2_service(smb2, 0));
                assert(result.completed == 1);
        }
        if (caller_owns) {
                smb2_free_pdu(smb2, owner);
        }
        assert(result.released == !timeout);
        assert(smb2->waitqueue == pdu);
        smb2->waitqueue = pdu->next;
        smb2->pdu = pdu;
        memset(reply.file_id, 0x53, sizeof(reply.file_id));
        pdu->cb(smb2, success ? 0 : SMB2_STATUS_ACCESS_DENIED,
                success ? &reply : NULL, pdu->cb_data);
        smb2->pdu = NULL;
        smb2_free_pdu(smb2, pdu);
        if (success) {
                assert(!smb2_service(smb2, POLLOUT));
                pdu = smb2->waitqueue;
                assert(pdu && !pdu->next && pdu->header.command == SMB2_CLOSE);
                assert(pdu->header.sync.tree_id == 1);
                assert(!memcmp(pdu->out.iov[1].buf + 8, reply.file_id, SMB2_FD_SIZE));
        } else {
                assert(!smb2->outqueue && !smb2->waitqueue);
        }
        assert(result.completed == timeout && result.released == !timeout);
        smb2_destroy_context(smb2);
        close(fd[1]);
}

int main(void)
{
        int dir, success;
        for (dir = 0; dir <= 1; dir++) {
                for (success = 0; success <= 1; success++) {
                        check_late_reply(dir, 0, 1, success);
                        check_late_reply(dir, 1, 1, success);
                        check_late_reply(dir, 1, 0, success);
                }
        }
        return 0;
}
