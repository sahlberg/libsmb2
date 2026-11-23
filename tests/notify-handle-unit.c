/* Change notify keeps the share selected at submission. LGPL-2.1-or-later. */
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
#include "portable-endian.h"
#include "libsmb2-private.h"

/* Return an empty response for the outstanding request through the dispatcher. */
static void send_reply(struct smb2_context *smb2, int peer, struct smb2_pdu *pdu,
                       uint32_t status, uint8_t struct_size)
{
        uint8_t packet[SMB2_SPL_SIZE + SMB2_HEADER_SIZE + SMB2_CREATE_REPLY_SIZE] = {0};
        uint8_t *header = packet + SMB2_SPL_SIZE;
        size_t size = SMB2_HEADER_SIZE + (struct_size & ~1u);
        uint32_t wire_status = htole32(status);

        packet[3] = (uint8_t)size;
        memcpy(header, pdu->hdr, SMB2_HEADER_SIZE);
        memcpy(header + 8, &wire_status, sizeof(wire_status));
        header[14] = 1; /* credit grant */
        header[15] = 0;
        header[16] = SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND;
        header[SMB2_HEADER_SIZE] = struct_size;
        assert(write(peer, packet, SMB2_SPL_SIZE + size) == (ssize_t)(SMB2_SPL_SIZE + size));
        assert(!smb2_service(smb2, POLLIN));
}

static void reply(struct smb2_context *smb2, int peer, enum smb2_command command,
                  uint32_t status, uint8_t struct_size)
{
        struct smb2_pdu *pdu = smb2->waitqueue;

        assert(pdu && pdu->header.command == command);
        assert(pdu->header.sync.tree_id == 1);
        send_reply(smb2, peer, pdu, SMB2_STATUS_PENDING, SMB2_ERROR_REPLY_SIZE);
        assert(smb2->waitqueue == pdu && (pdu->header.flags & SMB2_FLAGS_ASYNC_COMMAND));
        assert(!smb2_select_tree_id(smb2, 2));
        send_reply(smb2, peer, pdu, status, struct_size);
}

static void expect_io_error(struct smb2_context *smb2, int status, void *reply, void *data)
{
        int *calls = data;
        assert(status == -EIO && reply == NULL);
        (*calls)++;
}

static void notify_done(struct smb2_context *smb2, int status, void *changes, void *data)
{
        int *calls = data;
        (*calls)++;
        free_smb2_file_notify_change_information(smb2, changes);
}

static void watch_across_tree_switch(struct smb2_context *smb2, int peer)
{
        smb2_file_id id = {0};
        struct smb2fh *fh;
        int calls = 0;

        assert(smb2_select_tree_id(smb2, 1) == 0);
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        assert(smb2_notify_change_filehandle_async(smb2, fh, 0,
                       SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME, 1, notify_done, &calls) == 0);
        reply(smb2, peer, SMB2_CHANGE_NOTIFY, SMB2_STATUS_SUCCESS, SMB2_CHANGE_NOTIFY_REPLY_SIZE);
        reply(smb2, peer, SMB2_CHANGE_NOTIFY, SMB2_STATUS_CANCELLED, SMB2_ERROR_REPLY_SIZE);
        assert(calls == 2);
        assert(!smb2_notify_change_filehandle_async(smb2, fh, 0,
                       SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME, 1, expect_io_error, &calls));
        reply(smb2, peer, SMB2_CHANGE_NOTIFY, SMB2_STATUS_END_OF_FILE, SMB2_ERROR_REPLY_SIZE);
        assert(calls == 3 && !smb2->waitqueue && !smb2->outqueue);
}

static void start_path_watch(struct smb2_context *smb2, int status, void *changes, void *data)
{
        assert(status == 0);
        free_smb2_file_notify_change_information(smb2, changes);
        assert(!smb2_select_tree_id(smb2, 1));
        assert(!smb2_notify_change_async(smb2, "dir", 0,
                        SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME, 0, notify_done, data));
}

static void watch_path(struct smb2_context *smb2, int peer)
{
        int calls = 0;

        smb2_file_id id = {0};
        struct smb2fh *fh;

        assert(!smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        assert(!smb2_notify_change_filehandle_async(smb2, fh, 0,
                        SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME, 0, start_path_watch, &calls));
        reply(smb2, peer, SMB2_CHANGE_NOTIFY, 0, SMB2_CHANGE_NOTIFY_REPLY_SIZE);
        reply(smb2, peer, SMB2_CREATE, 0, SMB2_CREATE_REPLY_SIZE);
        reply(smb2, peer, SMB2_CHANGE_NOTIFY, 0, SMB2_CHANGE_NOTIFY_REPLY_SIZE);
        reply(smb2, peer, SMB2_CLOSE, 0, SMB2_CLOSE_REPLY_SIZE);
        assert(calls == 1);
}

static void ignore_result(struct smb2_context *smb2, int status, void *reply, void *data)
{
}

static void handle_io_across_tree_switch(void)
{
        const enum smb2_command commands[] = {SMB2_READ, SMB2_WRITE, SMB2_FLUSH,
                SMB2_SET_INFO, SMB2_QUERY_INFO, SMB2_IOCTL, SMB2_IOCTL};
        struct smb2_context *smb2 = smb2_init_context();
        struct smb2_srv_copychunk_resume_key key = {0};
        struct smb2_srv_copychunk chunk = {0};
        struct smb2_stat_64 st;
        struct smb2_pdu *pdu;
        smb2_file_id id = {1};
        struct smb2fh *fh;
        uint8_t byte = 0;
        size_t i;

        assert(smb2 && !smb2_connect_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh && !smb2_connect_tree_id(smb2, 2));
        assert(!smb2_select_tree_id(smb2, 2));
        assert(!smb2_pread_async(smb2, fh, &byte, 1, 0, ignore_result, NULL));
        assert(!smb2_pwrite_async(smb2, fh, &byte, 1, 0, ignore_result, NULL));
        assert(!smb2_fsync_async(smb2, fh, ignore_result, NULL));
        assert(!smb2_ftruncate_async(smb2, fh, 0, ignore_result, NULL));
        assert(!smb2_fstat_async(smb2, fh, &st, ignore_result, NULL));
        assert(!smb2_request_resume_key_async(smb2, fh, ignore_result, NULL));
        chunk.length = 1;
        assert(!smb2_copychunk_async(smb2, SMB2_FSCTL_SRV_COPYCHUNK, &key, fh,
                                     &chunk, 1, ignore_result, NULL));
        pdu = smb2->outqueue;
        for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
                assert(pdu && pdu->header.command == commands[i]);
                assert(pdu->header.sync.tree_id == 1);
                if (commands[i] == SMB2_QUERY_INFO) {
                        assert(pdu->next_compound && pdu->next_compound->header.sync.tree_id == 1);
                }
                pdu = pdu->next;
        }
        assert(!pdu);
        smb2_destroy_context(smb2);
}

int main(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        int sockets[2];

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, sockets));
        assert(!fcntl(sockets[0], F_SETFL, O_NONBLOCK));
        smb2_set_passthrough(smb2, 1);
        smb2->fd = sockets[0];
        smb2->credits = 8;
        assert(!smb2_connect_tree_id(smb2, 1));
        assert(!smb2_connect_tree_id(smb2, 2));
        handle_io_across_tree_switch();
        watch_across_tree_switch(smb2, sockets[1]);
        watch_path(smb2, sockets[1]);
        smb2_destroy_context(smb2);
        close(sockets[1]);
        return 0;
}
