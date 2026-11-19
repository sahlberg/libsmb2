/* Offline checks for the lifetime of a caller-owned CREATE. LGPL-2.1-or-later. */
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

struct callbacks {
        int completed;
        int released;
};

static void completed(struct smb2_context *smb2, int status, void *reply, void *data)
{
        struct callbacks *calls = data;
        calls->completed++;
}

static void released(void *data)
{
        struct callbacks *calls = data;
        calls->released++;
}

static void release_on_completion(struct smb2_context *smb2, int status,
                                  void *reply, void *data)
{
        struct smb2_pdu **owner = data;
        assert(status < 0 && reply == NULL);
        smb2_free_pdu(smb2, *owner);
        *owner = NULL;
}

/* Complete one valid response with the same ownership rules as the receiver.
 * The socketpair lets us also check which SMB command was really sent next. */
static void reply(struct smb2_context *smb2, enum smb2_command command,
                  int status, void *data)
{
        struct smb2_pdu *pdu = smb2->waitqueue;

        assert(pdu && pdu->header.command == command);
        assert(pdu->header.sync.tree_id == 1);
        assert(smb2_select_tree_id(smb2, 2) == 0);
        smb2->credits++; /* grant one credit with each mock reply */
        smb2_unlink_pdu(smb2, pdu);
        smb2->pdu = pdu;
        if (pdu->cb) {
                pdu->cb(smb2, status, data, pdu->cb_data);
        }
        if (!pdu->caller_frees_pdu) {
                smb2_free_pdu(smb2, pdu);
        }
        smb2->pdu = NULL;
}

/* Cancel an opendir while its CREATE, QUERY_DIRECTORY or CLOSE is pending. */
static void cancel_directory(struct smb2_context *smb2, enum smb2_command stage)
{
        struct callbacks calls = {0};
        struct smb2_pdu *owner;
        struct smb2_create_reply created = {0};

        assert(smb2_select_tree_id(smb2, 1) == 0);
        smb2_set_timeout(smb2, 30);
        owner = smb2_opendir_async_pdu(smb2, "", completed, &calls, released);
        assert(owner);
        if (stage == SMB2_CREATE) {
                smb2_free_pdu(smb2, owner);
                smb2->waitqueue->timeout = time(NULL) - 1;
                assert(!smb2_service(smb2, 0));
        }
        reply(smb2, SMB2_CREATE, SMB2_STATUS_SUCCESS, &created);
        if (stage != SMB2_CREATE) {
                if (stage == SMB2_QUERY_DIRECTORY) {
                        smb2_free_pdu(smb2, owner);
                }
                reply(smb2, SMB2_QUERY_DIRECTORY, SMB2_STATUS_NO_MORE_FILES, NULL);
                if (stage == SMB2_CLOSE) {
                        smb2_free_pdu(smb2, owner);
                }
        }
        assert(calls.released == 1);
        reply(smb2, SMB2_CLOSE, SMB2_STATUS_SUCCESS, NULL);
        assert(calls.completed == 0 && calls.released == 1);
        assert(smb2->dirs == NULL);
        smb2_set_timeout(smb2, 0);
}

static void directory_query_failure(struct smb2_context *smb2)
{
        struct callbacks calls = {0};
        struct smb2_create_reply created = {0};

        assert(smb2_select_tree_id(smb2, 1) == 0);
        assert(smb2_opendir_async(smb2, "", completed, &calls) == 0);
        reply(smb2, SMB2_CREATE, SMB2_STATUS_SUCCESS, &created);
        reply(smb2, SMB2_QUERY_DIRECTORY, SMB2_STATUS_ACCESS_DENIED, NULL);
        assert(calls.completed == 1 && smb2->dirs == NULL);
        reply(smb2, SMB2_CLOSE, SMB2_STATUS_SUCCESS, NULL);
        assert(calls.completed == 1);
}

static void cancel_on_error(struct smb2_context *smb2, const char *message)
{
        struct smb2_pdu **owner = smb2_get_opaque(smb2);

        smb2_register_error_callback(smb2, NULL);
        smb2_free_pdu(smb2, *owner);
        *owner = NULL;
}

enum cancel_stage { RETRY_QUEUED, RETRY_SENT, LINK_WALK_ERROR };

static void cancel_symlink_retry(struct smb2_context *smb2, enum cancel_stage stage)
{
        struct callbacks calls = {0};
        struct smb2_pdu *owner;
        struct smb2_create_reply created = {0};
        /* Relative symlink with substitute and print name "x". */
        uint8_t target[] = {
                26,0,0,0, 'S','Y','M','L', 0x0c,0,0,0xa0, 14,0,0,0,
                0,0,2,0, 0,0,2,0, 1,0,0,0, 'x',0
        };
        struct smb2_error_reply link = {0};

        link.byte_count = sizeof(target);
        link.error_data = target;
        assert(smb2_select_tree_id(smb2, 1) == 0);
        smb2_set_timeout(smb2, 30);
        owner = smb2_open_async_pdu(smb2, "link", O_RDONLY, completed, &calls, released);
        assert(owner);
        if (stage == LINK_WALK_ERROR) {
                smb2_set_opaque(smb2, &owner);
                smb2_register_error_callback(smb2, cancel_on_error);
                /* A directory entry "x" links back to itself. */
                while (owner && smb2->credits > 0) {
                        reply(smb2, SMB2_CREATE, SMB2_STATUS_STOPPED_ON_SYMLINK, &link);
                }
                assert(owner == NULL);
                smb2_set_opaque(smb2, NULL);
        } else {
                if (stage == RETRY_QUEUED) {
                        smb2->credits = 0;
                }
                reply(smb2, SMB2_CREATE, SMB2_STATUS_STOPPED_ON_SYMLINK, &link);
                smb2_free_pdu(smb2, owner);
                if (stage == RETRY_SENT) {
                        smb2->waitqueue->timeout = time(NULL) - 1;
                        assert(!smb2_service(smb2, 0));
                        reply(smb2, SMB2_CREATE, SMB2_STATUS_SUCCESS, &created);
                        reply(smb2, SMB2_CLOSE, SMB2_STATUS_SUCCESS, NULL);
                }
        }
        assert(smb2->outqueue == NULL && smb2->waitqueue == NULL);
        smb2->credits = 32;
        assert(calls.released == 1 && calls.completed == 0);
        assert(smb2->fhs == NULL);
        smb2_set_timeout(smb2, 0);
}

static void cancel_other_open(struct smb2_context *smb2, int status, void *data, void *priv)
{
        struct smb2_pdu **other = priv;
        assert(status < 0);
        smb2_free_pdu(smb2, *other);
        *other = NULL;
}

static void timeout_batch(struct smb2_context *smb2)
{
        struct callbacks calls = {0};
        struct smb2_pdu *first, *other, *last;

        smb2->credits = 0;
        smb2_set_timeout(smb2, 10);
        first = smb2_open_async_pdu(smb2, "first", O_RDONLY, cancel_other_open, &other, NULL);
        other = smb2_open_async_pdu(smb2, "second", O_RDONLY, completed, &calls, released);
        last = smb2_open_async_pdu(smb2, "last", O_RDONLY, completed, &calls, NULL);
        assert(first && other && last);
        first->timeout = last->timeout = time(NULL) - 1;
        assert(smb2_service(smb2, 0) == 0);
        assert(!other && calls.released == 1 && calls.completed == 1);
        smb2_free_pdu(smb2, first);
        smb2_free_pdu(smb2, last);
        smb2_set_timeout(smb2, 0);
        smb2->credits = 32;
}

static void expect_io_error(struct smb2_context *smb2, int status, void *reply, void *data)
{
        int *calls = data;
        assert(status == -EIO && reply == NULL);
        (*calls)++;
}

static void copy_across_tree_switch(struct smb2_context *smb2)
{
        struct smb2_srv_copychunk chunk = {0};
        struct smb2_ioctl_reply rep = {0};
        struct callbacks calls = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;

        assert(smb2_select_tree_id(smb2, 1) == 0);
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        chunk.length = 1;
        assert(smb2_server_side_copy_async(smb2, SMB2_FSCTL_SRV_COPYCHUNK,
                                           fh, fh, &chunk, 1, completed, &calls) == 0);
        rep.output = smb2_alloc_init(smb2, sizeof(struct smb2_srv_copychunk_resume_key));
        assert(rep.output);
        /* reply() selects tree 2 before it dispatches each completion. */
        reply(smb2, SMB2_IOCTL, SMB2_STATUS_SUCCESS, &rep);
        reply(smb2, SMB2_IOCTL, SMB2_STATUS_ACCESS_DENIED, NULL);
        assert(calls.completed == 1);
}

static void seek_during_positioned_io(struct smb2_context *smb2)
{
        struct smb2_write_reply written = {0};
        struct smb2_read_reply read = {0};
        struct callbacks calls = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;
        uint8_t byte = 0;

        assert(smb2_select_tree_id(smb2, 1) == 0);
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        assert(!smb2_pwrite_async(smb2, fh, &byte, 1, 0, completed, &calls));
        assert(smb2_lseek(smb2, fh, 7, SEEK_SET, NULL) == 7);
        written.count = 1;
        reply(smb2, SMB2_WRITE, 0, &written);
        assert(smb2_lseek(smb2, fh, 0, SEEK_CUR, NULL) == 7);
        assert(smb2_select_tree_id(smb2, 1) == 0);
        assert(!smb2_pread_async(smb2, fh, &byte, 1, 0, completed, &calls));
        assert(smb2_lseek(smb2, fh, 9, SEEK_SET, NULL) == 9);
        read.data_length = 1;
        reply(smb2, SMB2_READ, 0, &read);
        assert(smb2_lseek(smb2, fh, 0, SEEK_CUR, NULL) == 9);
        assert(calls.completed == 2);
}

static void count_diagnostic(struct smb2_context *smb2, const char *message)
{
        int *count = smb2_get_opaque(smb2);
        (*count)++;
}

static void timed_read_done(struct smb2_context *smb2, int status, void *args, void *priv)
{
        struct smb2_read_cb_data *rd = args;
        struct callbacks *calls = priv;
        int diagnostics = 0;
        assert(status < 0);
        smb2_set_opaque(smb2, &diagnostics);
        smb2_register_error_callback(smb2, count_diagnostic);
        assert(smb2_close(smb2, rd->fh) == -EDEADLK);
        assert(smb2_fstat(smb2, rd->fh, NULL) == -EDEADLK);
        assert(smb2_stat(smb2, "", NULL) == -EDEADLK);
        assert(smb2_statvfs(smb2, "", NULL) == -EDEADLK);
        assert(!diagnostics);
        smb2_register_error_callback(smb2, NULL);
        smb2_set_opaque(smb2, NULL);
        calls->completed++;
}

static void timeout_during_sync_wait(struct smb2_context *smb2)
{
        struct callbacks calls = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;
        uint8_t byte;

        assert(!smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        smb2_set_timeout(smb2, 1);
        assert(fh && !smb2_pread_async(smb2, fh, &byte, 1, 0, timed_read_done, &calls));
        smb2->waitqueue->timeout = time(NULL) - 1;
        assert(smb2_echo(smb2) < 0);
        assert(calls.completed == 1 && !smb2->servicing);
        smb2_set_timeout(smb2, 0);
}

static void expect_timeout(struct smb2_context *smb2, int status, void *args, void *data)
{
        int *count = data;
        assert(status == -ETIMEDOUT);
        (*count)++;
}

static void close_waiting_for_credit(struct smb2_context *smb2)
{
        struct smb2fh *fh, *previous = smb2->fhs;
        smb2_file_id id = {0};
        int expired = 0;

        assert(!smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        smb2->credits = 0;
        smb2_set_timeout(smb2, 30);
        assert(fh && !smb2_close_async(smb2, fh, expect_timeout, &expired));
        smb2_set_timeout(smb2, 0);
        smb2->outqueue->timeout = time(NULL) - 1;
        assert(!smb2_service(smb2, 0) && expired == 1 && smb2->fhs == previous);
        assert(smb2->outqueue && smb2->outqueue->timeout > time(NULL));
        smb2->credits = 32;
        assert(!smb2_service(smb2, POLLOUT));
        assert(smb2->waitqueue && smb2->waitqueue->timeout > time(NULL));
        reply(smb2, SMB2_CLOSE, 0, NULL);
        assert(expired == 1);
}

static void late_open(struct smb2_context *smb2, int directory, int owned)
{
        struct smb2_create_reply created = {0};
        struct smb2_pdu *owner = NULL;
        int expired = 0;

        assert(!smb2_select_tree_id(smb2, 1));
        smb2->credits = 32;
        smb2_set_timeout(smb2, 30);
        if (directory) {
                if (owned) {
                        owner = smb2_opendir_async_pdu(smb2, "", expect_timeout, &expired, NULL);
                } else {
                        assert(!smb2_opendir_async(smb2, "", expect_timeout, &expired));
                }
        } else if (owned) {
                owner = smb2_open_async_pdu(smb2, "file", O_RDONLY, expect_timeout, &expired, NULL);
        } else {
                assert(!smb2_open_async(smb2, "file", O_RDONLY, expect_timeout, &expired));
        }
        assert(smb2->waitqueue && (!owned || owner == smb2->waitqueue));
        smb2->waitqueue->timeout = time(NULL) - 1;
        assert(!smb2_service(smb2, 0) && expired == 1 && smb2->waitqueue);
        if (owned == 1) {
                smb2_free_pdu(smb2, owner);
        }
        reply(smb2, SMB2_CREATE, SMB2_STATUS_SUCCESS, &created);
        if (owned == 2) {
                smb2_free_pdu(smb2, owner);
        }
        reply(smb2, SMB2_CLOSE, SMB2_STATUS_SUCCESS, NULL);
        assert(expired == 1 && !smb2->waitqueue);
        smb2_set_timeout(smb2, 0);
}

static void directory_close_waiting_for_credit(struct smb2_context *smb2)
{
        struct smb2_create_reply created = {0};
        int expired = 0;
        assert(!smb2_select_tree_id(smb2, 1));
        smb2->credits = 32;
        smb2_set_timeout(smb2, 30);
        assert(!smb2_opendir_async(smb2, "", expect_timeout, &expired));
        reply(smb2, SMB2_CREATE, 0, &created);
        smb2->credits = -1; /* reply() grants one credit */
        reply(smb2, SMB2_QUERY_DIRECTORY, SMB2_STATUS_NO_MORE_FILES, NULL);
        assert(smb2->outqueue && !smb2->waitqueue);
        smb2->outqueue->timeout = time(NULL) - 1;
        assert(!smb2_service(smb2, 0) && expired == 1 && !smb2->dirs);
        assert(smb2->outqueue && smb2->outqueue->timeout > time(NULL));
        smb2->credits = 32;
        assert(!smb2_service(smb2, POLLOUT));
        reply(smb2, SMB2_CLOSE, 0, NULL);
        smb2_set_timeout(smb2, 0);
}

static void deferred_io_timeout(struct smb2_context *smb2, int positioned)
{
        struct callbacks calls = {0};
        struct smb2_read_reply read = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;
        uint8_t byte;
        int expired = 0;

        assert(!smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        if (positioned) {
                assert(!smb2_pread_async(smb2, fh, &byte, 1, 0, completed, &calls));
        } else {
                assert(!smb2_read_async(smb2, fh, &byte, 1, completed, &calls));
        }
        /* Make the next request's deadline deterministic without sleeping. */
        smb2_set_timeout(smb2, -1);
        assert(!smb2_close_async(smb2, fh, expect_timeout, &expired));
        smb2_set_timeout(smb2, 0);
        assert(!smb2_service(smb2, 0));
        assert(expired == 1 && !calls.completed);
        reply(smb2, SMB2_READ, 0, &read);
        assert(smb2->waitqueue && smb2->waitqueue->timeout >= time(NULL));
        reply(smb2, SMB2_CLOSE, 0, NULL);
        assert(calls.completed == 1 && expired == 1);
}

static void mixed_io_timeouts(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        int pair[2];
        struct callbacks calls = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;
        int expired = 0, i;

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        smb2->fd = pair[0];
        smb2->credits = 32;
        assert(!smb2_connect_tree_id(smb2, 2) && !smb2_connect_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh && !smb2_fsync_async(smb2, fh, completed, &calls));
        for (i = 0; i < 8; i++) {
                smb2_set_timeout(smb2, 60);
                assert(!smb2_fsync_async(smb2, fh, completed, &calls));
                smb2_set_timeout(smb2, -1);
                assert(!smb2_fsync_async(smb2, fh, expect_timeout, &expired));
        }
        smb2_set_timeout(smb2, 0);
        assert(!smb2_service(smb2, 0) && expired == 8);
        for (i = 0; i < 9; i++) {
                reply(smb2, SMB2_FLUSH, 0, NULL);
        }
        assert(calls.completed == 9 && !smb2->io_timers);
        assert(!smb2_close_async(smb2, fh, completed, &calls));
        reply(smb2, SMB2_CLOSE, 0, NULL);
        smb2_destroy_context(smb2);
        close(pair[1]);
}

static void promoted_io_timeout(struct smb2_context *smb2)
{
        struct callbacks calls = {0};
        smb2_file_id id = {1};
        struct smb2fh *fh;
        int expired = 0;

        assert(!smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh && !smb2_fsync_async(smb2, fh, completed, &calls));
        smb2_set_timeout(smb2, 5);
        assert(!smb2_fsync_async(smb2, fh, expect_timeout, &expired));
        smb2_set_timeout(smb2, 0);
        reply(smb2, SMB2_FLUSH, 0, NULL);
        assert(calls.completed == 1 && !smb2->io_timers);
        assert(smb2->waitqueue && smb2->waitqueue->timeout);
        smb2->waitqueue->timeout = time(NULL) - 1;
        assert(!smb2_service(smb2, 0) && expired == 1);
}

static void flush_after_tree_switch(struct smb2_context *smb2)
{
        struct callbacks calls = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;

        assert(!smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh && !smb2_select_tree_id(smb2, 2));
        assert(!smb2_fsync_async(smb2, fh, completed, &calls));
        assert(!smb2_close_async(smb2, fh, completed, &calls));
        assert(smb2->waitqueue && !smb2->waitqueue->next);
        reply(smb2, SMB2_FLUSH, 0, NULL);
        reply(smb2, SMB2_CLOSE, 0, NULL);
        assert(calls.completed == 2);
}

struct reentrant_close {
        struct smb2fh *fh;
        struct callbacks calls;
};

static void close_on_reject(struct smb2_context *smb2, const char *message)
{
        struct reentrant_close *op = smb2_get_opaque(smb2);

        assert(strstr(message, "message id"));
        smb2_register_error_callback(smb2, NULL);
        smb2->owning_server = NULL;
        assert(!smb2_close_async(smb2, op->fh, completed, &op->calls));
}

static void reject_first_io(struct smb2_context *smb2, int positioned)
{
        struct smb2_server server = {0};
        struct reentrant_close op = {0};
        smb2_file_id id = {1};
        uint8_t byte;

        assert(!smb2_select_tree_id(smb2, 1));
        op.fh = smb2_fh_from_file_id(smb2, &id);
        assert(op.fh);
        smb2_set_opaque(smb2, &op);
        smb2_register_error_callback(smb2, close_on_reject);
        /* Server queueing rejects a client request without a reply ID. */
        smb2->owning_server = &server;
        if (positioned) {
                assert(smb2_pread_async(smb2, op.fh, &byte, 1, 0, completed, &op.calls) < 0);
        } else {
                assert(smb2_read_async(smb2, op.fh, &byte, 1, completed, &op.calls) < 0);
        }
        assert(!op.calls.completed);
        reply(smb2, SMB2_CLOSE, 0, NULL);
        assert(op.calls.completed == 1);
        smb2_set_opaque(smb2, NULL);
}

static void nonread_eof(struct smb2_context *smb2)
{
        smb2_file_id id = {0};
        struct smb2fh *fh;
        int calls = 0;

        assert(!smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh && !smb2_fsync_async(smb2, fh, expect_io_error, &calls));
        assert(!smb2_ftruncate_async(smb2, fh, 10, expect_io_error, &calls));
        assert(!smb2_close_async(smb2, fh, expect_io_error, &calls));
        reply(smb2, SMB2_FLUSH, SMB2_STATUS_END_OF_FILE, NULL);
        reply(smb2, SMB2_SET_INFO, SMB2_STATUS_END_OF_FILE, NULL);
        reply(smb2, SMB2_CLOSE, SMB2_STATUS_END_OF_FILE, NULL);
        assert(calls == 3);
        assert(!smb2_select_tree_id(smb2, 1));
        assert(!smb2_disconnect_share_async(smb2, expect_io_error, &calls));
        reply(smb2, SMB2_TREE_DISCONNECT, SMB2_STATUS_END_OF_FILE, NULL);
        assert(calls == 4 && SMB2_VALID_SOCKET(smb2_get_fd(smb2)) && !smb2->waitqueue);
}

static void close_after_positioned_io(struct smb2_context *smb2)
{
        struct callbacks calls = {0};
        struct smb2_write_reply written = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;
        uint8_t byte = 0;

        assert(!smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        assert(smb2_pwrite_async(smb2, fh, NULL, 1, 0, completed, &calls) == -EINVAL);
        assert(smb2_pread_async(smb2, fh, NULL, 1, 0, completed, &calls) == -EINVAL);
        assert(!smb2->waitqueue && !smb2->outqueue && calls.completed == 0);
        assert(!smb2_pwrite_async(smb2, fh, &byte, 1, 0, completed, &calls));
        assert(!smb2_pread_async(smb2, fh, &byte, 1, 0, completed, &calls));
        assert(!smb2_close_async(smb2, fh, completed, &calls));
        assert(smb2_pread_async(smb2, fh, &byte, 1, 0, completed, &calls) == -EBADF);
        assert(smb2->waitqueue->next && !smb2->waitqueue->next->next);
        written.count = 1;
        reply(smb2, SMB2_WRITE, 0, &written);
        assert(calls.completed == 1 && !smb2->waitqueue->next);
        reply(smb2, SMB2_READ, SMB2_STATUS_END_OF_FILE, NULL);
        reply(smb2, SMB2_CLOSE, 0, NULL);
        assert(calls.completed == 3);
}

static void disconnect_during_copy(struct smb2_context *smb2, int peer)
{
        struct smb2_srv_copychunk_resume_key key = {0};
        struct smb2_srv_copychunk chunk = {0};
        struct smb2_srv_copychunk_reply result;
        smb2_file_id id = {0};
        struct smb2fh *fh = smb2_fh_from_file_id(smb2, &id);

        assert(fh);
        chunk.length = 1;
        assert(shutdown(peer, SHUT_WR) == 0);
        assert(smb2_request_resume_key(smb2, fh, &key) < 0);
        assert(smb2_copychunk(smb2, SMB2_FSCTL_SRV_COPYCHUNK, &key,
                              fh, &chunk, 1, &result) < 0);
        assert(smb2_server_side_copy(smb2, SMB2_FSCTL_SRV_COPYCHUNK,
                                     fh, fh, &chunk, 1, &result) < 0);
        /* Context teardown below completes the outstanding IOCTL callbacks. */
}

static void release_context(struct smb2_context *smb2, int status, void *reply, void *data)
{
        int *completed = data;
        (*completed)++;
        smb2_destroy_context(smb2);
}

static void release_from_completion(int sync_open)
{
        struct smb2_context *smb2 = smb2_init_context();
        int pair[2], completed = 0;

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        smb2->fd = pair[0];
        smb2->credits = 0;
        smb2_set_timeout(smb2, 5);
        assert(!smb2_echo_async(smb2, release_context, &completed));
        smb2->outqueue->timeout = time(NULL) - 1;
        if (sync_open) {
                assert(!smb2_open(smb2, "missing", O_RDONLY));
        } else {
                assert(smb2_service(smb2, 0) == 0);
        }
        assert(completed == 1);
        close(pair[1]);
}

static void release_with_queued_truncate(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        struct smb2fh *fh;
        struct callbacks calls = {0};
        smb2_file_id id = {1};
        uint8_t wire[512], byte = 1;
        int pair[2], released = 0;

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        smb2->fd = pair[0];
        smb2->credits = 32;
        smb2_set_timeout(smb2, 5);
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh && !smb2_write_async(smb2, fh, &byte, 1, release_context, &released));
        assert(read(pair[1], wire, sizeof(wire)) > 0);
        assert(!smb2_ftruncate_async(smb2, fh, 0, completed, &calls));
        smb2->waitqueue->timeout = time(NULL) - 1;
        assert(smb2_service(smb2, 0) == 0);
        assert(released == 1 && calls.completed == 1);
        assert(read(pair[1], wire, sizeof(wire)) == 0);
        close(pair[1]);
}

static void release_from_cancel(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        struct callbacks echo = {0};
        struct smb2_pdu *cancel;
        int pair[2], released = 0;

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        smb2->fd = pair[0];
        smb2->credits = 32;
        assert(!smb2_echo_async(smb2, completed, &echo));
        cancel = smb2_cmd_cancel_async(smb2, smb2->waitqueue->header.message_id,
                                       release_context, &released);
        assert(cancel && !smb2_queue_pdu_checked(smb2, cancel));
        assert(released == 1 && echo.completed == 1);
        close(pair[1]);
}

static void sync_buffers_after_failed_wait(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        struct smb2_pdu *pdu;
        struct smb2_iovec *payload;
        smb2_file_id id = {1};
        struct smb2fh *fh;
        uint8_t input = 7, output = 0;

        assert(smb2);
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        /* The disconnected transport retains both unsent operations. */
        assert(smb2_pread(smb2, fh, &output, 1, 0) < 0);
        assert(smb2_write(smb2, fh, &input, 1) < 0);
        pdu = smb2->outqueue;
        assert(pdu && pdu->header.command == SMB2_READ && pdu->in.niov == 1);
        assert(pdu->in.iov[0].buf != &output);
        pdu = pdu->next;
        assert(pdu && pdu->header.command == SMB2_WRITE);
        payload = &pdu->out.iov[pdu->out.niov - 1];
        input = 8;
        assert(payload->len == 1 && *payload->buf == 7);
        smb2_destroy_context(smb2);
}

static void sync_stat_after_failed_wait(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        struct smb2_query_info_reply query = {0};
        struct smb2_file_fs_full_size_info *fs;
        struct smb2_stat_64 by_handle = {0}, by_path = {0};
        struct smb2_statvfs volume = {0};
        struct smb2fh *fh;
        smb2_file_id id = {1};
        int pair[2], i;

        assert(smb2 && !smb2_connect_tree_id(smb2, 1));
        assert(!smb2_connect_tree_id(smb2, 2) && !smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh && !smb2_select_tree_id(smb2, 2));
        assert(smb2_fstat(smb2, fh, &by_handle) < 0);
        assert(!smb2_select_tree_id(smb2, 1));
        assert(smb2_stat(smb2, "file", &by_path) < 0);
        assert(smb2_statvfs(smb2, "", &volume) < 0);

        /* Finish the retained compounds after all three synchronous callers
         * have returned and reused their output structures. */
        by_handle.smb2_size = by_path.smb2_size = volume.f_blocks = 123;
        assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        smb2->fd = pair[0];
        smb2->credits = 32;
        assert(!smb2_service(smb2, POLLOUT));
        for (i = 0; i < 2; i++) {
                struct smb2_file_all_info *file = smb2_alloc_init(smb2, sizeof(*file));
                assert(file);
                if (i == 1) {
                        reply(smb2, SMB2_CREATE, 0, NULL);
                }
                reply(smb2, SMB2_QUERY_INFO, SMB2_STATUS_NOT_SUPPORTED, NULL);
                file->standard.end_of_file = 456;
                query.output_buffer = file;
                reply(smb2, SMB2_QUERY_INFO, 0, &query);
                if (i == 1) {
                        reply(smb2, SMB2_CLOSE, 0, NULL);
                }
        }
        fs = smb2_alloc_init(smb2, sizeof(*fs));
        assert(fs);
        fs->total_allocation_units = 456;
        query.output_buffer = fs;
        reply(smb2, SMB2_CREATE, 0, NULL);
        reply(smb2, SMB2_QUERY_INFO, 0, &query);
        reply(smb2, SMB2_CLOSE, 0, NULL);
        assert(!smb2->waitqueue && !smb2->outqueue);
        assert(by_handle.smb2_size == 123 && by_path.smb2_size == 123 && volume.f_blocks == 123);
        smb2_destroy_context(smb2);
        close(pair[1]);
}

static void partial_reply_timeout(int sync_wait)
{
        struct smb2_context *smb2 = smb2_init_context();
        int expired = 0;
        uint8_t prefix[SMB2_SPL_SIZE + SMB2_HEADER_SIZE];
        int pair[2];

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        assert(!fcntl(pair[0], F_SETFL, O_NONBLOCK));
        smb2->fd = pair[0];
        smb2->credits = 32;
        smb2_set_timeout(smb2, 30);
        assert(!smb2_echo_async(smb2, expect_timeout, &expired));
        smb2_set_timeout(smb2, 0);

        /* An ECHO reply has the same body as the request. Deliver only its
         * header so the receiver is waiting for the body on the next tick. */
        assert(recv(pair[1], prefix, sizeof(prefix), MSG_WAITALL) == sizeof(prefix));
        prefix[SMB2_SPL_SIZE + 16] = SMB2_FLAGS_SERVER_TO_REDIR;
        assert(write(pair[1], prefix, sizeof(prefix)) == sizeof(prefix));
        assert(!smb2_service(smb2, POLLIN));
        assert(!smb2->waitqueue && !smb2->outqueue && smb2->pdu);
        assert(smb2->recv_state == SMB2_RECV_FIXED && !expired);
        smb2->pdu->timeout = time(NULL) - 1;
        if (sync_wait) {
                assert(smb2_echo(smb2) == -ETIMEDOUT);
        } else {
                assert(smb2_service(smb2, 0) == -ETIMEDOUT);
        }
        assert(!SMB2_VALID_SOCKET(smb2_get_fd(smb2)));
        smb2_destroy_context(smb2);
        assert(expired == 1);
        close(pair[1]);
}

static void partial_unmatched_reply(int encrypted)
{
        struct smb2_context *smb2 = smb2_init_context();
        uint8_t prefix[SMB2_SPL_SIZE + SMB2_HEADER_SIZE];
        int pair[2], expired = 0;

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        assert(!fcntl(pair[0], F_SETFL, O_NONBLOCK));
        smb2->fd = pair[0];
        smb2->credits = 32;
        smb2->seal = smb2->enc_keys_ready = encrypted;
        smb2_set_timeout(smb2, 30);
        assert(!smb2_echo_async(smb2, expect_timeout, &expired));
        smb2_set_timeout(smb2, 0);
        /* Fragment a library-generated transform before the encrypted body
         * can be decoded, or stop after the header of an interim response. */
        assert(recv(pair[1], prefix, sizeof(prefix), MSG_WAITALL) == sizeof(prefix));
        if (!encrypted) {
                prefix[SMB2_SPL_SIZE + 16] = SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND;
                prefix[SMB2_SPL_SIZE + 8] = SMB2_STATUS_PENDING & 0xff;
                prefix[SMB2_SPL_SIZE + 9] = SMB2_STATUS_PENDING >> 8;
        }
        assert(write(pair[1], prefix, sizeof(prefix)) == sizeof(prefix));
        assert(!smb2_service(smb2, POLLIN));
        assert(smb2->recv_state == (encrypted ? SMB2_RECV_TRFM : SMB2_RECV_PAD));
        assert(smb2->waitqueue && !smb2->pdu);
        assert(smb2->frame_deadline == smb2->waitqueue->timeout);
        smb2->waitqueue->timeout = smb2->frame_deadline = time(NULL) - 1;
        assert(smb2_service(smb2, 0) == -ETIMEDOUT && expired == 1);
        assert(!SMB2_VALID_SOCKET(smb2_get_fd(smb2)));
        smb2_destroy_context(smb2);
        close(pair[1]);
}

static void missing_close_credit(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        smb2_file_id id = {1};
        struct smb2fh *fh;
        int pair[2], expired = 0;

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        smb2->fd = pair[0];
        smb2->credits = 0;
        fh = smb2_fh_from_file_id(smb2, &id);
        smb2_set_timeout(smb2, 10);
        assert(fh && !smb2_close_async(smb2, fh, expect_timeout, &expired));
        smb2->outqueue->timeout = time(NULL) - 1;
        assert(!smb2_service(smb2, 0) && expired == 1);
        assert(smb2->outqueue->timeout > time(NULL));
        smb2->outqueue->timeout = time(NULL) - 1;
        assert(smb2_service(smb2, 0) == -ETIMEDOUT);
        assert(!SMB2_VALID_SOCKET(smb2->fd));
        smb2_destroy_context(smb2);
        assert(expired == 1);
        close(pair[1]);
}

static void missing_create_reply(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        int pair[2], expired = 0;

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        smb2->fd = pair[0];
        smb2->credits = 8;
        smb2_set_timeout(smb2, 10);
        assert(!smb2_open_async(smb2, "file", O_RDONLY, expect_timeout, &expired));
        smb2_set_timeout(smb2, 0);
        smb2->waitqueue->timeout = time(NULL) - 1;
        assert(!smb2_service(smb2, 0) && expired == 1);
        assert(smb2->waitqueue->timeout > time(NULL));
        smb2->waitqueue->timeout = time(NULL) - 1;
        assert(smb2_service(smb2, 0) == -ETIMEDOUT);
        assert(!SMB2_VALID_SOCKET(smb2->fd));
        smb2_destroy_context(smb2);
        assert(expired == 1);
        close(pair[1]);
}

static void partial_cancelled_create(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        struct callbacks calls = {0};
        struct smb2_pdu *owner;
        uint8_t header[SMB2_SPL_SIZE + SMB2_HEADER_SIZE];
        int pair[2];

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        assert(!fcntl(pair[0], F_SETFL, O_NONBLOCK));
        smb2->fd = pair[0];
        smb2->credits = 32;
        assert(!smb2_connect_tree_id(smb2, 1));
        smb2_set_timeout(smb2, 30);
        owner = smb2_open_async_pdu(smb2, "file", O_RDONLY, completed, &calls, released);
        assert(owner && owner == smb2->waitqueue);
        owner->timeout = time(NULL) - 1;
        smb2_free_pdu(smb2, owner);
        smb2_set_timeout(smb2, 0);
        assert(!smb2_service(smb2, 0) && smb2->waitqueue);
        assert(recv(pair[1], header, sizeof(header), MSG_WAITALL) == sizeof(header));
        memset(header, 0, SMB2_SPL_SIZE);
        header[3] = SMB2_HEADER_SIZE + (SMB2_CREATE_REPLY_SIZE & ~1);
        header[SMB2_SPL_SIZE + 16] = SMB2_FLAGS_SERVER_TO_REDIR;
        assert(write(pair[1], header, sizeof(header)) == sizeof(header));
        assert(!smb2_service(smb2, POLLIN) && smb2->pdu && smb2->pdu->timeout > time(NULL));
        smb2->pdu->timeout = time(NULL) - 1;
        assert(smb2_service(smb2, 0) == -ETIMEDOUT);
        smb2_destroy_context(smb2);
        assert(calls.completed == 0 && calls.released == 1);
        close(pair[1]);
}

static void partial_send_timeout(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        int expired = 0;
        int pair[2];

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
        smb2->fd = pair[0];
        smb2->credits = 0;
        smb2_set_timeout(smb2, 5);
        assert(!smb2_echo_async(smb2, expect_timeout, &expired));
        assert(smb2->outqueue);
        smb2->outqueue->out.num_done = 1;
        smb2->outqueue->timeout = time(NULL) - 1;
        assert(smb2_service(smb2, 0) == -ETIMEDOUT);
        assert(!SMB2_VALID_SOCKET(smb2_get_fd(smb2)));
        smb2_destroy_context(smb2);
        assert(expired == 1);
        close(pair[1]);
}

int main(void)
{
        int pair[2];
        struct smb2_context *smb2 = smb2_init_context();
        struct smb2_pdu *owner;

        assert(smb2_open(NULL, "missing", O_RDONLY) == NULL);
        assert(smb2_opendir(NULL, "") == NULL);
        assert(smb2);
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
                return 1;
        }
        smb2->fd = pair[0];
        smb2->credits = 32;
        assert(smb2_connect_tree_id(smb2, 1) == 0);
        assert(smb2_connect_tree_id(smb2, 2) == 0);
        smb2_set_error(smb2, "previous error");
        assert(smb2_fsync_async(smb2, NULL, NULL, NULL) == -EINVAL);
        assert(strstr(smb2_get_error(smb2), "File handle was NULL"));
        cancel_directory(smb2, SMB2_CREATE);
        cancel_directory(smb2, SMB2_QUERY_DIRECTORY);
        cancel_directory(smb2, SMB2_CLOSE);
        directory_query_failure(smb2);
        cancel_symlink_retry(smb2, RETRY_QUEUED);
        cancel_symlink_retry(smb2, RETRY_SENT);
        cancel_symlink_retry(smb2, LINK_WALK_ERROR);
        assert(smb2_select_tree_id(smb2, 1) == 0);
        owner = smb2_open_async_pdu(smb2, "missing", O_RDONLY,
                                    release_on_completion, &owner, NULL);
        assert(owner);
        reply(smb2, SMB2_CREATE, SMB2_STATUS_OBJECT_NAME_NOT_FOUND, NULL);
        assert(owner == NULL && smb2->fhs == NULL);
        timeout_batch(smb2);
        copy_across_tree_switch(smb2);
        seek_during_positioned_io(smb2);
        close_after_positioned_io(smb2);
        reject_first_io(smb2, 0);
        reject_first_io(smb2, 1);
        nonread_eof(smb2);
        mixed_io_timeouts();
        promoted_io_timeout(smb2);
        close_waiting_for_credit(smb2);
        directory_close_waiting_for_credit(smb2);
        for (int owned = 0; owned <= 2; owned++) {
                char sent[4096];
                while (recv(pair[1], sent, sizeof(sent), MSG_DONTWAIT) > 0) {
                }
                late_open(smb2, 0, owned);
                late_open(smb2, 1, owned);
        }
        deferred_io_timeout(smb2, 0);
        deferred_io_timeout(smb2, 1);
        flush_after_tree_switch(smb2);
        timeout_during_sync_wait(smb2);
        disconnect_during_copy(smb2, pair[1]);
        smb2_destroy_context(smb2);
        close(pair[1]);
        sync_buffers_after_failed_wait();
        sync_stat_after_failed_wait();
        missing_create_reply();
        missing_close_credit();
        partial_cancelled_create();
        partial_unmatched_reply(0);
        partial_unmatched_reply(1);
        partial_send_timeout();
        partial_reply_timeout(0);
        partial_reply_timeout(1);
        release_from_cancel();
        release_with_queued_truncate();
        release_from_completion(0);
        release_from_completion(1);
        return 0;
}
