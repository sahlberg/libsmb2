/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#include <errno.h>

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "compat.h"

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <stdio.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

static int sync_in_service(struct smb2_context *smb2)
{
        if (smb2_is_dispatching(smb2)) {
                /* Preserve the dispatch error and avoid reentering its error callback. */
                errno = EDEADLK;
                return 1;
        }
        return 0;
}

static void *alloc_sync_cb_data(struct smb2_context *smb2, size_t size)
{
        void *data = calloc(1, size);

        if (!data) {
                smb2_set_error(smb2, "Failed to allocate sync_cb_data");
                errno = ENOMEM;
        }
        return data;
}

static struct sync_cb_data *new_sync_cb_data(struct smb2_context *smb2)
{
        if (sync_in_service(smb2)) {
                return NULL;
        }
        return alloc_sync_cb_data(smb2, sizeof(struct sync_cb_data));
}

static int wait_for_reply(struct smb2_context *smb2,
                          struct sync_cb_data *cb_data)
{
        time_t t = time(NULL);

        while (!cb_data->is_finished) {
                struct pollfd pfd;
                int rc;

                if (smb2->lifetime != SMB2_CONTEXT_LIVE) {
                        return -ECANCELED;
                }
		memset(&pfd, 0, sizeof(struct pollfd));
		pfd.fd = smb2_get_fd(smb2);
		pfd.events = smb2_which_events(smb2);

		if (poll(&pfd, 1, 1000) < 0) {
			if (errno != EINTR) {
				smb2_set_error(smb2, "Poll failed");
				return -1;
			}
			/* Interrupted by a signal: carry on, the
			 * timeouts are still checked below. */
			pfd.revents = 0;
		}
                rc = smb2_timeout_pdus(smb2);
                if (cb_data->is_finished) {
                        break;
                }
                if (rc < 0) {
                        return rc;
                }
		if (!SMB2_VALID_SOCKET(smb2->fd) && ((time(NULL) - t) > (smb2->timeout)))
		{
			smb2_set_error(smb2, "Timeout expired and no connection exists\n");
			return -1;
		}
                if (pfd.revents == 0) {
                        continue;
                }
		rc = smb2_service(smb2, pfd.revents);
		if (rc < 0) {
                        /*
                         * Our reply was processed before the error: the
                         * call completed, so return its result. The
                         * connection error shows up on the next call.
                         */
                        if (cb_data->is_finished) {
                                break;
                        }
                        if (rc == -ETIMEDOUT) {
                                return rc;
                        }
			smb2_set_error(smb2, "smb2_service failed with : "
                                        "%s\n", smb2_get_error(smb2));
                        return -1;
		}
	}

        return 0;
}

static void sync_generic_status_cb(struct smb2_context *smb2, int status,
                       void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        if (cb_data->status == SMB2_STATUS_CANCELLED) {
                free(cb_data);
                return;
        }

        cb_data->is_finished = 1;
        cb_data->status = status;
}

static int finish_sync_status(struct smb2_context *smb2,
                              struct sync_cb_data *data, int rc)
{
        if (rc >= 0) {
                rc = wait_for_reply(smb2, data);
                if (rc < 0 && !data->is_finished) {
                        data->status = SMB2_STATUS_CANCELLED;
                        return rc;
                }
                if (rc == 0) {
                        rc = data->status;
                }
        }
        free(data);
        return rc;
}

/*
 * Connect to the server and mount the share.
 */
int smb2_connect_share(struct smb2_context *smb2,
                       const char *server,
                       const char *share,
                       const char *user)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }
	rc = smb2_connect_share_async(smb2, server, share, user, sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

/*
 * Disconnect from share
 */
int smb2_disconnect_share(struct smb2_context *smb2)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

	rc = smb2_disconnect_share_async(smb2, sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

/*
 * opendir()
 */
static void sync_open_cb(struct smb2_context *smb2, int status,
                         void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->ptr = command_data;
}

static void *
finish_sync_open(struct smb2_context *smb2, struct smb2_pdu *pdu,
                 struct sync_cb_data *cb_data)
{
        if (pdu) {
                wait_for_reply(smb2, cb_data);
                smb2_free_pdu(smb2, pdu);
        }
        if (smb2->lifetime != SMB2_CONTEXT_LIVE) {
                cb_data->ptr = NULL;
        }
        smb2->sync_open_wait--;
        smb2_finish_dispatch(smb2);
        return cb_data->ptr;
}

struct smb2dir *smb2_opendir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data = {0};
        struct smb2_pdu *pdu;

        if (smb2 == NULL || sync_in_service(smb2)) {
                return NULL;
        }
        smb2->sync_open_wait++;
        pdu = smb2_opendir_async_pdu(smb2, path, sync_open_cb, &cb_data, NULL);
        return finish_sync_open(smb2, pdu, &cb_data);
}

struct smb2fh *smb2_open(struct smb2_context *smb2, const char *path, int flags)
{
        struct sync_cb_data cb_data = {0};
        struct smb2_pdu *pdu;

        if (smb2 == NULL || sync_in_service(smb2)) {
                return NULL;
        }
        smb2->sync_open_wait++;
        pdu = smb2_open_async_pdu(smb2, path, flags, sync_open_cb, &cb_data, NULL);
        return finish_sync_open(smb2, pdu, &cb_data);
}

/*
 * close()
 */
int smb2_close(struct smb2_context *smb2, struct smb2fh *fh)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

	rc = smb2_close_async(smb2, fh, sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

/*
 * fsync()
 */
int smb2_fsync(struct smb2_context *smb2, struct smb2fh *fh)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

	rc = smb2_fsync_async(smb2, fh, sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

/* A failed wait can leave the PDU in flight or behind an earlier file
 * operation. Its buffer must live until the asynchronous completion. */
static int sync_file_io(struct smb2_context *smb2, struct smb2fh *fh,
                        enum smb2_command command, void *buf, uint32_t count,
                        const uint64_t *position)
{
        struct sync_cb_data *data;
        uint8_t *buffer;
        int rc;

        if (sync_in_service(smb2)) {
                return -EDEADLK;
        }
        if (!smb2) {
                return -EINVAL;
        }
        if (!fh || (count && !buf)) {
                smb2_set_error(smb2, !fh ? "File handle was NULL" : "Missing buffer for file I/O");
                return -EINVAL;
        }
        count = smb2_file_io_length(smb2, command, count);
        data = malloc(sizeof(*data) + count);
        if (!data) {
                smb2_set_error(smb2, "Failed to allocate synchronous I/O buffer");
                return -ENOMEM;
        }
        memset(data, 0, sizeof(*data));
        buffer = (uint8_t *)(data + 1);
        if (command == SMB2_WRITE && count) {
                memcpy(buffer, buf, count);
        }
        rc = smb2_start_file_io(smb2, fh, command, buffer, count,
                                position ? *position : 0, position != NULL,
                                sync_generic_status_cb, data);
        if (rc == 0) {
                rc = wait_for_reply(smb2, data);
                if (rc < 0 && !data->is_finished) {
                        data->status = SMB2_STATUS_CANCELLED;
                        return rc;
                }
                rc = data->status;
                if (command == SMB2_READ && rc > 0) {
                        memcpy(buf, buffer, rc);
                }
        }
        free(data);
        return rc;
}

int smb2_pread(struct smb2_context *smb2, struct smb2fh *fh,
               uint8_t *buf, uint32_t count, uint64_t offset)
{
        return sync_file_io(smb2, fh, SMB2_READ, buf, count, &offset);
}

int smb2_pwrite(struct smb2_context *smb2, struct smb2fh *fh,
                const uint8_t *buf, uint32_t count, uint64_t offset)
{
        return sync_file_io(smb2, fh, SMB2_WRITE, discard_const(buf), count, &offset);
}

int smb2_read(struct smb2_context *smb2, struct smb2fh *fh,
              uint8_t *buf, uint32_t count)
{
        return sync_file_io(smb2, fh, SMB2_READ, buf, count, NULL);
}

int smb2_write(struct smb2_context *smb2, struct smb2fh *fh,
               const uint8_t *buf, uint32_t count)
{
        return sync_file_io(smb2, fh, SMB2_WRITE, discard_const(buf), count, NULL);
}

int smb2_unlink(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

	rc = smb2_unlink_async(smb2, path,
                               sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

int smb2_rmdir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

	rc = smb2_rmdir_async(smb2, path,
                              sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

int smb2_mkdir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

	rc = smb2_mkdir_async(smb2, path,
                              sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

/*
 * The reply can still arrive after wait_for_reply() fails, so the result
 * lives next to cb_data. cb must be first: sync_generic_status_cb() frees it.
 */
struct sync_stat_cb_data {
        struct sync_cb_data cb;
        struct smb2_stat_64 st;
};

int smb2_fstat(struct smb2_context *smb2, struct smb2fh *fh,
               struct smb2_stat_64 *st)
{
        struct sync_stat_cb_data *cb_data;
        int rc = 0;

        if (sync_in_service(smb2)) {
                return -EDEADLK;
        }
        if (!st) {
                return -EINVAL;
        }
        cb_data = calloc(1, sizeof(struct sync_stat_cb_data));
        if (cb_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate sync_cb_data");
                return -ENOMEM;
        }
        cb_data->st = *st;

	rc = smb2_fstat_async(smb2, fh, &cb_data->st,
                              sync_generic_status_cb, &cb_data->cb);
        if (rc < 0) {
                goto out;
	}

	rc = wait_for_reply(smb2, &cb_data->cb);
        if (rc < 0 && !cb_data->cb.is_finished) {
                cb_data->cb.status = SMB2_STATUS_CANCELLED;
                return rc;
	}

        rc = cb_data->cb.status;
        *st = cb_data->st;
 out:
        free(cb_data);

	return rc;
}

int smb2_stat(struct smb2_context *smb2, const char *path,
              struct smb2_stat_64 *st)
{
        struct sync_stat_cb_data *cb_data;
        int rc = 0;

        if (sync_in_service(smb2)) {
                return -EDEADLK;
        }
        if (!st) {
                return -EINVAL;
        }
        cb_data = calloc(1, sizeof(struct sync_stat_cb_data));
        if (cb_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate sync_cb_data");
                return -ENOMEM;
        }
        cb_data->st = *st;

	rc = smb2_stat_async(smb2, path, &cb_data->st,
                             sync_generic_status_cb, &cb_data->cb);
        if (rc < 0) {
                goto out;
	}

	rc = wait_for_reply(smb2, &cb_data->cb);
        if (rc < 0 && !cb_data->cb.is_finished) {
                cb_data->cb.status = SMB2_STATUS_CANCELLED;
                return rc;
	}

        rc = cb_data->cb.status;
        *st = cb_data->st;
 out:
        free(cb_data);

	return rc;
}

int smb2_rename(struct smb2_context *smb2, const char *oldpath,
                const char *newpath)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

	rc = smb2_rename_async(smb2, oldpath, newpath,
                               sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

int smb2_symlink(struct smb2_context *smb2, const char *target,
                 const char *linkpath, uint32_t flags)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

        rc = smb2_symlink_async(smb2, target, linkpath, flags,
                                sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

int smb2_link(struct smb2_context *smb2, const char *oldpath,
                const char *newpath)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

	rc = smb2_link_async(smb2, oldpath, newpath,
                               sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

struct sync_statvfs_cb_data {
        struct sync_cb_data cb;
        struct smb2_statvfs st;
};

int smb2_statvfs(struct smb2_context *smb2, const char *path,
                 struct smb2_statvfs *st)
{
        struct sync_statvfs_cb_data *cb_data;
        int rc = 0;

        if (sync_in_service(smb2)) {
                return -EDEADLK;
        }
        if (!st) {
                return -EINVAL;
        }
        cb_data = calloc(1, sizeof(struct sync_statvfs_cb_data));
        if (cb_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate sync_cb_data");
                return -ENOMEM;
        }
        cb_data->st = *st;

	rc = smb2_statvfs_async(smb2, path, &cb_data->st,
                                sync_generic_status_cb, &cb_data->cb);
        if (rc < 0) {
                goto out;
	}

	rc = wait_for_reply(smb2, &cb_data->cb);
        if (rc < 0 && !cb_data->cb.is_finished) {
                cb_data->cb.status = SMB2_STATUS_CANCELLED;
                return rc;
	}

        rc = cb_data->cb.status;
        *st = cb_data->st;
 out:
        free(cb_data);

	return rc;
}

int smb2_truncate(struct smb2_context *smb2, const char *path,
                  uint64_t length)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

	rc = smb2_truncate_async(smb2, path, length,
                                 sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

int smb2_ftruncate(struct smb2_context *smb2, struct smb2fh *fh,
                   uint64_t length)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

	rc = smb2_ftruncate_async(smb2, fh, length,
                                  sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

struct sync_readlink_cb_data {
	char *buf;
        int len;
};

static void readlink_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;
        struct sync_readlink_cb_data *rl_data = cb_data->ptr;

        if (cb_data->status == SMB2_STATUS_CANCELLED) {
                free(cb_data);
                return;
        }

        cb_data->is_finished = 1;
        cb_data->status = status;

        /* There is no target to report unless the call succeeded. */
        if (status || command_data == NULL || rl_data->len <= 0) {
                return;
        }
        strncpy(rl_data->buf, command_data, rl_data->len);
        rl_data->buf[rl_data->len - 1] = 0;
}

int smb2_readlink(struct smb2_context *smb2, const char *path,
                  char *buf, uint32_t len)
{
        struct sync_cb_data *cb_data;
        struct sync_readlink_cb_data rl_data _U_;
        int rc = 0;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

        rl_data.buf = buf;
        rl_data.len = len;

        cb_data->ptr = &rl_data;

	rc = smb2_readlink_async(smb2, path, readlink_cb, cb_data);
        if (rc < 0) {
                goto out;
	}

	rc = wait_for_reply(smb2, cb_data);
        if (rc < 0) {
                cb_data->status = SMB2_STATUS_CANCELLED;
                return rc;
	}

        rc = cb_data->status;
 out:
        free(cb_data);

	return rc;
}

static void sync_copy_ioctl_cb(struct smb2_context *smb2, int status,
                               void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        if (cb_data->status == SMB2_STATUS_CANCELLED) {
                smb2_free_data(smb2, command_data);
                free(cb_data);
                return;
        }

        cb_data->is_finished = 1;
        cb_data->status = status;
        cb_data->ptr = command_data;
}

int smb2_request_resume_key(struct smb2_context *smb2, struct smb2fh *fh,
                            struct smb2_srv_copychunk_resume_key *resume_key)
{
        struct sync_cb_data *cb_data;
        int rc = 0;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

        rc = smb2_request_resume_key_async(smb2, fh, sync_copy_ioctl_cb,
                                           cb_data);
        if (rc < 0) {
                goto out;
        }

        rc = wait_for_reply(smb2, cb_data);
        if (rc < 0) {
                cb_data->status = SMB2_STATUS_CANCELLED;
                return rc;
        }

        rc = cb_data->status;
        if (cb_data->ptr != NULL) {
                if (resume_key != NULL) {
                        memcpy(resume_key, cb_data->ptr, sizeof(*resume_key));
                }
                smb2_free_data(smb2, cb_data->ptr);
        }
 out:
        free(cb_data);

        return rc;
}

int smb2_copychunk(struct smb2_context *smb2,
                   uint32_t ctl_code,
                   const struct smb2_srv_copychunk_resume_key *resume_key,
                   struct smb2fh *dstfh,
                   const struct smb2_srv_copychunk *chunks,
                   uint32_t chunk_count,
                   struct smb2_srv_copychunk_reply *reply)
{
        struct sync_cb_data *cb_data;
        int rc = 0;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

        rc = smb2_copychunk_async(smb2, ctl_code, resume_key, dstfh, chunks,
                                  chunk_count, sync_copy_ioctl_cb, cb_data);
        if (rc < 0) {
                goto out;
        }

        rc = wait_for_reply(smb2, cb_data);
        if (rc < 0) {
                cb_data->status = SMB2_STATUS_CANCELLED;
                return rc;
        }

        rc = cb_data->status;
        if (cb_data->ptr != NULL) {
                if (reply != NULL) {
                        memcpy(reply, cb_data->ptr, sizeof(*reply));
                }
                smb2_free_data(smb2, cb_data->ptr);
                cb_data->ptr = NULL;
        }
 out:
        free(cb_data);

        return rc;
}

int smb2_server_side_copy(struct smb2_context *smb2,
                          uint32_t ctl_code,
                          struct smb2fh *srcfh, struct smb2fh *dstfh,
                          const struct smb2_srv_copychunk *chunks,
                          uint32_t chunk_count,
                          struct smb2_srv_copychunk_reply *reply)
{
        struct sync_cb_data *cb_data;
        int rc = 0;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

        rc = smb2_server_side_copy_async(smb2, ctl_code, srcfh, dstfh,
                                         chunks, chunk_count,
                                         sync_copy_ioctl_cb, cb_data);
        if (rc < 0) {
                goto out;
        }

        rc = wait_for_reply(smb2, cb_data);
        if (rc < 0) {
                cb_data->status = SMB2_STATUS_CANCELLED;
                return rc;
        }

        rc = cb_data->status;
        if (cb_data->ptr != NULL) {
                if (reply != NULL) {
                        memcpy(reply, cb_data->ptr, sizeof(*reply));
                }
                smb2_free_data(smb2, cb_data->ptr);
                cb_data->ptr = NULL;
        }
 out:
        free(cb_data);

        return rc;
}

/*
 * Send SMB2_ECHO command to the server
 */
int smb2_echo(struct smb2_context *smb2)
{
        struct sync_cb_data *cb_data;
        int rc;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return -errno;
        }

        if (!SMB2_VALID_SOCKET(smb2->fd)) {
                free(cb_data);
                smb2_set_error(smb2, "Not Connected to Server");
                return -ENOMEM;
        }

        rc = smb2_echo_async(smb2, sync_generic_status_cb, cb_data);
        return finish_sync_status(smb2, cb_data, rc);
}

static void sync_notify_change_cb(struct smb2_context *smb2, int status,
                       void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        if (cb_data->status == SMB2_STATUS_CANCELLED) {
                if (command_data) {
                        free_smb2_file_notify_change_information(smb2,
                                                                 command_data);
                }
                free(cb_data);
                return;
        }

        cb_data->is_finished = 1;
        cb_data->ptr = command_data;
}


/**
 * One-off sync command for getting notify change response
 */
struct smb2_file_notify_change_information *smb2_notify_change(struct smb2_context *smb2, const char *path, uint16_t flags, uint32_t filter)
{
        struct sync_cb_data *cb_data;
        void *ptr;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return NULL;
        }

	if (smb2_notify_change_async(smb2, path, flags, filter, 0,
                               sync_notify_change_cb, cb_data) != 0) {
		smb2_set_error(smb2, "smb2_notify_change failed");
                free(cb_data);
		return NULL;
	}

	if (wait_for_reply(smb2, cb_data) < 0) {
                cb_data->status = SMB2_STATUS_CANCELLED;
                return NULL;
        }

	ptr = cb_data->ptr;
        free(cb_data);
        return ptr;
}

static void sync_share_enum_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        if (cb_data->status == SMB2_STATUS_CANCELLED) {
                if (command_data) {
                        smb2_free_data(smb2, command_data);
                }
                free(cb_data);
                return;
        }

        cb_data->is_finished = 1;
        cb_data->status = status;
        cb_data->ptr = command_data;
}

/*
 * Send SRVSVC ShareEnum call to the server
 */
struct smb2_share_enum_reply *
smb2_share_enum_sync(struct smb2_context *smb2,
                     enum smb2_share_info_level level)
{
        struct smb2_share_enum_reply *rep = NULL;
        struct sync_cb_data *cb_data;
        int rc = 0;

        cb_data = new_sync_cb_data(smb2);
        if (cb_data == NULL) {
                return NULL;
        }

        if (!SMB2_VALID_SOCKET(smb2->fd)) {
                free(cb_data);
                smb2_set_error(smb2, "Not Connected to Server");
                return NULL;
        }

        rc = smb2_share_enum_async(smb2, level, sync_share_enum_cb, cb_data);
        if (rc < 0) {
                goto out;
	}

	rc = wait_for_reply(smb2, cb_data);
        if (rc < 0) {
                cb_data->status = SMB2_STATUS_CANCELLED;
                return NULL;
	}

        rep = cb_data->ptr;
        if (cb_data->status != 0) {
                /* a WERROR from the server still comes with a reply */
                if (rep != NULL) {
                        smb2_set_error(smb2, "NetrShareEnum failed with "
                                       "WERROR 0x%08x", cb_data->status);
                        smb2_free_data(smb2, rep);
                }
                rep = NULL;
        }

 out:
        free(cb_data);

	return rep;
}
