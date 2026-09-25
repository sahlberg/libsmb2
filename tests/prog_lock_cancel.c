/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Regression test for smb2_cmd_cancel_async() against a blocking
 * byte-range LOCK request, independent of the CHANGE_NOTIFY scenarios in
 * test_0320_cancel_change_notify.sh / prog_notify_cancel.c.
 *
 * Opens the same file on two handles. The first takes an exclusive lock
 * on a byte range (with SMB2_LOCKFLAG_FAIL_IMMEDIATELY, so acquiring it
 * cannot itself block). The second then requests a conflicting exclusive
 * lock on the same range, without FAIL_IMMEDIATELY, which any compliant
 * SMB2 server queues -- goes pending -- rather than failing right away,
 * since the range is already locked by the first handle.
 *
 * That queued LOCK is then cancelled via smb2_cmd_cancel_async(),
 * identified by its own MessageId, and must come back with
 * STATUS_CANCELLED, exactly like the CHANGE_NOTIFY case, but exercising
 * a completely different SMB2 command family -- broadening confidence
 * beyond notify-specific server quirks.
 *
 * Note: MS-SMB2 2.2.26.1's lock element flag bits (SHARED_LOCK,
 * EXCLUSIVE_LOCK, UNLOCK, FAIL_IMMEDIATELY) are not exposed by
 * include/smb2/smb2.h, so this test defines the ones it needs locally.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

/* MS-SMB2 2.2.26.1 SMB2_LOCK_ELEMENT Flags. */
#define TEST_SMB2_LOCKFLAG_SHARED_LOCK         0x00000001
#define TEST_SMB2_LOCKFLAG_EXCLUSIVE_LOCK      0x00000002
#define TEST_SMB2_LOCKFLAG_UNLOCK              0x00000004
#define TEST_SMB2_LOCKFLAG_FAIL_IMMEDIATELY    0x00000010

#define LOCK_RANGE_OFFSET 0
#define LOCK_RANGE_LENGTH 1

/* Bail out rather than hang forever if the server never answers the
 * cancel or the blocking lock. */
#define DEADLINE_SECONDS 15

struct result {
        int done;
        uint32_t status;
};

static void lock_cb(struct smb2_context *smb2 _U_, int status,
                    void *command_data _U_, void *private_data)
{
        struct result *res = private_data;

        res->status = (uint32_t)status;
        res->done = 1;
}

static void cancel_cb(struct smb2_context *smb2 _U_, int status,
                      void *command_data _U_, void *private_data)
{
        struct result *res = private_data;

        res->status = (uint32_t)status;
        res->done = 1;
}

/*
 * Build (but not queue) a LOCK pdu for a single element covering
 * LOCK_RANGE_OFFSET/LOCK_RANGE_LENGTH on fh, with the given flags.
 */
static struct smb2_pdu *
build_lock_pdu(struct smb2_context *smb2, struct smb2fh *fh, uint32_t flags,
              smb2_command_cb cb, void *cb_data)
{
        struct smb2_lock_request req;
        struct smb2_lock_element el;

        memset(&el, 0, sizeof(el));
        el.offset = LOCK_RANGE_OFFSET;
        el.length = LOCK_RANGE_LENGTH;
        el.flags = flags;

        memset(&req, 0, sizeof(req));
        req.lock_count = 1;
        memcpy(req.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);
        req.locks = &el;

        return smb2_cmd_lock_async(smb2, &req, cb, cb_data);
}

/*
 * Service the connection until res->done, or DEADLINE_SECONDS elapse.
 */
static int wait_for(struct smb2_context *smb2, struct result *res)
{
        time_t deadline = time(NULL) + DEADLINE_SECONDS;

        while (!res->done) {
                struct pollfd pfd;

                if (time(NULL) >= deadline) {
                        fprintf(stderr, "Timed out waiting for a reply\n");
                        return -1;
                }

                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);

                if (poll(&pfd, 1, 1000) < 0) {
                        fprintf(stderr, "Poll failed\n");
                        return -1;
                }
                if (pfd.revents == 0) {
                        continue;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        fprintf(stderr, "smb2_service failed with: %s\n",
                                smb2_get_error(smb2));
                        return -1;
                }
        }

        return 0;
}

/*
 * Build and queue the CANCEL request, then service the connection until
 * both it and the LOCK it targets have completed.
 *
 * smb2_cmd_cancel_async() only finds a target that is already on the
 * library's internal wait queue, which a pdu joins once it has actually
 * been written out -- not merely queued. Since this test program has no
 * way to observe that transition from outside the library, it just
 * retries building the CANCEL pdu on every iteration of the event loop
 * until it succeeds.
 */
static int cancel_and_wait(struct smb2_context *smb2, uint64_t msg_id,
                           struct result *lock_res, struct result *cancel_res)
{
        time_t deadline = time(NULL) + DEADLINE_SECONDS;
        int cancel_sent = 0;

        while (!lock_res->done || !cancel_res->done) {
                struct pollfd pfd;

                if (!cancel_sent) {
                        struct smb2_pdu *cancel_pdu = smb2_cmd_cancel_async(
                                smb2, msg_id, cancel_cb, cancel_res);
                        if (cancel_pdu != NULL) {
                                smb2_queue_pdu(smb2, cancel_pdu);
                                cancel_sent = 1;
                        }
                }

                if (time(NULL) >= deadline) {
                        fprintf(stderr, "Timed out waiting for the cancel "
                                "and/or the cancelled LOCK\n");
                        return -1;
                }

                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);

                if (poll(&pfd, 1, 1000) < 0) {
                        fprintf(stderr, "Poll failed\n");
                        return -1;
                }
                if (pfd.revents == 0) {
                        continue;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        fprintf(stderr, "smb2_service failed with: %s\n",
                                smb2_get_error(smb2));
                        return -1;
                }
        }

        if (!cancel_sent) {
                fprintf(stderr, "LOCK completed before the CANCEL could "
                        "be sent\n");
                return -1;
        }

        return 0;
}

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "prog_lock_cancel <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>/<path>\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2fh *fh_a = NULL, *fh_b = NULL;
        struct smb2_pdu *pdu;
        struct result acquire_res, lock_res, cancel_res;
        uint64_t msg_id;
        int rc = 1;

        if (argc < 2) {
                usage();
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                exit(1);
        }

        url = smb2_parse_url(smb2, argv[1]);
        if (url == NULL || url->path == NULL) {
                fprintf(stderr, "Failed to parse url (need a share and a "
                        "path): %s\n", smb2_get_error(smb2));
                exit(1);
        }

        if (url->user) {
                smb2_set_user(smb2, url->user);
        }
        if (url->domain) {
                smb2_set_domain(smb2, url->domain);
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (smb2_connect_share(smb2, url->server, url->share, url->user) != 0) {
                printf("smb2_connect_share failed. %s\n", smb2_get_error(smb2));
                goto out;
        }

        fh_a = smb2_open(smb2, url->path, O_RDWR);
        if (fh_a == NULL) {
                printf("Failed to open %s (handle A). %s\n", url->path,
                       smb2_get_error(smb2));
                goto out;
        }
        fh_b = smb2_open(smb2, url->path, O_RDWR);
        if (fh_b == NULL) {
                printf("Failed to open %s (handle B). %s\n", url->path,
                       smb2_get_error(smb2));
                goto out;
        }

        /*
         * Handle A grabs the range first. FAIL_IMMEDIATELY here means
         * this can only succeed or fail outright, never block, since
         * nothing else holds the range yet.
         */
        memset(&acquire_res, 0, sizeof(acquire_res));
        pdu = build_lock_pdu(smb2, fh_a,
                             TEST_SMB2_LOCKFLAG_EXCLUSIVE_LOCK |
                             TEST_SMB2_LOCKFLAG_FAIL_IMMEDIATELY,
                             lock_cb, &acquire_res);
        if (pdu == NULL) {
                printf("Failed to build the first LOCK. %s\n",
                       smb2_get_error(smb2));
                goto out;
        }
        smb2_queue_pdu(smb2, pdu);
        if (wait_for(smb2, &acquire_res) < 0) {
                goto out;
        }
        if (acquire_res.status != SMB2_STATUS_SUCCESS) {
                printf("First LOCK failed with status 0x%08x, expected "
                       "success\n", acquire_res.status);
                goto out;
        }

        /*
         * Handle B now asks for the same, already-locked range without
         * FAIL_IMMEDIATELY, so the server queues it instead of failing
         * it outright with STATUS_LOCK_NOT_GRANTED.
         */
        memset(&lock_res, 0, sizeof(lock_res));
        memset(&cancel_res, 0, sizeof(cancel_res));
        pdu = build_lock_pdu(smb2, fh_b, TEST_SMB2_LOCKFLAG_EXCLUSIVE_LOCK,
                             lock_cb, &lock_res);
        if (pdu == NULL) {
                printf("Failed to build the second (blocking) LOCK. %s\n",
                       smb2_get_error(smb2));
                goto out;
        }
        smb2_queue_pdu(smb2, pdu);
        msg_id = smb2_get_pdu_message_id(smb2, pdu);

        if (cancel_and_wait(smb2, msg_id, &lock_res, &cancel_res) < 0) {
                goto out;
        }

        if (cancel_res.status != SMB2_STATUS_SUCCESS) {
                printf("CANCEL callback reported status 0x%08x, expected "
                       "success\n", cancel_res.status);
                goto out;
        }
        if (lock_res.status != SMB2_STATUS_CANCELLED) {
                printf("Blocking LOCK finished with status 0x%08x, "
                       "expected STATUS_CANCELLED (0x%08x)\n",
                       lock_res.status, SMB2_STATUS_CANCELLED);
                goto out;
        }

        rc = 0;

 out:
        /*
         * Closing a handle releases any byte-range locks it still
         * holds, so no explicit UNLOCK is needed for handle A's grant.
         */
        if (fh_a) {
                smb2_close(smb2, fh_a);
        }
        if (fh_b) {
                smb2_close(smb2, fh_b);
        }
        smb2_disconnect_share(smb2);
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);

        return rc;
}
