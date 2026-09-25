/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Regression test for smb2_cmd_cancel_async().
 *
 * Starts a CHANGE_NOTIFY watch on the root of the share -- an operation
 * that any real SMB2 server holds open until something changes, since
 * nothing else in this test touches the share -- and sends an SMB2
 * CANCEL request for it via smb2_cmd_cancel_async(), identified by the
 * notify's own MessageId (smb2_get_pdu_message_id()).
 *
 * There is no reply to a CANCEL request, so its own callback must fire
 * locally as soon as it has been sent. The original CHANGE_NOTIFY must
 * then come back with STATUS_CANCELLED, proving the server actually
 * stopped waiting instead of the test just hanging until some unrelated
 * timeout. Unlike test_0311_open_timeout.sh this needs no special/broken
 * server: any compliant SMB2 server supports cancelling a pending
 * CHANGE_NOTIFY.
 *
 * This is exercised twice, on the same directory handle: once cancelling
 * the notify as soon as it can be (before the server has necessarily even
 * looked at it), and once giving it a second to genuinely sit pending
 * first -- which is also long enough for an interim STATUS_PENDING
 * response, if the server sends one, to be recorded onto it, so the
 * second run may exercise the AsyncId branch of smb2_cmd_cancel_async()
 * rather than the plain-MessageId one.
 *
 * A third, negative scenario checks that smb2_cmd_cancel_async() refuses
 * to build a CANCEL for a MessageId that does not correspond to any
 * outstanding request, rather than silently sending one.
 *
 * A fourth scenario starts two independent watches (on two separate
 * handles), sends exactly one CANCEL for the first, and checks the
 * second is left completely alone -- cancel must target exactly the
 * MessageId it was given, nothing else that happens to be outstanding
 * at the same time.
 *
 * A fifth scenario cancels a CHANGE_NOTIFY normally, then immediately
 * reuses that same, now-stale MessageId for a second CANCEL. Unlike the
 * third scenario's MessageId, which never existed at all, this one was
 * genuinely valid a moment ago; once its pdu has completed and left the
 * wait queue, smb2_cmd_cancel_async() must reject it exactly the same
 * way -- a request cannot be cancelled twice just because its old
 * MessageId is still known to the caller.
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

/* Bail out rather than hang forever if the server never answers the
 * cancel or the notify. */
#define DEADLINE_SECONDS 15

struct result {
        int done;
        uint32_t status;
};

static void notify_cb(struct smb2_context *smb2 _U_, int status,
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
 * Build and queue the CANCEL request, then service the connection until
 * both it and the CHANGE_NOTIFY it targets have completed.
 *
 * smb2_cmd_cancel_async() only finds a target that is already on the
 * library's internal wait queue, which a pdu joins once it has actually
 * been written out -- not merely queued. Since this test program has no
 * way to observe that transition from outside the library, it just
 * retries building the CANCEL pdu on every iteration of the event loop
 * until it succeeds.
 */
static int run(struct smb2_context *smb2, uint64_t msg_id,
               struct result *notify_res, struct result *cancel_res)
{
        time_t deadline = time(NULL) + DEADLINE_SECONDS;
        int cancel_sent = 0;

        while (!notify_res->done || !cancel_res->done) {
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
                                "and/or the cancelled CHANGE_NOTIFY\n");
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
                fprintf(stderr, "CHANGE_NOTIFY completed before the CANCEL "
                        "could be sent\n");
                return -1;
        }

        return 0;
}

/*
 * Just service the connection for a while without cancelling anything,
 * so the CHANGE_NOTIFY genuinely sits pending on the server rather than
 * being cancelled the moment it goes out.
 */
static int settle(struct smb2_context *smb2, struct result *notify_res,
                  int seconds)
{
        time_t deadline = time(NULL) + seconds;

        while (time(NULL) < deadline) {
                struct pollfd pfd;

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
                if (notify_res->done) {
                        fprintf(stderr, "CHANGE_NOTIFY completed on its "
                                "own before it could be cancelled -- did "
                                "something else touch the share?\n");
                        return -1;
                }
        }

        return 0;
}

/*
 * Build, queue and return a CHANGE_NOTIFY pdu on dir_fh, and fetch its
 * MessageId (only assigned once the pdu is queued, so this has to
 * happen after smb2_queue_pdu(), not before).
 */
static struct smb2_pdu *
start_notify(struct smb2_context *smb2, struct smb2fh *dir_fh,
            struct result *notify_res, uint64_t *msg_id)
{
        struct smb2_change_notify_request cn_req;
        struct smb2_pdu *notify_pdu;

        memset(&cn_req, 0, sizeof(cn_req));
        cn_req.flags = 0;
        cn_req.output_buffer_length = 4096;
        memcpy(cn_req.file_id, smb2_get_file_id(dir_fh), SMB2_FD_SIZE);
        cn_req.completion_filter = SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME;

        notify_pdu = smb2_cmd_change_notify_async(smb2, &cn_req,
                                                  notify_cb, notify_res);
        if (notify_pdu == NULL) {
                return NULL;
        }
        smb2_queue_pdu(smb2, notify_pdu);
        *msg_id = smb2_get_pdu_message_id(smb2, notify_pdu);

        return notify_pdu;
}

/*
 * Start a CHANGE_NOTIFY on dir_fh, optionally let it sit pending for
 * settle_seconds, then cancel it and check both the CANCEL and the
 * cancelled CHANGE_NOTIFY came back the way they should.
 */
static int run_scenario(struct smb2_context *smb2, struct smb2fh *dir_fh,
                        int settle_seconds, const char *label)
{
        struct result notify_res, cancel_res;
        uint64_t msg_id;

        printf("Scenario: %s\n", label);

        memset(&notify_res, 0, sizeof(notify_res));
        memset(&cancel_res, 0, sizeof(cancel_res));

        if (start_notify(smb2, dir_fh, &notify_res, &msg_id) == NULL) {
                printf("[%s] Failed to build CHANGE_NOTIFY. %s\n",
                       label, smb2_get_error(smb2));
                return -1;
        }

        if (settle_seconds > 0) {
                if (settle(smb2, &notify_res, settle_seconds) < 0) {
                        return -1;
                }
        }

        if (run(smb2, msg_id, &notify_res, &cancel_res) < 0) {
                return -1;
        }

        if (cancel_res.status != SMB2_STATUS_SUCCESS) {
                printf("[%s] CANCEL callback reported status 0x%08x, "
                       "expected success\n", label, cancel_res.status);
                return -1;
        }
        if (notify_res.status != SMB2_STATUS_CANCELLED) {
                printf("[%s] CHANGE_NOTIFY finished with status 0x%08x, "
                       "expected STATUS_CANCELLED (0x%08x)\n",
                       label, notify_res.status, SMB2_STATUS_CANCELLED);
                return -1;
        }

        return 0;
}

/*
 * Negative test: smb2_cmd_cancel_async() must refuse to build a CANCEL
 * for a MessageId that does not correspond to any outstanding request,
 * rather than silently sending one for it.
 *
 * This never touches the wire: smb2_cmd_cancel_async() looks msg_id up
 * on the library's internal wait queue first and returns NULL right
 * there when it isn't found, before a CANCEL pdu is ever allocated,
 * encoded or queued. Do not expect to see a CANCEL packet for this
 * scenario in a packet capture -- there isn't one to see.
 */
static int run_scenario_invalid_msg_id(struct smb2_context *smb2)
{
        struct result cancel_res;
        struct smb2_pdu *cancel_pdu;
        uint64_t bogus_msg_id = 0x7fffffffffffffffULL;

        printf("Scenario: cancel sent for a non-existent MessageId "
               "(negative test, rejected locally -- no packet is sent)\n");

        memset(&cancel_res, 0, sizeof(cancel_res));

        cancel_pdu = smb2_cmd_cancel_async(smb2, bogus_msg_id, cancel_cb,
                                           &cancel_res);
        if (cancel_pdu != NULL) {
                printf("[invalid] smb2_cmd_cancel_async() unexpectedly "
                       "built a CANCEL for a MessageId with no "
                       "outstanding request\n");
                smb2_free_pdu(smb2, cancel_pdu);
                return -1;
        }
        if (cancel_res.done) {
                printf("[invalid] cancel callback fired even though "
                       "smb2_cmd_cancel_async() returned NULL\n");
                return -1;
        }

        return 0;
}

/*
 * Start two independent CHANGE_NOTIFY watches (on two separate handles),
 * send exactly one CANCEL -- for the first -- and check the second is
 * left running untouched.
 *
 * The second watch is deliberately never cancelled: the whole point is
 * for it to still be outstanding when that check runs. It ends up being
 * completed later by the library itself, with SMB2_STATUS_SHUTDOWN, when
 * the leftover wait queue is torn down in smb2_destroy_context() -- so
 * its result has to be heap-allocated rather than a local, since its
 * callback can still fire after this function has returned. That one
 * small allocation is deliberately never freed; the process exits
 * shortly after.
 */
static int run_scenario_targeted_cancel(struct smb2_context *smb2,
                                        struct smb2fh *dir_fh_a,
                                        struct smb2fh *dir_fh_b)
{
        struct result notify_a, cancel_a;
        struct result *notify_b;
        uint64_t msg_id_a, msg_id_b;

        printf("Scenario: cancelling one CHANGE_NOTIFY does not affect "
               "another outstanding one\n");

        memset(&notify_a, 0, sizeof(notify_a));
        memset(&cancel_a, 0, sizeof(cancel_a));

        notify_b = calloc(1, sizeof(*notify_b));
        if (notify_b == NULL) {
                printf("[targeted] Failed to allocate result for the "
                       "second CHANGE_NOTIFY\n");
                return -1;
        }

        if (start_notify(smb2, dir_fh_a, &notify_a, &msg_id_a) == NULL) {
                printf("[targeted] Failed to build first CHANGE_NOTIFY. "
                       "%s\n", smb2_get_error(smb2));
                free(notify_b);
                return -1;
        }
        if (start_notify(smb2, dir_fh_b, notify_b, &msg_id_b) == NULL) {
                printf("[targeted] Failed to build second CHANGE_NOTIFY. "
                       "%s\n", smb2_get_error(smb2));
                free(notify_b);
                return -1;
        }

        /*
         * run() only ever builds a CANCEL for msg_id_a, so the second
         * watch is left completely alone by this call.
         */
        if (run(smb2, msg_id_a, &notify_a, &cancel_a) < 0) {
                return -1;
        }
        if (cancel_a.status != SMB2_STATUS_SUCCESS) {
                printf("[targeted] CANCEL for the first watch reported "
                       "status 0x%08x, expected success\n",
                       cancel_a.status);
                return -1;
        }
        if (notify_a.status != SMB2_STATUS_CANCELLED) {
                printf("[targeted] First CHANGE_NOTIFY finished with "
                       "status 0x%08x, expected STATUS_CANCELLED "
                       "(0x%08x)\n", notify_a.status, SMB2_STATUS_CANCELLED);
                return -1;
        }
        if (notify_b->done) {
                printf("[targeted] Second CHANGE_NOTIFY unexpectedly "
                       "completed while only the first was cancelled\n");
                return -1;
        }

        return 0;
}

/*
 * Cancel a CHANGE_NOTIFY normally, then try to cancel it again by the
 * same MessageId. The first CANCEL retires the pdu -- once completed,
 * it is removed from the wait queue smb2_cmd_cancel_async() looks it up
 * on -- so the second attempt must be refused exactly like the
 * never-existed MessageId in the third scenario: no CANCEL pdu built,
 * no packet sent, no callback fired.
 */
static int run_scenario_cancel_after_completion(struct smb2_context *smb2,
                                                struct smb2fh *dir_fh)
{
        struct result notify_res, cancel_res, stale_cancel_res;
        struct smb2_pdu *stale_cancel_pdu;
        uint64_t msg_id;

        printf("Scenario: cancelling an already-completed CHANGE_NOTIFY "
               "again is refused\n");

        memset(&notify_res, 0, sizeof(notify_res));
        memset(&cancel_res, 0, sizeof(cancel_res));
        memset(&stale_cancel_res, 0, sizeof(stale_cancel_res));

        if (start_notify(smb2, dir_fh, &notify_res, &msg_id) == NULL) {
                printf("[completed] Failed to build CHANGE_NOTIFY. %s\n",
                       smb2_get_error(smb2));
                return -1;
        }

        if (run(smb2, msg_id, &notify_res, &cancel_res) < 0) {
                return -1;
        }
        if (cancel_res.status != SMB2_STATUS_SUCCESS) {
                printf("[completed] CANCEL callback reported status "
                       "0x%08x, expected success\n", cancel_res.status);
                return -1;
        }
        if (notify_res.status != SMB2_STATUS_CANCELLED) {
                printf("[completed] CHANGE_NOTIFY finished with status "
                       "0x%08x, expected STATUS_CANCELLED (0x%08x)\n",
                       notify_res.status, SMB2_STATUS_CANCELLED);
                return -1;
        }

        /*
         * msg_id's pdu is gone now; a second CANCEL for it must be
         * refused just like run_scenario_invalid_msg_id()'s MessageId
         * that never existed at all.
         */
        stale_cancel_pdu = smb2_cmd_cancel_async(smb2, msg_id, cancel_cb,
                                                 &stale_cancel_res);
        if (stale_cancel_pdu != NULL) {
                printf("[completed] smb2_cmd_cancel_async() unexpectedly "
                       "built a second CANCEL for an already-completed "
                       "MessageId\n");
                smb2_free_pdu(smb2, stale_cancel_pdu);
                return -1;
        }
        if (stale_cancel_res.done) {
                printf("[completed] stale cancel callback fired even "
                       "though smb2_cmd_cancel_async() returned NULL\n");
                return -1;
        }

        return 0;
}

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "prog_notify_cancel <smb2-url> "
                "[immediate|delayed|invalid|targeted|completed]\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>\n\n"
                "With no scenario argument, all five are run in turn.\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2fh *dir_fh = NULL, *dir_fh_2 = NULL;
        int run_immediate = 1, run_delayed = 1, run_invalid = 1;
        int run_targeted = 1, run_completed = 1;
        int rc = 1;

        if (argc < 2) {
                usage();
        }
        if (argc > 2) {
                run_immediate = run_delayed = run_invalid = run_targeted = 0;
                run_completed = 0;
                if (!strcmp(argv[2], "immediate")) {
                        run_immediate = 1;
                } else if (!strcmp(argv[2], "delayed")) {
                        run_delayed = 1;
                } else if (!strcmp(argv[2], "invalid")) {
                        run_invalid = 1;
                } else if (!strcmp(argv[2], "targeted")) {
                        run_targeted = 1;
                } else if (!strcmp(argv[2], "completed")) {
                        run_completed = 1;
                } else {
                        usage();
                }
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                exit(1);
        }

        url = smb2_parse_url(smb2, argv[1]);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(smb2));
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

        /*
         * The root of the share is opened with an empty name, not ".";
         * SMB2 servers reject "." as an invalid path component.
         */
#ifdef O_DIRECTORY
        dir_fh = smb2_open(smb2, "", O_DIRECTORY);
        dir_fh_2 = smb2_open(smb2, "", O_DIRECTORY);
#else
        dir_fh = smb2_open(smb2, "", 0);
        dir_fh_2 = smb2_open(smb2, "", 0);
#endif
        if (dir_fh == NULL || dir_fh_2 == NULL) {
                printf("Failed to open share root. %s\n", smb2_get_error(smb2));
                goto out;
        }

        if (run_immediate &&
            run_scenario(smb2, dir_fh, 0,
                         "cancel sent as soon as possible") != 0) {
                goto out;
        }
        if (run_delayed &&
            run_scenario(smb2, dir_fh, 1,
                         "cancel sent after CHANGE_NOTIFY has been "
                         "pending for a second") != 0) {
                goto out;
        }
        if (run_invalid && run_scenario_invalid_msg_id(smb2) != 0) {
                goto out;
        }
        if (run_targeted &&
            run_scenario_targeted_cancel(smb2, dir_fh, dir_fh_2) != 0) {
                goto out;
        }
        if (run_completed &&
            run_scenario_cancel_after_completion(smb2, dir_fh) != 0) {
                goto out;
        }

        rc = 0;

 out:
        /*
         * CANCEL only aborts the pending CHANGE_NOTIFY; the directory
         * handles themselves are still open and need a real CLOSE.
         */
        if (dir_fh) {
                smb2_close(smb2, dir_fh);
        }
        if (dir_fh_2) {
                smb2_close(smb2, dir_fh_2);
        }
        smb2_disconnect_share(smb2);
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);

        return rc;
}
