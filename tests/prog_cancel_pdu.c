/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Test cancelling smb2_open_async_pdu() and smb2_opendir_async_pdu() by
 * freeing the pdu before its callback is invoked, both while the request
 * is still queued and after it has been sent.
 *
 * A cancelled call must never invoke its callback, must call free_cb
 * with cb_data exactly once, and must not leak the smb2fh or smb2dir
 * that libsmb2 allocated for it (run this under valgrind to check that,
 * see test_0312_cancel_async_pdu.sh). The connection must keep working,
 * and the replies to the requests that were sent are discarded.
 *
 * The URL names a file that exists on the share.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

static int cb_calls;
static int free_calls;

static void must_not_run_cb(struct smb2_context *smb2, int status,
                            void *command_data, void *private_data)
{
        printf("callback of a cancelled pdu was invoked\n");
        cb_calls++;
}

static void count_free(void *ptr)
{
        free_calls++;
        free(ptr);
}

/* Service the context until the queued requests have been sent */
static int send_queued(struct smb2_context *smb2)
{
        struct pollfd pfd;
        int i;

        for (i = 0; i < 10 && (smb2_which_events(smb2) & POLLOUT); i++) {
                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);
                if (poll(&pfd, 1, 1000) < 0) {
                        printf("Poll failed\n");
                        return -1;
                }
                if (pfd.revents &&
                    smb2_service(smb2, pfd.revents) < 0) {
                        printf("smb2_service failed with: %s\n",
                               smb2_get_error(smb2));
                        return -1;
                }
        }
        if (smb2_which_events(smb2) & POLLOUT) {
                printf("Failed to send the requests\n");
                return -1;
        }
        return 0;
}

/* Service the context until it has been idle for timeout ms */
static int drain(struct smb2_context *smb2, int timeout)
{
        struct pollfd pfd;

        for (;;) {
                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);
                switch (poll(&pfd, 1, timeout)) {
                case -1:
                        printf("Poll failed\n");
                        return -1;
                case 0:
                        return 0;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        printf("smb2_service failed with: %s\n",
                               smb2_get_error(smb2));
                        return -1;
                }
        }
}

static int cancel_open_and_opendir(struct smb2_context *smb2,
                                   const char *path, int sent)
{
        struct smb2_pdu *pdu;

        pdu = smb2_open_async_pdu(smb2, path, O_RDONLY, must_not_run_cb,
                                  malloc(8), count_free);
        if (pdu == NULL) {
                printf("smb2_open_async_pdu failed: %s\n",
                       smb2_get_error(smb2));
                return -1;
        }
        if (sent && send_queued(smb2)) {
                return -1;
        }
        smb2_free_pdu(smb2, pdu);

        pdu = smb2_opendir_async_pdu(smb2, "", must_not_run_cb,
                                     malloc(8), count_free);
        if (pdu == NULL) {
                printf("smb2_opendir_async_pdu failed: %s\n",
                       smb2_get_error(smb2));
                return -1;
        }
        if (sent && send_queued(smb2)) {
                return -1;
        }
        smb2_free_pdu(smb2, pdu);

        /* The replies to the requests that were sent arrive and are dropped */
        return drain(smb2, 500);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2dir *dir;
        int rc = 1;

        if (argc < 2) {
                fprintf(stderr, "Usage: prog_cancel_pdu <smb2-url>\n");
                exit(1);
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
                smb2_destroy_context(smb2);
                exit(1);
        }
        if (url->domain) {
                smb2_set_domain(smb2, url->domain);
        }

        if (smb2_connect_share(smb2, url->server, url->share,
                               url->user) < 0) {
                printf("smb2_connect_share failed. %s\n",
                       smb2_get_error(smb2));
                goto out;
        }

        printf("Cancelling queued open and opendir\n");
        if (cancel_open_and_opendir(smb2, url->path, 0)) {
                goto out_disconnect;
        }
        printf("Cancelling sent open and opendir\n");
        if (cancel_open_and_opendir(smb2, url->path, 1)) {
                goto out_disconnect;
        }

        dir = smb2_opendir(smb2, "");
        if (dir == NULL) {
                printf("opendir after the cancels failed: %s\n",
                       smb2_get_error(smb2));
                goto out_disconnect;
        }
        smb2_closedir(smb2, dir);

        if (cb_calls != 0 || free_calls != 4) {
                printf("callbacks invoked %d times, free_cb %d times; "
                       "expected 0 and 4\n", cb_calls, free_calls);
                goto out_disconnect;
        }
        rc = 0;

 out_disconnect:
        smb2_disconnect_share(smb2);
 out:
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);
        return rc;
}
