/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Fully async client for the axpy "A * X plus Y" example service.
 *
 * Usage:
 *   axpy-clnt-async <smb2-url> <x> <y>
 *   axpy-clnt-async smb://[[domain;]user@]host[:port]/[?args] 5 3
 *
 * Unlike axpy-clnt (sync convenience via dcerpc_create_context_smb),
 * this example owns the smb2 context explicitly and drives everything
 * with the async APIs:
 *
 *   smb2_connect_share_async  →  dcerpc_create_context(smb2)
 *     →  dcerpc_connect_context_async  →  dcerpc_call_async
 *
 * A poll()/smb2_service() loop runs until the RPC completes.
 *
 * SMB options (signing, sec, etc.) are taken from the URL query string,
 * e.g. ?sign  or  ?sec=ntlmssp&sign
 */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

#include "axpy_coder.h"

static volatile int is_finished;
static int exit_status = 1;

struct clnt_state {
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct dcerpc_context *dce;
        struct axpy_compute_req req;
};

static int
usage(void)
{
        fprintf(stderr,
                "Usage:\n"
                "  axpy-clnt-async <smb2-url> <x> <y>\n\n"
                "URL format:\n"
                "  smb://[<domain>;][<username>@]<host>[:<port>]/[?args]\n"
                "  Query args (optional): sign, seal, sec=ntlmssp|krb5, ...\n\n"
                "Async client: owns the smb2 context, connects IPC$ with\n"
                "smb2_connect_share_async, then open/bind + compute via\n"
                "dcerpc_*_async. Prints the response string.\n");
        exit(1);
}

static void
finish(struct clnt_state *st, int status)
{
        exit_status = status;
        is_finished = 1;
        (void)st;
}

static void
call_cb(struct dcerpc_context *dce, int status,
        void *command_data, void *cb_data)
{
        struct clnt_state *st = cb_data;
        struct axpy_compute_rep *rep = command_data;

        if (status != (int)SMB2_STATUS_SUCCESS) {
                fprintf(stderr, "compute failed (%s) %s\n",
                        strerror(-status), dcerpc_get_error(dce));
                if (rep) {
                        dcerpc_free_data(dce, rep);
                }
                finish(st, 1);
                return;
        }

        if (rep == NULL) {
                fprintf(stderr, "compute: empty response\n");
                finish(st, 1);
                return;
        }

        if (rep->status != 0) {
                fprintf(stderr, "compute status=0x%x result=%s\n",
                        rep->status,
                        rep->result ? rep->result : "(null)");
                dcerpc_free_data(dce, rep);
                finish(st, 1);
                return;
        }

        printf("%s\n", rep->result ? rep->result : "");
        dcerpc_free_data(dce, rep);
        finish(st, 0);
}

static void
bind_cb(struct dcerpc_context *dce, int status,
        void *command_data, void *cb_data)
{
        struct clnt_state *st = cb_data;

        (void)command_data;

        if (status != (int)SMB2_STATUS_SUCCESS) {
                fprintf(stderr, "Failed to bind %s: %s\n",
                        axpy_PIPE_NAME, dcerpc_get_error(dce));
                finish(st, 1);
                return;
        }

        if (dcerpc_call_async(dce, AXPY_COMPUTE,
                              axpy_compute_req_coder, &st->req,
                              axpy_compute_rep_coder,
                              sizeof(struct axpy_compute_rep),
                              call_cb, st) != 0) {
                fprintf(stderr, "dcerpc_call_async failed: %s\n",
                        dcerpc_get_error(dce));
                finish(st, 1);
        }
}

/*
 * IPC$ tree connect finished. Create a dcerpc context on the caller's
 * smb2 (caller retains ownership) and open/bind the named pipe async.
 */
static void
connect_cb(struct smb2_context *smb2, int status,
           void *command_data, void *cb_data)
{
        struct clnt_state *st = cb_data;

        (void)command_data;

        if (status != 0) {
                fprintf(stderr, "Failed to connect IPC$: (%s) %s\n",
                        strerror(-status), smb2_get_error(smb2));
                finish(st, 1);
                return;
        }

        st->dce = dcerpc_create_context(st->smb2);
        if (st->dce == NULL) {
                fprintf(stderr, "Failed to create dce context: %s\n",
                        smb2_get_error(st->smb2));
                finish(st, 1);
                return;
        }

        if (dcerpc_connect_context_async(st->dce, axpy_PIPE_NAME,
                                         &axpy_interface,
                                         bind_cb, st) != 0) {
                fprintf(stderr, "Failed to open %s: %s\n",
                        axpy_PIPE_NAME, dcerpc_get_error(st->dce));
                dcerpc_destroy_context(st->dce);
                st->dce = NULL;
                finish(st, 1);
        }
}

int
main(int argc, char *argv[])
{
        struct clnt_state st;
        struct pollfd pfd;
        char *end = NULL;
        uint32_t x, y;

        if (argc != 4 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
                usage();
        }

        x = (uint32_t)strtoul(argv[2], &end, 0);
        if (end == argv[2] || (end && *end != '\0')) {
                fprintf(stderr, "invalid integer x: %s\n", argv[2]);
                return 1;
        }

        y = (uint32_t)strtoul(argv[3], &end, 0);
        if (end == argv[3] || (end && *end != '\0')) {
                fprintf(stderr, "invalid integer y: %s\n", argv[3]);
                return 1;
        }

        memset(&st, 0, sizeof(st));
        st.req.x = x;
        st.req.y = y;

        st.smb2 = smb2_init_context();
        if (st.smb2 == NULL) {
                fprintf(stderr, "Failed to init smb2 context\n");
                return 1;
        }

        st.url = smb2_parse_url(st.smb2, argv[1]);
        if (st.url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(st.smb2));
                smb2_destroy_context(st.smb2);
                return 1;
        }

        if (st.url->user) {
                smb2_set_user(st.smb2, st.url->user);
        }
        if (st.url->domain) {
                smb2_set_domain(st.smb2, st.url->domain);
        }

        /*
         * DCE/RPC named pipes always use IPC$. Query args from the URL
         * (?sign, ?seal, ?sec=…) were applied by smb2_parse_url.
         */
        if (smb2_connect_share_async(st.smb2, st.url->server, "IPC$",
                                     st.url->user, connect_cb, &st) != 0) {
                fprintf(stderr, "smb2_connect_share_async failed: %s\n",
                        smb2_get_error(st.smb2));
                smb2_destroy_url(st.url);
                smb2_destroy_context(st.smb2);
                return 1;
        }

        while (!is_finished) {
                pfd.fd = smb2_get_fd(st.smb2);
                pfd.events = smb2_which_events(st.smb2);

                if (poll(&pfd, 1, 1000) < 0) {
                        fprintf(stderr, "poll failed: %s\n", strerror(errno));
                        break;
                }
                if (pfd.revents == 0) {
                        continue;
                }
                if (smb2_service(st.smb2, pfd.revents) < 0) {
                        fprintf(stderr, "smb2_service failed: %s\n",
                                smb2_get_error(st.smb2));
                        break;
                }
        }

        if (st.dce) {
                dcerpc_destroy_context(st.dce);
        }
        smb2_disconnect_share(st.smb2);
        smb2_destroy_url(st.url);
        smb2_destroy_context(st.smb2);

        return exit_status;
}
