/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Sync client for the axpy "A * X plus Y" example service.
 *
 * Usage:
 *   axpy-clnt <smb2-url> <x> <y>
 *   axpy-clnt smb://[[domain;]user@]host[:port]/[?args] 5 3
 *
 * Connects to IPC$/axpy, calls compute(x, y) which performs the BLAS
 * style update y := a*x + y, and prints the result string.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "axpy_coder.h"

static int
usage(void)
{
        fprintf(stderr,
                "Usage:\n"
                "  axpy-clnt <smb2-url> <x> <y>\n\n"
                "URL format:\n"
                "  smb://[<domain>;][<username>@]<host>[:<port>]/[?args]\n"
                "  Query args (optional): sign, seal, sec=ntlmssp|krb5, ...\n\n"
                "Connects to IPC$/" axpy_PIPE_NAME " and calls compute(x, y).\n"
                "Prints the response string (prefix + a*x+y in CONFIG base).\n");
        exit(1);
}

int
main(int argc, char *argv[])
{
        struct dcerpc_context *dce = NULL;
        struct axpy_compute_req req;
        struct axpy_compute_rep *rep = NULL;
        uint32_t x, y;
        char *end = NULL;
        int rc = 1;

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

        dce = dcerpc_create_context_smb(argv[1]);
        if (dce == NULL) {
                fprintf(stderr, "Failed to create dce context for %s\n",
                        argv[1]);
                return 1;
        }

        if (dcerpc_connect_context(dce, axpy_PIPE_NAME, &axpy_interface) != 0) {
                fprintf(stderr, "Failed to connect %s: %s\n",
                        axpy_PIPE_NAME, dcerpc_get_error(dce));
                goto out;
        }

        memset(&req, 0, sizeof(req));
        req.x = x;
        req.y = y;

        rep = dcerpc_call(dce, AXPY_COMPUTE,
                          axpy_compute_req_coder, &req,
                          axpy_compute_rep_coder,
                          sizeof(struct axpy_compute_rep));
        if (rep == NULL) {
                fprintf(stderr, "compute failed: %s\n", dcerpc_get_error(dce));
                goto out;
        }
        if (rep->status != 0) {
                fprintf(stderr, "compute status=0x%x result=%s\n",
                        rep->status,
                        rep->result ? rep->result : "(null)");
                goto out;
        }

        printf("%s\n", rep->result ? rep->result : "");
        rc = 0;

out:
        if (rep) {
                dcerpc_free_data(dce, rep);
        }
        dcerpc_destroy_context(dce);
        return rc;
}
