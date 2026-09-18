/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Check that a create which never gets a reply is cleaned up correctly
 * once it hits the timeout.
 *
 * smb2_open() and smb2_opendir() own the pdu they build and free it once
 * wait_for_reply() returns, so the timeout sweep in smb2_timeout_pdus()
 * must not free it as well.  Before that was fixed both calls aborted
 * with a double free here.  See libsmb2 issue 484.
 *
 * This needs a server that accepts the create and then never answers it.
 * scrambla on the tests/libsmb2_issue_484 branch does that for the name
 * "libsmb2_issue_484":
 *   https://github.com/sahlberg/scrambla/tree/tests/libsmb2_issue_484
 * Against any other server the create is answered right away, and we
 * exit with SKIP_RC since there is nothing to test.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "smb2.h"
#include "libsmb2.h"

/* Same value automake uses for a test that could not be run. */
#define SKIP_RC 77

#define TIMEOUT 5

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "prog_open_timeout <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>/<path>\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2fh *fh;
        struct smb2dir *dir;
        time_t t;
        int rc = 0;

        if (argc < 2) {
                usage();
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

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        /*
         * scrambla offers krb5 in its spnego blob but the test setup only
         * has NTLM credentials, so do not let the krb5 mech be picked.
         */
        smb2_set_authentication(smb2, SMB2_SEC_NTLMSSP);
        smb2_set_timeout(smb2, TIMEOUT);

        if (smb2_connect_share(smb2, url->server, url->share, url->user) != 0) {
                fprintf(stderr, "smb2_connect_share failed. %s\n",
                        smb2_get_error(smb2));
                rc = 1;
                goto destroy;
        }

        /*
         * Both of these must come back as a failure after the timeout has
         * expired, and must not free the pdu twice on the way out.
         */
        t = time(NULL);
        fh = smb2_open(smb2, url->path, O_RDONLY);
        if (fh != NULL) {
                printf("smb2_open succeeded, the server did not drop "
                       "the create. Skipping.\n");
                smb2_close(smb2, fh);
                rc = SKIP_RC;
                goto finished;
        }
        if (time(NULL) - t < TIMEOUT) {
                printf("smb2_open failed before the timeout expired, "
                       "the server did not drop the create. Skipping.\n");
                rc = SKIP_RC;
                goto finished;
        }
        printf("smb2_open timed out as expected\n");

        t = time(NULL);
        dir = smb2_opendir(smb2, url->path);
        if (dir != NULL) {
                printf("smb2_opendir succeeded, the server did not drop "
                       "the create. Skipping.\n");
                smb2_closedir(smb2, dir);
                rc = SKIP_RC;
                goto finished;
        }
        if (time(NULL) - t < TIMEOUT) {
                printf("smb2_opendir failed before the timeout expired, "
                       "the server did not drop the create. Skipping.\n");
                rc = SKIP_RC;
                goto finished;
        }
        printf("smb2_opendir timed out as expected\n");

 finished:
        smb2_disconnect_share(smb2);
 destroy:
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);

        return rc;
}
