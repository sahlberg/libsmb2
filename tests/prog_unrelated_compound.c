/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Regression test for smb2_add_unrelated_compound_pdu().
 *
 * Opens two distinct files and sends a single compound packet with a
 * QUERY_INFO for each, linked with smb2_add_unrelated_compound_pdu()
 * instead of smb2_add_compound_pdu(). Unlike a CREATE, QUERY_INFO
 * carries a real FileId in the request, so if SMB2_FLAGS_RELATED_OPERATIONS
 * ever leaked across that boundary the server would substitute the FileId
 * from the preceding response instead of honouring the one we sent,
 * and the second query would come back against the wrong file (or with
 * STATUS_FILE_CLOSED, see libsmb2 issue for
 * smb2_add_unrelated_compound_pdu()).
 *
 * This needs two files of different, known sizes to already exist on
 * the share -- see test_0330_unrelated_compound.sh, which creates them.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

#define FILE_A "UNRELATED_A"
#define FILE_B "UNRELATED_B"

struct query_result {
        int done;
        uint32_t status;
        uint64_t end_of_file;
};

static int wait_for(struct smb2_context *smb2,
                    struct query_result *a, struct query_result *b)
{
        while (!a->done || !b->done) {
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
        }

        return 0;
}

static void query_cb(struct smb2_context *smb2, int status,
                     void *command_data, void *private_data)
{
        struct query_result *res = private_data;
        struct smb2_query_info_reply *rep = command_data;

        res->status = (uint32_t)status;
        if (status == SMB2_STATUS_SUCCESS && rep && rep->output_buffer) {
                struct smb2_file_all_info *fs = rep->output_buffer;

                res->end_of_file = fs->standard.end_of_file;
                smb2_free_data(smb2, rep->output_buffer);
        }
        res->done = 1;
}

static struct smb2_pdu *
build_query_info_pdu(struct smb2_context *smb2, struct smb2fh *fh,
                     smb2_command_cb cb, void *cb_data)
{
        struct smb2_query_info_request req;

        memset(&req, 0, sizeof(req));
        req.info_type = SMB2_0_INFO_FILE;
        req.file_info_class = SMB2_FILE_ALL_INFORMATION;
        req.output_buffer_length = 65535;
        memcpy(req.file_id, smb2_get_file_id(fh), SMB2_FD_SIZE);

        return smb2_cmd_query_info_async(smb2, &req, cb, cb_data);
}

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "prog_unrelated_compound <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2fh *fh_a = NULL, *fh_b = NULL;
        struct smb2_stat_64 st_a, st_b;
        struct smb2_pdu *pdu_a, *pdu_b;
        struct query_result res_a, res_b;
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

        if (smb2_stat(smb2, FILE_A, &st_a) != 0) {
                printf("smb2_stat(%s) failed. %s\n", FILE_A, smb2_get_error(smb2));
                goto out;
        }
        if (smb2_stat(smb2, FILE_B, &st_b) != 0) {
                printf("smb2_stat(%s) failed. %s\n", FILE_B, smb2_get_error(smb2));
                goto out;
        }
        if (st_a.smb2_size == st_b.smb2_size) {
                printf("Test files must have different sizes "
                       "(both are %" PRIu64 " bytes)\n", st_a.smb2_size);
                goto out;
        }

        fh_a = smb2_open(smb2, FILE_A, O_RDONLY);
        if (fh_a == NULL) {
                printf("Failed to open %s. %s\n", FILE_A, smb2_get_error(smb2));
                goto out;
        }
        fh_b = smb2_open(smb2, FILE_B, O_RDONLY);
        if (fh_b == NULL) {
                printf("Failed to open %s. %s\n", FILE_B, smb2_get_error(smb2));
                goto out;
        }

        memset(&res_a, 0, sizeof(res_a));
        memset(&res_b, 0, sizeof(res_b));

        pdu_a = build_query_info_pdu(smb2, fh_a, query_cb, &res_a);
        if (pdu_a == NULL) {
                printf("Failed to build QUERY_INFO for %s. %s\n",
                       FILE_A, smb2_get_error(smb2));
                goto out;
        }
        pdu_b = build_query_info_pdu(smb2, fh_b, query_cb, &res_b);
        if (pdu_b == NULL) {
                printf("Failed to build QUERY_INFO for %s. %s\n",
                       FILE_B, smb2_get_error(smb2));
                smb2_free_pdu(smb2, pdu_a);
                goto out;
        }

        /*
         * The two queries are for different files and must not be
         * treated as related to each other.
         */
        smb2_add_unrelated_compound_pdu(smb2, pdu_a, pdu_b);
        smb2_queue_pdu(smb2, pdu_a);

        if (wait_for(smb2, &res_a, &res_b) < 0) {
                goto out;
        }

        if (res_a.status != SMB2_STATUS_SUCCESS) {
                printf("QUERY_INFO for %s failed with status 0x%08x\n",
                       FILE_A, res_a.status);
                goto out;
        }
        if (res_b.status != SMB2_STATUS_SUCCESS) {
                printf("QUERY_INFO for %s failed with status 0x%08x\n",
                       FILE_B, res_b.status);
                goto out;
        }
        if (res_a.end_of_file != st_a.smb2_size) {
                printf("QUERY_INFO for %s returned size %" PRIu64
                       ", expected %" PRIu64 "\n",
                       FILE_A, res_a.end_of_file, st_a.smb2_size);
                goto out;
        }
        if (res_b.end_of_file != st_b.smb2_size) {
                printf("QUERY_INFO for %s returned size %" PRIu64
                       ", expected %" PRIu64 "\n",
                       FILE_B, res_b.end_of_file, st_b.smb2_size);
                goto out;
        }

        rc = 0;

 out:
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
