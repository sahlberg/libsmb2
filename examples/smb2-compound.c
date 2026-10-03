/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Demonstrates smb2_add_compound_pdu() and smb2_add_unrelated_compound_pdu().
 *
 * Sends a single compound packet containing two independent chains:
 *   file A: CREATE -> READ -> CLOSE
 *   file B: CREATE -> QUERY_INFO -> CLOSE
 *
 * Each chain's own steps are joined with smb2_add_compound_pdu(), since
 * each step really is related to the one before it -- same file, using
 * the handle its CREATE just returned. The two chains are joined to
 * each other with smb2_add_unrelated_compound_pdu(), since file A's
 * chain and file B's chain have nothing to do with one another.
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

#define READ_BUF_SIZE 256

struct compound_data {
        int is_finished;
        int status;
};

static void status_cb(struct smb2_context *smb2 _U_, int status,
                      void *command_data _U_, void *private_data)
{
        struct compound_data *cd = private_data;

        if (cd->status == 0) {
                cd->status = status;
        }
}

static void read_cb(struct smb2_context *smb2 _U_, int status,
                    void *command_data _U_, void *private_data)
{
        struct compound_data *cd = private_data;

        if (cd->status == 0) {
                cd->status = status;
        }
        if (status == SMB2_STATUS_SUCCESS) {
                printf("Read from file A succeeded\n");
        }
}

static void query_info_cb(struct smb2_context *smb2, int status,
                          void *command_data, void *private_data)
{
        struct compound_data *cd = private_data;
        struct smb2_query_info_reply *rep = command_data;

        if (cd->status == 0) {
                cd->status = status;
        }
        if (status == SMB2_STATUS_SUCCESS && rep && rep->output_buffer) {
                struct smb2_file_all_info *fs = rep->output_buffer;

                printf("File B size: %" PRIu64 " bytes\n",
                       fs->standard.end_of_file);
                smb2_free_data(smb2, rep->output_buffer);
        }
}

static void last_close_cb(struct smb2_context *smb2 _U_, int status,
                          void *command_data _U_, void *private_data)
{
        struct compound_data *cd = private_data;

        if (cd->status == 0) {
                cd->status = status;
        }
        cd->is_finished = 1;
}

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-compound <smb2-share-url> <file-A> <file-B>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct compound_data cd;
        struct smb2_create_request cr_req;
        struct smb2_read_request rd_req;
        struct smb2_close_request cl_req;
        struct smb2_query_info_request qi_req;
        struct smb2_pdu *pdu, *next_pdu;
        uint8_t read_buf[READ_BUF_SIZE];
        int rc = 1;

        if (argc < 4) {
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

        memset(&cd, 0, sizeof(cd));

        /* --- File A chain: CREATE -> READ -> CLOSE, all related --- */
        memset(&cr_req, 0, sizeof(cr_req));
        cr_req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        cr_req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        cr_req.desired_access = SMB2_FILE_READ_DATA | SMB2_FILE_READ_ATTRIBUTES;
        cr_req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        cr_req.create_disposition = SMB2_FILE_OPEN;
        cr_req.name = argv[2];

        pdu = smb2_cmd_create_async(smb2, &cr_req, status_cb, &cd);
        if (pdu == NULL) {
                printf("Failed to build CREATE for %s. %s\n", argv[2],
                       smb2_get_error(smb2));
                goto out;
        }

        memset(&rd_req, 0, sizeof(rd_req));
        rd_req.length = READ_BUF_SIZE;
        rd_req.offset = 0;
        rd_req.buf = read_buf;
        memcpy(rd_req.file_id, compound_file_id, SMB2_FD_SIZE);

        next_pdu = smb2_cmd_read_async(smb2, &rd_req, read_cb, &cd);
        if (next_pdu == NULL) {
                printf("Failed to build READ for %s. %s\n", argv[2],
                       smb2_get_error(smb2));
                smb2_free_pdu(smb2, pdu);
                goto out;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        memset(&cl_req, 0, sizeof(cl_req));
        memcpy(cl_req.file_id, compound_file_id, SMB2_FD_SIZE);

        next_pdu = smb2_cmd_close_async(smb2, &cl_req, status_cb, &cd);
        if (next_pdu == NULL) {
                printf("Failed to build CLOSE for %s. %s\n", argv[2],
                       smb2_get_error(smb2));
                smb2_free_pdu(smb2, pdu);
                goto out;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        /* --- File B chain: CREATE -> QUERY_INFO -> CLOSE, all related.
         * Joined to file A's chain above as UNRELATED: it is a
         * completely separate file, so it must not inherit file A's
         * handle the way a related step would.
         */
        memset(&cr_req, 0, sizeof(cr_req));
        cr_req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        cr_req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        cr_req.desired_access = SMB2_FILE_READ_ATTRIBUTES;
        cr_req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        cr_req.create_disposition = SMB2_FILE_OPEN;
        cr_req.name = argv[3];

        next_pdu = smb2_cmd_create_async(smb2, &cr_req, status_cb, &cd);
        if (next_pdu == NULL) {
                printf("Failed to build CREATE for %s. %s\n", argv[3],
                       smb2_get_error(smb2));
                smb2_free_pdu(smb2, pdu);
                goto out;
        }
        smb2_add_unrelated_compound_pdu(smb2, pdu, next_pdu);

        memset(&qi_req, 0, sizeof(qi_req));
        qi_req.info_type = SMB2_0_INFO_FILE;
        qi_req.file_info_class = SMB2_FILE_ALL_INFORMATION;
        qi_req.output_buffer_length = 65535;
        memcpy(qi_req.file_id, compound_file_id, SMB2_FD_SIZE);

        next_pdu = smb2_cmd_query_info_async(smb2, &qi_req, query_info_cb, &cd);
        if (next_pdu == NULL) {
                printf("Failed to build QUERY_INFO for %s. %s\n", argv[3],
                       smb2_get_error(smb2));
                smb2_free_pdu(smb2, pdu);
                goto out;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        memset(&cl_req, 0, sizeof(cl_req));
        memcpy(cl_req.file_id, compound_file_id, SMB2_FD_SIZE);

        next_pdu = smb2_cmd_close_async(smb2, &cl_req, last_close_cb, &cd);
        if (next_pdu == NULL) {
                printf("Failed to build CLOSE for %s. %s\n", argv[3],
                       smb2_get_error(smb2));
                smb2_free_pdu(smb2, pdu);
                goto out;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        /* One packet, six commands, two files. */
        smb2_queue_pdu(smb2, pdu);

        while (!cd.is_finished) {
                struct pollfd pfd;

                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);

                if (poll(&pfd, 1, 1000) < 0) {
                        fprintf(stderr, "Poll failed\n");
                        goto out;
                }
                if (pfd.revents == 0) {
                        continue;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        fprintf(stderr, "smb2_service failed with: %s\n",
                                smb2_get_error(smb2));
                        goto out;
                }
        }

        if (cd.status != SMB2_STATUS_SUCCESS) {
                printf("Compound request failed with status 0x%08x\n",
                       cd.status);
                goto out;
        }

        rc = 0;

 out:
        smb2_disconnect_share(smb2);
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);

        return rc;
}
