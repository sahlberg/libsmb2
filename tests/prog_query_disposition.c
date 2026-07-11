/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Rida Shamasneh <ridahani@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#if !defined(__amigaos4__) && !defined(__AMIGA__) && !defined(__AROS__)
#include <poll.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

struct sync_cb_data {
        int is_finished;
        int status;
        void *ptr;
};

struct compound_cb_data {
        smb2_command_cb cb;
        void *cb_data;
        uint32_t status;
        void *ptr;
};

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "prog_query_disposition <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>/<path>\n");
        exit(1);
}

static int wait_for_reply(struct smb2_context *smb2,
                          struct sync_cb_data *cb_data)
{
        while (!cb_data->is_finished) {
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
                        fprintf(stderr, "smb2_service failed with : %s\n",
                                smb2_get_error(smb2));
                        return -1;
                }
        }

        return 0;
}

static void generic_status_cb(struct smb2_context *smb2 _U_, int status,
                              void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->status = status;
        cb_data->ptr = command_data;
}

static void compound_cb_1(struct smb2_context *smb2 _U_, int status,
                          void *command_data _U_, void *private_data)
{
        struct compound_cb_data *cd = private_data;

        if (cd->status == SMB2_STATUS_SUCCESS) {
                cd->status = status;
        }
}

static void compound_cb_2_set(struct smb2_context *smb2 _U_, int status,
                              void *command_data _U_, void *private_data)
{
        struct compound_cb_data *cd = private_data;

        if (cd->status == SMB2_STATUS_SUCCESS) {
                cd->status = status;
        }
}

static void compound_cb_3_query(struct smb2_context *smb2 _U_, int status,
                                void *command_data, void *private_data)
{
        struct compound_cb_data *cd = private_data;
        struct smb2_query_info_reply *rep = command_data;

        if (cd->status == SMB2_STATUS_SUCCESS) {
            cd->status = status;
        }
        if (cd->status == SMB2_STATUS_SUCCESS) {
                cd->ptr = rep->output_buffer;
        }
}

static void compound_cb_4(struct smb2_context *smb2, int status,
                          void *command_data _U_, void *private_data)
{
        struct compound_cb_data *cd = private_data;

        if (cd->status == SMB2_STATUS_SUCCESS) {
                cd->status = status;
        }

        cd->cb(smb2, -nterror_to_errno(cd->status), cd->ptr, cd->cb_data);
        free(cd);
}

static int
send_compound_disposition_query(struct smb2_context *smb2, const char *path,
                                smb2_command_cb cb, void *cb_data)
{
        struct compound_cb_data *cd;
        struct smb2_create_request cr_req;
        struct smb2_set_info_request si_req;
        struct smb2_query_info_request qi_req;
        struct smb2_close_request cl_req;
        struct smb2_file_disposition_info fdi;
        struct smb2_pdu *pdu, *next_pdu;

        cd = malloc(sizeof(struct compound_cb_data));
        if (cd == NULL) {
                fprintf(stderr, "Failed to allocate compound_cb_data\n");
                return -1;
        }
        memset(cd, 0, sizeof(struct compound_cb_data));

        cd->cb = cb;
        cd->cb_data = cb_data;

        memset(&cr_req, 0, sizeof(cr_req));
        cr_req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        cr_req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        cr_req.desired_access = SMB2_DELETE | SMB2_FILE_READ_ATTRIBUTES;
        cr_req.file_attributes = 0;
        cr_req.share_access = SMB2_FILE_SHARE_READ |
                              SMB2_FILE_SHARE_WRITE |
                              SMB2_FILE_SHARE_DELETE;
        cr_req.create_disposition = SMB2_FILE_OPEN;
        cr_req.create_options = 0;
        cr_req.name = path;

        pdu = smb2_cmd_create_async(smb2, &cr_req, compound_cb_1, cd);
        if (pdu == NULL) {
                fprintf(stderr, "Failed to create create command\n");
                free(cd);
                return -1;
        }

        memset(&fdi, 0, sizeof(fdi));
        fdi.delete_pending = 1;

        memset(&si_req, 0, sizeof(si_req));
        si_req.info_type = SMB2_0_INFO_FILE;
        si_req.file_info_class = SMB2_FILE_DISPOSITION_INFORMATION;
        si_req.input_data = &fdi;
        memcpy(si_req.file_id, compound_file_id, SMB2_FD_SIZE);

        next_pdu = smb2_cmd_set_info_async(smb2, &si_req,
                                           compound_cb_2_set, cd);
        if (next_pdu == NULL) {
                fprintf(stderr, "Failed to create set-info command\n");
                free(cd);
                smb2_free_pdu(smb2, pdu);
                return -1;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        memset(&qi_req, 0, sizeof(qi_req));
        qi_req.info_type = SMB2_0_INFO_FILE;
        qi_req.file_info_class = SMB2_FILE_DISPOSITION_INFORMATION;
        qi_req.output_buffer_length = 1;
        memcpy(qi_req.file_id, compound_file_id, SMB2_FD_SIZE);

        next_pdu = smb2_cmd_query_info_async(smb2, &qi_req,
                                             compound_cb_3_query, cd);
        if (next_pdu == NULL) {
                fprintf(stderr, "Failed to create query-info command\n");
                free(cd);
                smb2_free_pdu(smb2, pdu);
                return -1;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        memset(&cl_req, 0, sizeof(cl_req));
        memcpy(cl_req.file_id, compound_file_id, SMB2_FD_SIZE);

        next_pdu = smb2_cmd_close_async(smb2, &cl_req, compound_cb_4, cd);
        if (next_pdu == NULL) {
                fprintf(stderr, "Failed to create close command\n");
                free(cd);
                smb2_free_pdu(smb2, pdu);
                return -1;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        smb2_queue_pdu(smb2, pdu);
        return 0;
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2_file_disposition_info *fdi;
        struct sync_cb_data cb_data;
        int rc = 0;

        if (argc < 2) {
                usage();
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                return 1;
        }

        url = smb2_parse_url(smb2, argv[1]);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(smb2));
                smb2_destroy_context(smb2);
                return 1;
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (smb2_connect_share(smb2, url->server, url->share, url->user) != 0) {
                fprintf(stderr, "smb2_connect_share failed. %s\n",
                        smb2_get_error(smb2));
                rc = 1;
                goto out;
        }

        memset(&cb_data, 0, sizeof(cb_data));
        if (send_compound_disposition_query(smb2, url->path,
                                            generic_status_cb, &cb_data) < 0) {
                rc = 1;
                goto out_disconnect;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                rc = 1;
                goto out_disconnect;
        }
        if (cb_data.status != 0) {
                fprintf(stderr, "compound disposition query failed: 0x%08x\n",
                        cb_data.status);
                rc = 1;
                if (cb_data.ptr != NULL) {
                        smb2_free_data(smb2, cb_data.ptr);
                }
                goto out_disconnect;
        }

        fdi = cb_data.ptr;
        if (fdi == NULL) {
                fprintf(stderr, "did not receive disposition info\n");
                rc = 1;
                goto out_disconnect;
        }
        if (fdi->delete_pending != 1) {
                fprintf(stderr, "unexpected delete_pending value: %u\n",
                        fdi->delete_pending);
                rc = 1;
                smb2_free_data(smb2, fdi);
                goto out_disconnect;
        }

        printf("delete_pending=%u\n", fdi->delete_pending);
        smb2_free_data(smb2, fdi);

out_disconnect:
        smb2_disconnect_share(smb2);
out:
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);
        return rc;
}
