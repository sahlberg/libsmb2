/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Rida Shamasneh <ridahani@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#if !defined(__amigaos4__) && !defined(__AMIGA__) && !defined(__AROS__)
#include <poll.h>
#endif
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-set-security-info <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>/<path>\n");
        exit(1);
}

struct sync_cb_data {
        int is_finished;
        int status;
        void *ptr;
};

static int wait_for_reply(struct smb2_context *smb2,
                          struct sync_cb_data *cb_data)
{
        while (!cb_data->is_finished) {
                struct pollfd pfd;

                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);

                if (poll(&pfd, 1, 1000) < 0) {
                        fprintf(stderr, "Poll failed");
                        return -1;
                }
                if (pfd.revents == 0) {
                        continue;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        fprintf(stderr, "smb2_service failed with : "
                                "%s\n", smb2_get_error(smb2));
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

struct set_sd_cb_data {
        smb2_command_cb cb;
        void *cb_data;

        uint32_t status;
};

static void
set_sd_cb_3(struct smb2_context *smb2, int status,
           void *command_data _U_, void *private_data)
{
        struct set_sd_cb_data *sd_data = private_data;

        if (sd_data->status == SMB2_STATUS_SUCCESS) {
                sd_data->status = status;
        }

        sd_data->cb(smb2, -nterror_to_errno(sd_data->status), NULL,
                    sd_data->cb_data);
        free(sd_data);
}

static void
set_sd_cb_2(struct smb2_context *smb2 _U_, int status,
           void *command_data _U_, void *private_data)
{
        struct set_sd_cb_data *sd_data = private_data;

        if (sd_data->status == SMB2_STATUS_SUCCESS) {
                sd_data->status = status;
        }
}

static void
set_sd_cb_1(struct smb2_context *smb2 _U_, int status,
           void *command_data _U_, void *private_data)
{
        struct set_sd_cb_data *sd_data = private_data;

        if (sd_data->status == SMB2_STATUS_SUCCESS) {
                sd_data->status = status;
        }
}

/*
 * Setting a file's DACL requires the handle to be opened with
 * SMB2_WRITE_DACL access. The high-level smb2_open() API has no way to
 * request that access right, so this issues a raw compound
 * CREATE + SET_INFO + CLOSE instead.
 */
static int
send_compound_set_security(struct smb2_context *smb2, const char *path,
                           struct smb2_security_descriptor *sd,
                           smb2_command_cb cb, void *cb_data)
{
        struct set_sd_cb_data *sd_data;
        struct smb2_create_request cr_req;
        struct smb2_set_info_request si_req;
        struct smb2_close_request cl_req;
        struct smb2_pdu *pdu, *next_pdu;

        sd_data = malloc(sizeof(struct set_sd_cb_data));
        if (sd_data == NULL) {
                fprintf(stderr, "Failed to allocate set_sd_data\n");
                return -1;
        }
        memset(sd_data, 0, sizeof(struct set_sd_cb_data));

        sd_data->cb = cb;
        sd_data->cb_data = cb_data;

        /* CREATE command */
        memset(&cr_req, 0, sizeof(struct smb2_create_request));
        cr_req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        cr_req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        cr_req.desired_access = SMB2_WRITE_DACL;
        cr_req.file_attributes = 0;
        cr_req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        cr_req.create_disposition = SMB2_FILE_OPEN;
        cr_req.create_options = 0;
        cr_req.name = path;

        pdu = smb2_cmd_create_async(smb2, &cr_req, set_sd_cb_1, sd_data);
        if (pdu == NULL) {
                fprintf(stderr, "Failed to create create command\n");
                free(sd_data);
                return -1;
        }

        /* SET INFO command */
        memset(&si_req, 0, sizeof(struct smb2_set_info_request));
        si_req.info_type = SMB2_0_INFO_SECURITY;
        si_req.additional_information = SMB2_DACL_SECURITY_INFORMATION;
        si_req.input_data = sd;
        memcpy(si_req.file_id, compound_file_id, SMB2_FD_SIZE);

        next_pdu = smb2_cmd_set_info_async(smb2, &si_req, set_sd_cb_2,
                                           sd_data);
        if (next_pdu == NULL) {
                fprintf(stderr, "Failed to create set-info command\n");
                free(sd_data);
                smb2_free_pdu(smb2, pdu);
                return -1;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        /* CLOSE command */
        memset(&cl_req, 0, sizeof(struct smb2_close_request));
        cl_req.flags = 0;
        memcpy(cl_req.file_id, compound_file_id, SMB2_FD_SIZE);

        next_pdu = smb2_cmd_close_async(smb2, &cl_req, set_sd_cb_3, sd_data);
        if (next_pdu == NULL) {
                fprintf(stderr, "Failed to create close command\n");
                free(sd_data);
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
        struct smb2_security_descriptor sd;
        struct smb2_acl dacl;
        struct smb2_ace ace;
        struct smb2_sid *everyone_sid;
        struct sync_cb_data cb_data;

        if (argc < 2) {
                usage();
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                exit(0);
        }

        url = smb2_parse_url(smb2, argv[1]);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(smb2));
                exit(0);
        }

        if (url->domain) {
                smb2_set_domain(smb2, url->domain);
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (smb2_connect_share(smb2, url->server, url->share, url->user) != 0) {
                printf("smb2_connect_share failed. %s\n", smb2_get_error(smb2));
                exit(10);
        }

        /* Build a DACL that grants "Everyone" (S-1-1-0) full control, and
         * push it to the server via SET_INFO/SMB2_0_INFO_SECURITY. */
        everyone_sid = malloc(offsetof(struct smb2_sid, sub_auth) +
                              sizeof(uint32_t));
        if (everyone_sid == NULL) {
                fprintf(stderr, "Failed to allocate sid\n");
                exit(10);
        }
        everyone_sid->revision = 1;
        everyone_sid->sub_auth_count = 1;
        memset(everyone_sid->id_auth, 0, SID_ID_AUTH_LEN);
        everyone_sid->id_auth[5] = 1; /* SECURITY_WORLD_SID_AUTHORITY */
        everyone_sid->sub_auth[0] = 0; /* SECURITY_WORLD_RID -> S-1-1-0 */

        memset(&ace, 0, sizeof(ace));
        ace.ace_type = SMB2_ACCESS_ALLOWED_ACE_TYPE;
        ace.mask = SMB2_GENERIC_ALL;
        ace.sid = everyone_sid;

        memset(&dacl, 0, sizeof(dacl));
        dacl.revision = SMB2_ACL_REVISION;
        dacl.ace_count = 1;
        dacl.aces = &ace;

        memset(&sd, 0, sizeof(sd));
        sd.revision = 1;
        sd.control = SMB2_SD_CONTROL_DP;
        sd.dacl = &dacl;

        memset(&cb_data, 0, sizeof(cb_data));
        if (send_compound_set_security(smb2, url->path, &sd,
                                       generic_status_cb, &cb_data) != 0) {
                printf("sending compound set-security failed. %s\n",
                       smb2_get_error(smb2));
                exit(10);
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                printf("failed waiting for a reply. %s\n",
                       smb2_get_error(smb2));
                exit(10);
        }

        if (cb_data.status != 0) {
                printf("Server rejected SET_INFO/SMB2_0_INFO_SECURITY: "
                       "0x%08x\n", cb_data.status);
        } else {
                printf("Server accepted SET_INFO/SMB2_0_INFO_SECURITY\n");
        }

        free(everyone_sid);
        smb2_disconnect_share(smb2);
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);

        return 0;
}
