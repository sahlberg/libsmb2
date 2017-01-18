/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"

int is_finished;

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-ls <smb2-url>\n\n"
                "URL format: "
                "smb2://[<domain;][<username>@]<host>/<share>/<path>\n");
        exit(1);
}

void lo_cb(struct smb2_context *smb2, int status,
                void *command_data _U_, void *private_data)
{
	printf("Logged off status:0x%08x\n", status);
        is_finished = 1;
}

void cl_cb(struct smb2_context *smb2, int status,
                void *command_data _U_, void *private_data)
{
	printf("Close status:0x%08x\n", status);
        if (status) {
                printf("failed to close\n");
                exit(10);
        }

        if (smb2_logoff_async(smb2, lo_cb, NULL) < 0) {
                printf("Failed to send LOGOFF command\n");
                exit(10);
        }
}

void cr_cb(struct smb2_context *smb2, int status,
                void *command_data, void *private_data)
{
        struct smb2_create_reply *rep = command_data;
        struct smb2_close_request req;

        printf("Create status:0x%08x\n", status);
        if (status) {
                printf("failed to create/open\n");
                exit(10);
        }
        
        memset(&req, 0, sizeof(struct smb2_close_request));
        req.struct_size = SMB2_CLOSE_REQUEST_SIZE;
        req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
        memcpy(req.file_id, rep->file_id, SMB2_FD_SIZE);
        
        if (smb2_close_async(smb2, &req, cl_cb, NULL) < 0) {
                printf("Failed to send Close command\n");
                exit(10);
        }
}

void cf_cb(struct smb2_context *smb2, int status,
                void *command_data _U_, void *private_data)
{
        struct smb2_create_request req;

	printf("Connected to SMB2 share status:0x%08x\n", status);
        if (status) {
                printf("failed to connect share\n");
                exit(10);
        }

        memset(&req, 0, sizeof(struct smb2_create_request));
        req.struct_size = SMB2_CREATE_REQUEST_SIZE;
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        req.desired_access = SMB2_FILE_LIST_DIRECTORY | SMB2_FILE_READ_ATTRIBUTES;
        req.file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
        req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        req.create_disposition = SMB2_FILE_OPEN;
        req.create_options = SMB2_FILE_DIRECTORY_FILE;
        req.name_offset = 0x78;
        req.name_length = 0;
        req.name = NULL;
        
        if (smb2_create_async(smb2, &req, cr_cb, NULL) < 0) {
                printf("Failed to send Create command\n");
                exit(10);
        }
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
	struct pollfd pfd;
        int ret;

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
                
        printf("Domain:%s\n", url->domain);
        printf("User:%s\n", url->user);
        printf("Server:%s\n", url->server);
        printf("Share:%s\n", url->share);
        printf("Path:%s\n", url->path);

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

	if (smb2_connect_share_async(smb2, url->server, url->share,
                                     cf_cb, NULL) != 0) {
		printf("smb2_connect_full failed. %s\n", smb2_get_error(smb2));
		exit(10);
	}
        
        while (!is_finished) {
		pfd.fd = smb2_get_fd(smb2);
		pfd.events = smb2_which_events(smb2);

		if (poll(&pfd, 1, 1000) < 0) {
			printf("Poll failed");
			exit(10);
		}
                if (pfd.revents == 0) {
                        continue;
                }
		if (smb2_service(smb2, pfd.revents) < 0) {
			printf("smb2_service failed with : %s\n",
                               smb2_get_error(smb2));
			break;
		}
	}

        smb2_destroy_url(url);
        smb2_destroy_context(smb2);
        
	return 0;
}
