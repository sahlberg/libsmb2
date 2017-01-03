/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"

#define NUM_DIALECTS 2

int is_finished;

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-ls <smb2-url>\n\n"
                "URL format: "
                "smb2://[<domain;][<username>@]<host>/<share>/<path>\n");
        exit(1);
}

void session_setup_cb(struct smb2_context *smb2, int status,
                void *command_data, void *private_data)
{
        struct session_setup_reply *rep = command_data;
        
	printf("Session Setup:0x%08x\n", status);

	printf("Security buffer offset:0x%08x\n", rep->security_buffer_offset);
	printf("Security buffer length:%d\n", rep->security_buffer_length);

        printf("Sec blob [%02x][%02x][%02x]\n",
               (unsigned char)rep->security_buffer[0],
               (unsigned char)rep->security_buffer[1],
               (unsigned char)rep->security_buffer[2]);
        
        /* TODO: Here we need to take the blob we got in
         * rep->security_buffer and try another SessionSetup until
         * negotiation is complete.
         */
        if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                printf("HELP. Do another SessionSetup if not complete yet.\n");
		exit(10);
	}
        
	if (status != STATUS_SUCCESS) {
		printf("session_setup failed : %s\n",
                       smb2_get_error(smb2));
		exit(10);
	}

}

void negotiate_cb(struct smb2_context *smb2, int status,
                void *command_data, void *private_data)
{
        struct negotiate_reply *rep = command_data;
        struct session_setup_request req;
        
        /* Example. We need a proper blob MIT/Heimdal GSS/SPNEGO/NTLM blob here.
         * This is just to demonstrate we can send a blob and that the server
         * responds.
         */
        static char foo[] = {
                0x60, 0x48, 0x06, 0x06,
                0x2b, 0x06, 0x01, 0x05,
                0x05, 0x02, 0xa0, 0x3e,
                0x30, 0x3c, 0xa0, 0x0e,
                
                0x30, 0x0c, 0x06, 0x0a,
                0x2b, 0x06, 0x01, 0x04,
                0x01, 0x82, 0x37, 0x02,
                0x02, 0x0a, 0xa2, 0x2a,
                
                0x04, 0x28, 0x4e, 0x54,
                0x4c, 0x4d, 0x53, 0x53,
                0x50, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x97, 0x82,
                
                0x08, 0xe2, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x0a, 0x00,
                0x39, 0x38, 0x00, 0x00,
                0x00, 0x0f};

        
	printf("Negotiate status:0x%08x\n", status);
        printf("max transaction size:%d\n", rep->max_transact_size);
               
	if (status != STATUS_SUCCESS) {
		printf("negotiate_cb: connection failed : %s\n",
                       smb2_get_error(smb2));
		exit(10);
	}

        /* Session setup request. */
        memset(&req, 0, sizeof(struct session_setup_request));
        req.struct_size = SESSION_SETUP_REQUEST_SIZE;
        req.security_buffer_offset = 0x58;
        req.security_buffer_length = sizeof(foo);
        printf("HELP. Need a real security blob here from MIT or Heimdal.\n");
        req.security_buffer = foo;
        
	if (smb2_session_setup_async(smb2, &req, session_setup_cb, NULL) != 0) {
		printf("smb2_session_setup failed. %s\n", smb2_get_error(smb2));
		exit(10);
	}
}

void connect_cb(struct smb2_context *smb2, int status,
                void *command_data _U_, void *private_data)
{
        struct negotiate_request req;
        
	printf("Connected to SMB2 socket status:0x%08x\n", status);

	if (status != 0) {
		printf("connect_cb: connection failed : %s\n",
                       smb2_get_error(smb2));
		exit(10);
	}
        
        memset(&req, 0, sizeof(struct negotiate_request));
        req.struct_size = NEGOTIATE_REQUEST_SIZE;
        req.dialect_count = NUM_DIALECTS;
        req.security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
        req.dialects[0] = SMB2_VERSION_0202;
        req.dialects[1] = SMB2_VERSION_0210;
        memcpy(req.client_guid, smb2_get_client_guid(smb2), 16);

	if (smb2_negotiate_async(smb2, &req, negotiate_cb, NULL) != 0) {
		printf("smb2_negotiate failed. %s\n", smb2_get_error(smb2));
		exit(10);
	}
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
	struct pollfd pfd;

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

	if (smb2_connect_async(smb2, url->server, connect_cb, NULL) != 0) {
		printf("smb2_connect failed. %s\n", smb2_get_error(smb2));
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
