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

#include <gssapi/gssapi.h>

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

/* FIXME: this should not be global but passed down via private_data */
char *g_server;

gss_OID_desc gss_mech_spnego = {
    6, "\x2b\x06\x01\x05\x05\x02"
};

struct private_auth_data {
    gss_ctx_id_t context;
    gss_cred_id_t cred;
    gss_name_t target_name;
    gss_OID mech_type;
    uint32_t req_flags;
};

static char *display_status(int type, uint32_t err)
{
    gss_buffer_desc text;
    uint32_t msg_ctx;
    char *msg, *tmp;
    uint32_t maj, min;

    msg = NULL;
    msg_ctx = 0;
    do {
        maj = gss_display_status(&min, err, type,
                                 GSS_C_NO_OID, &msg_ctx, &text);
        if (maj != GSS_S_COMPLETE) {
            return msg;
        }

        tmp = NULL;
        if (msg) {
            tmp = msg;
            min = asprintf(&msg, "%s, %*s", msg,
                           (int)text.length, (char *)text.value);
        } else {
            min = asprintf(&msg, "%*s", (int)text.length, (char *)text.value);
        }
        if (min == -1) return tmp;
        free(tmp);
        gss_release_buffer(&min, &text);
    } while (msg_ctx != 0);

    return msg;
}

void session_setup_cb(struct smb2_context *smb2, int status,
                void *command_data, void *private_data)
{
        struct session_setup_reply *rep = command_data;
        struct private_auth_data *auth_data =
                (struct private_auth_data *)private_data;
        gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
        uint32_t maj, min;

	printf("Session Setup:0x%08x\n", status);

	printf("Security buffer offset:0x%08x\n", rep->security_buffer_offset);
	printf("Security buffer length:%d\n", rep->security_buffer_length);

        printf("SESSION SETUP Sec blob [%02x][%02x][%02x]...\n",
               (unsigned char)rep->security_buffer[0],
               (unsigned char)rep->security_buffer[1],
               (unsigned char)rep->security_buffer[2]);

        input_token.length = rep->security_buffer_length;
        input_token.value = rep->security_buffer;

        maj = gss_init_sec_context(&min, auth_data->cred,
                                   &auth_data->context,
                                   auth_data->target_name,
                                   auth_data->mech_type,
                                   GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG |
                                   GSS_C_REPLAY_FLAG |
                                   /* TODO: sign/seal ito be set as needed */
                                   GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG,
                                   GSS_C_INDEFINITE,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &input_token,
                                   NULL,
                                   &output_token,
                                   NULL,
                                   NULL);
        if (GSS_ERROR(maj)) {
                char *err_maj = display_status(GSS_C_GSS_CODE, maj);
                char *err_min = display_status(GSS_C_MECH_CODE, min);
                printf("init_sec_context: (%s, %s)\n", err_maj, err_min);
                free(err_min);
                free(err_maj);
                exit(55);
        }

        if (maj == GSS_S_CONTINUE_NEEDED) {
                struct session_setup_request req;
                /* Session setup request. */
                memset(&req, 0, sizeof(struct session_setup_request));
                req.struct_size = SESSION_SETUP_REQUEST_SIZE;
                req.security_buffer_offset = 0x58;
                req.security_buffer_length = output_token.length;
                req.security_buffer = output_token.value;

                /* TODO: need to free output_token */

	        if (smb2_session_setup_async(smb2, &req, session_setup_cb,
                                             auth_data) != 0) {
                        printf("smb2_session_setup failed. %s\n",
                               smb2_get_error(smb2));
                        exit(10);
                }
        } else {
            /* TODO: cleanup auth_data and buffers */
        }
}

void negotiate_cb(struct smb2_context *smb2, int status,
                void *command_data, void *private_data)
{
        struct negotiate_reply *rep = command_data;
        struct session_setup_request req;
        struct private_auth_data *auth_data;
        gss_buffer_desc target = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
        uint32_t maj, min;

        auth_data = calloc(1, sizeof(*auth_data));

        target.value = g_server;
        target.length = strlen(g_server);

        maj = gss_import_name(&min, &target, GSS_C_NT_HOSTBASED_SERVICE,
                              &auth_data->target_name);
        if (maj != GSS_S_COMPLETE) {
                /* FIXME: print error with gss_display_status wrapper */
                exit(55);
        }

        /* TODO: acquire cred before hand if not using default creds,
         * with gss_acquire_cred_from() or gss_acquire_cred_with_password()
         */
        auth_data->cred = GSS_C_NO_CREDENTIAL;

        /* TODO: the proper mechanism (SPNEGO vs NTLM vs KRB5) should be
         * selected based on the SMB negotiation flags */
        auth_data->mech_type = &gss_mech_spnego;

        /* NOTE: this call is not async, a helper thread should be used if that
         * is an issue */
        maj = gss_init_sec_context(&min, auth_data->cred,
                                   &auth_data->context,
                                   auth_data->target_name,
                                   auth_data->mech_type,
                                   GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG |
                                   GSS_C_REPLAY_FLAG |
                                   /* TODO: sign/seal ito be set as needed */
                                   GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG,
                                   GSS_C_INDEFINITE,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   NULL,
                                   NULL,
                                   &output_token,
                                   NULL,
                                   NULL);
        if (GSS_ERROR(maj)) {
                char *err_maj = display_status(GSS_C_GSS_CODE, maj);
                char *err_min = display_status(GSS_C_MECH_CODE, min);
                printf("init_sec_context: (%s, %s)\n", err_maj, err_min);
                free(err_min);
                free(err_maj);
                exit(55);
        }

	printf("Negotiate status:0x%08x\n", status);
        printf("max transaction size:%d\n", rep->max_transact_size);

	if (status != STATUS_SUCCESS) {
		printf("negotiate_cb: connection failed : %s\n",
                       smb2_get_error(smb2));
		exit(10);
	}

        printf("NEGOTIATE Sec blob [%02x][%02x][%02x]...\n",
               (unsigned char)rep->security_buffer[0],
               (unsigned char)rep->security_buffer[1],
               (unsigned char)rep->security_buffer[2]);
        
        /* Session setup request. */
        memset(&req, 0, sizeof(struct session_setup_request));
        req.struct_size = SESSION_SETUP_REQUEST_SIZE;
        req.security_buffer_offset = 0x58;
        req.security_buffer_length = output_token.length;
        req.security_buffer = output_token.value;

        /* TODO: need to free output_token */

	if (smb2_session_setup_async(smb2, &req, session_setup_cb,
                                     auth_data) != 0) {
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

        /* FIXME: move in negotiate_cb */
        asprintf(&g_server, "cifs@%s", url->server);

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
