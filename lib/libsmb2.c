/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef STDC_HEADERS
#include <stddef.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <gssapi/gssapi.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

static gss_OID_desc gss_mech_spnego = {
    6, "\x2b\x06\x01\x05\x05\x02"
};

struct private_auth_data {
        gss_ctx_id_t context;
        gss_cred_id_t cred;
        gss_name_t target_name;
        gss_OID mech_type;
        uint32_t req_flags;
        gss_buffer_desc output_token;
};

struct connect_data {
        smb2_command_cb cb;
        void *cb_data;
        char *g_server;

        const char *server;
        const char *share;

        /* UNC for the share in utf8 as well as ucs2 formats */
        char *utf8_unc;
        struct ucs2 *ucs2_unc;
                
        struct private_auth_data *auth_data;
};

static int
send_session_setup_request(struct smb2_context *smb2,
                           struct connect_data *c_data,
                           gss_buffer_desc *input_token);

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
                        min = asprintf(&msg, "%*s", (int)text.length,
                                       (char *)text.value);
                }
                if (min == -1) return tmp;
                free(tmp);
                gss_release_buffer(&min, &text);
        } while (msg_ctx != 0);

        return msg;
}

static void set_gss_error(struct smb2_context *smb2, char *func,
                          uint32_t maj, uint32_t min)
{
        char *err_maj = display_status(GSS_C_GSS_CODE, maj);
        char *err_min = display_status(GSS_C_MECH_CODE, min);
        smb2_set_error(smb2, "%s: (%s, %s)", func, err_maj, err_min);
        free(err_min);
        free(err_maj);
}

static void free_auth_data(struct private_auth_data *auth)
{
        uint32_t maj, min;

        /* Delete context */
        if (auth->context) {
                maj = gss_delete_sec_context(&min, &auth->context,
                                             &auth->output_token);
                if (maj != GSS_S_COMPLETE) {
                        /* No logging, yet. Do we care? */
                }
        }
        /* Free output_token */
        gss_release_buffer(&min, &auth->output_token);

        /* Free the target name */
        if (auth->target_name) {
                gss_release_name(&min, &auth->target_name);
        }

        free(auth);
}

static void free_c_data(struct connect_data *c_data)
{
        if (c_data->auth_data) {
                free_auth_data(c_data->auth_data);
        }

        free(c_data->utf8_unc);
        free(c_data->ucs2_unc);
        free(c_data->g_server);
        free(discard_const(c_data->server));
        free(discard_const(c_data->share));
        free(c_data);
}


static void
tree_connect_cb(struct smb2_context *smb2, int status,
                void *command_data, void *private_data)
{
        struct connect_data *c_data = private_data;

        if (status != STATUS_SUCCESS) {
                smb2_set_error(smb2, "Session setup failed.\n");
                c_data->cb(smb2, -1, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }

        c_data->cb(smb2, status, NULL, c_data->cb_data);
        free_c_data(c_data);
}

static void
session_setup_cb(struct smb2_context *smb2, int status,
                 void *command_data, void *private_data)
{
        struct connect_data *c_data = private_data;
        struct session_setup_reply *rep = command_data;
        struct tree_connect_request req;
        gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
        uint32_t min;

        /* release the previous token */
        gss_release_buffer(&min, &c_data->auth_data->output_token);
        c_data->auth_data->output_token.length = 0;
        c_data->auth_data->output_token.value = NULL;
        
        if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                input_token.length = rep->security_buffer_length;
                input_token.value = rep->security_buffer;

                if (send_session_setup_request(smb2, c_data,
                                               &input_token) < 0) {
                        c_data->cb(smb2, -1, NULL, c_data->cb_data);
                        free_c_data(c_data);
                        return;
                }
                return;
        }

        if (status != STATUS_SUCCESS) {
                smb2_set_error(smb2, "Session setup failed.\n");
                c_data->cb(smb2, -1, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }

        memset(&req, 0, sizeof(struct tree_connect_request));
        req.struct_size = TREE_CONNECT_REQUEST_SIZE;
        req.flags       = 0;
        req.path_offset = 0x48;
        req.path_length = 2 * c_data->ucs2_unc->len;
        req.path        = c_data->ucs2_unc->val;
        if (smb2_tree_connect_async(smb2, &req, tree_connect_cb,
                                    c_data) != 0) {
                printf("smb2_tree_connect failed. %s\n",
                       smb2_get_error(smb2));
                c_data->cb(smb2, -1, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }
}

static int
send_session_setup_request(struct smb2_context *smb2,
                           struct connect_data *c_data,
                           gss_buffer_desc *input_token)
{
        uint32_t maj, min;
        struct session_setup_request req;
        
        /* NOTE: this call is not async, a helper thread should be used if that
         * is an issue */
        maj = gss_init_sec_context(&min, c_data->auth_data->cred,
                                   &c_data->auth_data->context,
                                   c_data->auth_data->target_name,
                                   c_data->auth_data->mech_type,
                                   GSS_C_SEQUENCE_FLAG |
                                   GSS_C_MUTUAL_FLAG |
                                   GSS_C_REPLAY_FLAG |
                                   ((smb2->security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED)?GSS_C_INTEG_FLAG:0),
                                   GSS_C_INDEFINITE,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   input_token,
                                   NULL,
                                   &c_data->auth_data->output_token,
                                   NULL,
                                   NULL);
        if (GSS_ERROR(maj)) {
                set_gss_error(smb2, "gss_init_sec_context", maj, min);
                return -1;
        }

        if (maj == GSS_S_CONTINUE_NEEDED) {
                /* Session setup request. */
                memset(&req, 0, sizeof(struct session_setup_request));
                req.struct_size = SESSION_SETUP_REQUEST_SIZE;
                req.security_mode = smb2->security_mode;
                req.security_buffer_offset = 0x58;
                req.security_buffer_length = c_data->auth_data->output_token.length;
                req.security_buffer = c_data->auth_data->output_token.value;
                
                if (smb2_session_setup_async(smb2, &req, session_setup_cb,
                                             c_data) != 0) {
                        return -1;
                }
        } else {
                /* TODO: cleanup and fail */
        }
        
        return 0;
}

static void
negotiate_cb(struct smb2_context *smb2, int status,
             void *command_data, void *private_data)
{
        struct connect_data *c_data = private_data;
        gss_buffer_desc target = GSS_C_EMPTY_BUFFER;
        uint32_t maj, min;
        
        if (status != STATUS_SUCCESS) {
                c_data->cb(smb2, -1, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }

        c_data->auth_data = malloc(sizeof(struct private_auth_data));
        if (c_data->auth_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate private_auth_data\n");
                c_data->cb(smb2, -1, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }
        memset(c_data->auth_data, 0, sizeof(struct private_auth_data));
        c_data->auth_data->context = GSS_C_NO_CONTEXT;
                
        if (asprintf(&c_data->g_server, "cifs@%s", c_data->server) < 0) {
                smb2_set_error(smb2, "Failed to allocate server string\n");
                c_data->cb(smb2, -1, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }

        target.value = c_data->g_server;
        target.length = strlen(c_data->g_server);

        maj = gss_import_name(&min, &target, GSS_C_NT_HOSTBASED_SERVICE,
                              &c_data->auth_data->target_name);

        if (maj != GSS_S_COMPLETE) {
                set_gss_error(smb2, "gss_import_name", maj, min);
                c_data->cb(smb2, -1, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }

        /* TODO: acquire cred before hand if not using default creds,
         * with gss_acquire_cred_from() or gss_acquire_cred_with_password()
         */
        c_data->auth_data->cred = GSS_C_NO_CREDENTIAL;

        /* TODO: the proper mechanism (SPNEGO vs NTLM vs KRB5) should be
         * selected based on the SMB negotiation flags */
        c_data->auth_data->mech_type = &gss_mech_spnego;

        if (send_session_setup_request(smb2, c_data, NULL) < 0) {
                c_data->cb(smb2, -1, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }
}

static void
connect_cb(struct smb2_context *smb2, int status,
           void *command_data _U_, void *private_data)
{
        struct connect_data *c_data = private_data;
        struct negotiate_request req;

        if (status != 0) {
                smb2_set_error(smb2, "Failed to connect socket. errno:%d\n",
                               errno);
                c_data->cb(smb2, -1, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }
        
        memset(&req, 0, sizeof(struct negotiate_request));
        req.struct_size = NEGOTIATE_REQUEST_SIZE;
        req.dialect_count = SMB2_NUM_DIALECTS;
        req.security_mode = smb2->security_mode;
        req.dialects[0] = SMB2_VERSION_0202;
        req.dialects[1] = SMB2_VERSION_0210;
        memcpy(req.client_guid, smb2_get_client_guid(smb2), 16);

        if (smb2_negotiate_async(smb2, &req, negotiate_cb, c_data) != 0) {
                c_data->cb(smb2, -1, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }
}

int smb2_connect_share_async(struct smb2_context *smb2,
                             const char *server, const char *share,
                             smb2_command_cb cb, void *private_data)
{
        struct connect_data *c_data;

        c_data = malloc(sizeof(struct connect_data));
        if (c_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate connect_data\n");
                return -1;
        }
        memset(c_data, 0, sizeof(struct connect_data));
        c_data->server = strdup(server);
        if (c_data->server == NULL) {
                free_c_data(c_data);
                smb2_set_error(smb2, "Failed to strdup(server)\n");
                return -1;
        }
        c_data->share = strdup(share);
        if (c_data->share == NULL) {
                free_c_data(c_data);
                smb2_set_error(smb2, "Failed to strdup(server)\n");
                return -1;
        }
        if (asprintf(&c_data->utf8_unc, "\\\\%s\\%s", c_data->server,
                     c_data->share) < 0) {
                free_c_data(c_data);
                smb2_set_error(smb2, "Failed to allocate unc string.\n");
                return -1;
        }

        c_data->ucs2_unc = utf8_to_ucs2(c_data->utf8_unc);
        if (c_data->ucs2_unc == NULL) {
                free_c_data(c_data);
                smb2_set_error(smb2, "Count not convert UNC:[%s] into UCS2\n",
                               c_data->utf8_unc);
                return -1;
        }
                
        c_data->cb = cb;
        c_data->cb_data = private_data;
 
        if (smb2_connect_async(smb2, server, connect_cb, c_data) != 0) {
                free_c_data(c_data);
                return -1;
        }

        return 0;
}
