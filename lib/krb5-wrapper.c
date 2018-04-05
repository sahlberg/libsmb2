/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2018 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#ifdef HAVE_LIBKRB5

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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <krb5/krb5.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi.h>
#include <stdio.h>

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

#include "krb5-wrapper.h"

/** Global Definitions */
krb5_context    krb5_cctx;
krb5_ccache     krb5_Ccache;
krb5_creds      krb5_ccreds;
krb5_principal  client_princ;


void
krb5_free_auth_data(struct private_auth_data *auth)
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

        gss_release_buffer(&min, &auth->output_token);

        if (auth->target_name) {
                gss_release_name(&min, &auth->target_name);
        }

        if (auth->user_name) {
                gss_release_name(&min, &auth->user_name);
        }

        free(auth->g_server);
        free(auth);
}

static char *
display_status(int type, uint32_t err)
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

void
krb5_set_gss_error(struct smb2_context *smb2, char *func,
                   uint32_t maj, uint32_t min)
{
        char *err_maj = display_status(GSS_C_GSS_CODE, maj);
        char *err_min = display_status(GSS_C_MECH_CODE, min);
        smb2_set_error(smb2, "%s: (%s, %s)", func, err_maj, err_min);
        free(err_min);
        free(err_maj);
}

struct private_auth_data *
krb5_negotiate_reply(struct smb2_context *smb2,
                     const char *server,
                     const char *domain,
                     const char *user_name,
                     const char *password)
{
        struct private_auth_data *auth_data;
        gss_buffer_desc target = GSS_C_EMPTY_BUFFER;
        uint32_t maj, min;
        gss_buffer_desc user;
        char user_principal[2048];
        char *nc_password = NULL;
        gss_buffer_desc passwd;
        gss_OID_set_desc mechOidSet;
        gss_OID_set_desc wantMech;

        auth_data = malloc(sizeof(struct private_auth_data));
        if (auth_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate private_auth_data");
                return NULL;
        }
        memset(auth_data, 0, sizeof(struct private_auth_data));
        auth_data->context = GSS_C_NO_CONTEXT;

        if (asprintf(&auth_data->g_server, "cifs@%s", server) < 0) {
                smb2_set_error(smb2, "Failed to allocate server string");
                return NULL;
        }

        target.value = auth_data->g_server;
        target.length = strlen(auth_data->g_server);

        maj = gss_import_name(&min, &target, GSS_C_NT_HOSTBASED_SERVICE,
                              &auth_data->target_name);

        if (maj != GSS_S_COMPLETE) {
                krb5_set_gss_error(smb2, "gss_import_name", maj, min);
                return NULL;
        }

        memset(&user_principal[0], 0, 2048);
        if (sprintf(&user_principal[0], "%s@%s", user_name, domain) < 0) {
                smb2_set_error(smb2, "Failed to allocate user principal");
                return NULL;
        }

        if (smb2->use_cached_creds) {
            user.value = discard_const(user_principal);
            user.length = strlen(user_principal);
        } else {
            user.value = discard_const(user_name);
            user.length = strlen(user_name);
        }

        /* create a name for the user */
        maj = gss_import_name(&min, &user, GSS_C_NT_USER_NAME,
                              &auth_data->user_name);

        if (maj != GSS_S_COMPLETE) {
                krb5_set_gss_error(smb2, "gss_import_name", maj, min);
                return NULL;
        }

        /* TODO: the proper mechanism (SPNEGO vs NTLM vs KRB5) should be
         * selected based on the SMB negotiation flags */
        auth_data->mech_type = &gss_mech_spnego;
        auth_data->cred = GSS_C_NO_CREDENTIAL;

        /* Create creds for the user */
        mechOidSet.count = 1;
        mechOidSet.elements = discard_const(&gss_mech_spnego);

        nc_password = strdup(password);
        passwd.value = nc_password;
        passwd.length = strlen(nc_password);


        if (smb2->use_cached_creds) {
            maj = gss_acquire_cred_with_password(&min, auth_data->user_name, &passwd, 0,
                                                 &mechOidSet, GSS_C_INITIATE, &auth_data->cred,
                                                 NULL, NULL);
        } else {
            maj = gss_acquire_cred(&min, auth_data->user_name, 0,
                                   &mechOidSet, GSS_C_INITIATE,
                                   &auth_data->cred, NULL, NULL);
        }

        if (maj != GSS_S_COMPLETE) {
            krb5_set_gss_error(smb2, "gss_acquire_cred", maj, min);
            return NULL;
        }

        if (smb2->sec != SMB2_SEC_UNDEFINED) {
                wantMech.count = 1;
                if (smb2->sec == SMB2_SEC_KRB5) {
                        wantMech.elements = discard_const(&spnego_mech_krb5);
                } else if (smb2->sec == SMB2_SEC_NTLMSSP) {
                        wantMech.elements = discard_const(&spnego_mech_ntlmssp);
                }

                maj = gss_set_neg_mechs(&min, auth_data->cred, &wantMech);
                if (GSS_ERROR(maj)) {
                        krb5_set_gss_error(smb2, "gss_set_neg_mechs", maj, min);
                        return NULL;
                }
        }

        if (nc_password)
        {
            free(nc_password);
            nc_password = NULL;
        }

        return auth_data;
}

int
krb5_session_request(struct smb2_context *smb2,
                     struct private_auth_data *auth_data,
                     unsigned char *buf, int len)
{
        uint32_t maj, min;
        gss_buffer_desc *input_token = NULL;
        gss_buffer_desc token = GSS_C_EMPTY_BUFFER;

        if (buf) {
                /* release the previous token */
                gss_release_buffer(&min, &auth_data->output_token);
                auth_data->output_token.length = 0;
                auth_data->output_token.value = NULL;

                token.value = buf;
                token.length = len;
                input_token = &token;
        }

        /* TODO return -errno instead of just -1 */
        /* NOTE: this call is not async, a helper thread should be used if that
         * is an issue */
        maj = gss_init_sec_context(&min, auth_data->cred,
                                   &auth_data->context,
                                   auth_data->target_name,
                                   discard_const(auth_data->mech_type),
                                   GSS_C_SEQUENCE_FLAG |
                                   GSS_C_MUTUAL_FLAG |
                                   GSS_C_REPLAY_FLAG |
                                   0, //GSS_C_INTEG_FLAG,
                                   GSS_C_INDEFINITE,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   input_token,
                                   NULL,
                                   &auth_data->output_token,
                                   NULL,
                                   NULL);
        if (GSS_ERROR(maj)) {
                krb5_set_gss_error(smb2, "gss_init_sec_context", maj, min);
                return -1;
        }

        return 0;
}

int
krb5_get_output_token_length(struct private_auth_data *auth_data)
{
        return auth_data->output_token.length;
}

unsigned char *
krb5_get_output_token_buffer(struct private_auth_data *auth_data)
{
        return auth_data->output_token.value;
}

#endif /* HAVE_LIBKRB5 */
