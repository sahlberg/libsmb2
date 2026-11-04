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

#ifdef HAVE_SYS_UNISTD_H
#include <sys/unistd.h>
#endif

/* Use Apple's GSS.framework only where it actually exists (issue #476);
 * otherwise fall back to the normal Unix gssapi/gssapi.h codepath, e.g.
 * when linking against a Heimdal/MIT krb5 install on macOS. */
#if defined(__APPLE__) && defined(HAVE_GSS_GSS_H)
#include <GSS/GSS.h>
#else
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi.h>
#endif
#include <stdio.h>

#include "compat.h"

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

#include "krb5-wrapper.h"
#include "spnego-wrapper.h"

/* 1.3.6.1.5.2.5. gss_mech_iakerb is MIT only. */
static unsigned char smb2_iakerb_oid[] = { 0x2b, 0x06, 0x01, 0x05, 0x02, 0x05 };
#if !(defined(__APPLE__) && defined(HAVE_GSS_GSS_H))
static gss_OID_desc smb2_mech_iakerb = { sizeof(smb2_iakerb_oid), smb2_iakerb_oid };
#endif
/* DER mechTypes of our NegTokenInit, the input to SPNEGO's mechListMIC */
static unsigned char iakerb_mech_types[] = {
        0x30, 0x08, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x02, 0x05
};

/* 1.2.840.113554.1.2.2 */
static const unsigned char smb2_krb5_oid[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };

/*
 * Windows runs the IAKerb proxy messages under the IAKerb OID but the AP
 * exchange that follows under the krb5 OID, while MIT keeps the IAKerb OID
 * throughout. The OID in the GSS token header is not covered by any
 * checksum, so swap it. Returns a new token, or NULL if tok is not framed
 * with from, or if it is an IAKerb proxy message (TOK_ID 05 01) and
 * keep_proxy is set.
 */
static unsigned char *
iakerb_reframe(const unsigned char *tok, size_t len,
               const unsigned char *from, size_t from_len,
               const unsigned char *to, size_t to_len,
               int keep_proxy, size_t *out_len)
{
        size_t pos = 2, body, rest_len, inner_len, i;
        const unsigned char *rest;
        unsigned char *out;

        if (len < 2 || tok[0] != 0x60) {
                return NULL;
        }
        if (tok[1] < 0x80) {
                body = tok[1];
        } else {
                size_t n = tok[1] & 0x7f;

                if (n == 0 || n > 3 || len < 2 + n) {
                        return NULL;
                }
                for (body = 0, i = 0; i < n; i++) {
                        body = (body << 8) | tok[2 + i];
                }
                pos += n;
        }
        if (pos + body != len || body < 2 + from_len ||
            tok[pos] != 0x06 || tok[pos + 1] != from_len ||
            memcmp(&tok[pos + 2], from, from_len)) {
                return NULL;
        }
        rest = &tok[pos + 2 + from_len];
        rest_len = len - (pos + 2 + from_len);
        if (keep_proxy && rest_len >= 2 && rest[0] == 0x05 && rest[1] == 0x01) {
                return NULL;
        }

        inner_len = 2 + to_len + rest_len;
        out = malloc(inner_len + 5);
        if (out == NULL) {
                return NULL;
        }
        pos = 0;
        out[pos++] = 0x60;
        if (inner_len < 0x80) {
                out[pos++] = (unsigned char)inner_len;
        } else if (inner_len < 0x100) {
                out[pos++] = 0x81;
                out[pos++] = (unsigned char)inner_len;
        } else if (inner_len < 0x10000) {
                out[pos++] = 0x82;
                out[pos++] = (unsigned char)(inner_len >> 8);
                out[pos++] = (unsigned char)inner_len;
        } else {
                out[pos++] = 0x83;
                out[pos++] = (unsigned char)(inner_len >> 16);
                out[pos++] = (unsigned char)(inner_len >> 8);
                out[pos++] = (unsigned char)inner_len;
        }
        out[pos++] = 0x06;
        out[pos++] = (unsigned char)to_len;
        memcpy(&out[pos], to, to_len);
        pos += to_len;
        memcpy(&out[pos], rest, rest_len);
        *out_len = pos + rest_len;
        return out;
}

void
krb5_free_auth_data(struct private_auth_data *auth)
{
        uint32_t maj, min;

        gss_release_buffer(&min, &auth->output_token);
        free(auth->spnego_buf);
        auth->spnego_buf = NULL;

        if (auth->krb5_Ccache) {
                krb5_cc_destroy(auth->krb5_cctx, auth->krb5_Ccache);
                krb5_free_context(auth->krb5_cctx);
        }

        /* Delete context */
        if (auth->context) {
                maj = gss_delete_sec_context(&min, &auth->context,
                                             &auth->output_token);
                if (maj != GSS_S_COMPLETE) {
                        /* No logging, yet. Do we care? */
                }
        }

        if (auth->target_name) {
                gss_release_name(&min, &auth->target_name);
        }

        if (auth->user_name) {
                gss_release_name(&min, &auth->user_name);
        }

        if (auth->cred) {
                gss_release_cred(&min, &auth->cred);
        }
        if (auth->iakerb_cred) {
                gss_release_cred(&min, &auth->iakerb_cred);
        }
        free(auth->mech_types);

        free(auth->g_server);
        free(auth);
}

static char *
display_status(int type, uint32_t err)
{
        gss_buffer_desc text;
        uint32_t msg_ctx;
        char *msg, *tmp, *tv;
        uint32_t maj, min;

        if (asprintf(&msg, " ") < 0) {
                return NULL;
        }
        msg_ctx = 0;
        do {
                maj = gss_display_status(&min, err, type,
                                         GSS_C_NO_OID, &msg_ctx, &text);
                if (maj != GSS_S_COMPLETE) {
                        return msg;
                }

                tv = malloc(text.length + 4);
                if (tv) {
                        memcpy(tv, text.value, text.length);
                        tv[text.length] = 0;

                        tmp = NULL;
                        if (msg) {
                                tmp = msg;
                                min = asprintf(&msg, "%s, %s", tmp, tv);
                                free(tmp);
                        } else {
                                min = asprintf(&msg, "%s", tv);
                        }
                        free(tv);
                        if (min == -1) {
                               return msg;
                        }
                }
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
        if (smb2) {
                smb2_set_error(smb2, "%s: (%s, %s)", func, err_maj, err_min);
        }
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
        char *spos;
        gss_buffer_desc passwd;
        gss_OID_set_desc mechOidSet;
        gss_OID name_type = GSS_C_NT_HOSTBASED_SERVICE;

        /* IAKerb builds the AS-REQ locally from the password. A ccache
         * primed by kinit cannot be obtained while the KDC is unreachable. */
        if (smb2->sec == SMB2_SEC_IAKERB) {
                smb2->use_cached_creds = 1;
        }

        if (smb2->use_cached_creds) {
                /* Validate the parameters */
                if (domain == NULL || password == NULL) {
                        smb2_set_error(smb2, "domain and password must be set "
                                       "for krb5cc and iakerb");
                        return NULL;
                }
        }

        auth_data = calloc(1, sizeof(struct private_auth_data));
        if (auth_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate private_auth_data");
                krb5_free_auth_data(auth_data);
                return NULL;
        }
        auth_data->context = GSS_C_NO_CONTEXT;

        /* strip any port off server */
        strncpy(user_principal, server, sizeof(user_principal) - 1);
        user_principal[sizeof(user_principal) - 1] = '\0';
        spos = strchr(user_principal, ':');
        if (spos) {
                *spos = '\0';
        }
        /* form spn cifs/hostname.domain.
         * IAKerb puts the target realm in the proxy header. A host-based
         * name takes that realm from krb5.conf, which this client may not
         * have, because it never talks to the KDC itself. Use the domain
         * from the URL as the realm: cifs/host@REALM. */
        if (smb2->sec == SMB2_SEC_IAKERB) {
#if defined(__APPLE__) && defined(HAVE_GSS_GSS_H)
                smb2_set_error(smb2, "IAKerb is not supported with Apple GSS");
                krb5_free_auth_data(auth_data);
                return NULL;
#else
                if (domain[0] == '\0') {
                        smb2_set_error(smb2, "IAKerb requires a Kerberos realm "
                                       "in the domain");
                        krb5_free_auth_data(auth_data);
                        return NULL;
                }
                if (asprintf(&auth_data->g_server, "cifs/%s@%s",
                             user_principal, domain) < 0) {
                        smb2_set_error(smb2, "Failed to allocate server string");
                        krb5_free_auth_data(auth_data);
                        return NULL;
                }
                name_type = (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME;
#endif
        } else if (asprintf(&auth_data->g_server, "cifs@%s", user_principal) < 0) {
                smb2_set_error(smb2, "Failed to allocate server string");
                krb5_free_auth_data(auth_data);
                return NULL;
        }

        target.value = auth_data->g_server;
        target.length = strlen(auth_data->g_server);

        maj = gss_import_name(&min, &target, name_type,
                              &auth_data->target_name);

        if (maj != GSS_S_COMPLETE) {
                krb5_set_gss_error(smb2, "gss_import_name", maj, min);
                krb5_free_auth_data(auth_data);
                return NULL;
        }

        /* if there is a delegated credential in the context, just use that
        */
        if (smb2->cred_handle) {
                auth_data->cred = smb2->cred_handle;
                smb2->cred_handle = NULL;
                return auth_data;
        }

        /* using cached-creds with a memory-cache means the password supplied as
         * a parameter is used to setup the ticket, as opposed to having to do
         * a "kinit user" in the environment.  this cache does not persist
         */
        if (smb2->use_cached_creds) {
                memset(&user_principal[0], 0, sizeof(user_principal));
                if (snprintf(&user_principal[0], sizeof(user_principal),
                                "%s@%s", user_name, domain) < 0) {
                        smb2_set_error(smb2, "Failed to generate user principal");
                        return NULL;
                }
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
                krb5_free_auth_data(auth_data);
                return NULL;
        }

        /* TODO: the proper mechanism (SPNEGO vs NTLM vs KRB5) should be
         * selected based on the SMB negotiation flags */
        #if defined(__APPLE__) && defined(HAVE_GSS_GSS_H)
        auth_data->mech_type = auth_data->use_spnego ? GSS_SPNEGO_MECHANISM : GSS_KRB5_MECHANISM;
        #else
        /* IAKerb is GSS_C_MA_NOT_DFLT_MECH, so a SPNEGO password cred does
         * not carry it. Acquire the IAKerb mech directly; the session
         * request wraps the tokens in SPNEGO for Windows Negotiate. */
        if (smb2->sec == SMB2_SEC_IAKERB) {
                auth_data->mech_type = &smb2_mech_iakerb;
        } else {
                auth_data->mech_type = auth_data->use_spnego ? &gss_mech_spnego : gss_mech_krb5;
        }
        #endif

        /* Create creds for the user */
        mechOidSet.count = 1;
        mechOidSet.elements = discard_const(auth_data->mech_type);

        auth_data->cred = GSS_C_NO_CREDENTIAL;

        if (smb2->use_cached_creds) {
                krb5_error_code ret = 0;
                const char *cname = NULL;

                /* krb5 cache management */
                ret = krb5_init_context(&auth_data->krb5_cctx);
                if (ret) {
                        smb2_set_error(smb2, "Failed to initialize krb5 context - %s",
                                        krb5_get_error_message(auth_data->krb5_cctx, ret));
                        return NULL;
                }
                ret = krb5_cc_new_unique(auth_data->krb5_cctx, "MEMORY", NULL, &auth_data->krb5_Ccache);
                if (ret != 0) {
                        smb2_set_error(smb2, "Failed to create krb5 credentials cache - %s",
                                        krb5_get_error_message(auth_data->krb5_cctx, ret));
                        krb5_free_auth_data(auth_data);
                        return NULL;
                }
                cname = krb5_cc_get_name(auth_data->krb5_cctx, auth_data->krb5_Ccache);
                if (cname == NULL) {
                        smb2_set_error(smb2, "Failed to retrieve the credentials cache name");
                        krb5_free_auth_data(auth_data);
                        return NULL;
                }

                maj = gss_krb5_ccache_name(&min, cname, NULL);
                if (maj != GSS_S_COMPLETE) {
                        krb5_set_gss_error(smb2, "gss_krb5_ccache_name", maj, min);
                        krb5_free_auth_data(auth_data);
                        return NULL;
                }

                nc_password = strdup(password);
                passwd.value = nc_password;
                passwd.length = strlen(nc_password);

                maj = gss_acquire_cred_with_password(&min, auth_data->user_name, &passwd, 0,
                                                     &mechOidSet, GSS_C_INITIATE, &auth_data->cred,
                                                     NULL, NULL);
        } else {
                maj = gss_acquire_cred(&min, auth_data->user_name, 0,
                                       &mechOidSet, GSS_C_INITIATE, &auth_data->cred,
                                       NULL, NULL);
        }

        if (maj != GSS_S_COMPLETE) {
                        krb5_set_gss_error(smb2, "gss_acquire_cred (client)", maj, min);
                        krb5_free_auth_data(auth_data);
                        return NULL;
        }
        #if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H) /* gss_set_neg_mechs is not defined by Apple's GSS.framework. */
        #ifdef SMB2_USER_KRB5_FOR_NTLLM
        if (smb2->sec != SMB2_SEC_UNDEFINED) {
                gss_OID_set_desc wantMech;

                wantMech.count = 1;
                if (smb2->sec == SMB2_SEC_KRB5) {
                        wantMech.elements = discard_const(&spnego_mech_krb5);
                } else if (smb2->sec == SMB2_SEC_NTLMSSP) {
                        wantMech.elements = discard_const(&spnego_mech_ntlmssp);
                }

                maj = gss_set_neg_mechs(&min, auth_data->cred, &wantMech);
                if (GSS_ERROR(maj)) {
                        krb5_set_gss_error(smb2, "gss_set_neg_mechs", maj, min);
                        krb5_free_auth_data(auth_data);
                        return NULL;
                }
        }
        #endif
        #endif

        if (nc_password) {
                free(nc_password);
                nc_password = NULL;
        }

        return auth_data;
}

int
krb5_session_get_session_key(struct smb2_context *smb2,
                             struct private_auth_data *auth_data)
{
        /* Get the Session Key */
        uint32_t gssMajor, gssMinor;
        gss_buffer_set_t sessionKey = NULL;

        gssMajor = gss_inquire_sec_context_by_oid(
                           &gssMinor,
                           auth_data->context,
                           GSS_C_INQ_SSPI_SESSION_KEY,
                           &sessionKey);
        if (gssMajor != GSS_S_COMPLETE) {
                krb5_set_gss_error(smb2, "gss_inquire_sec_context_by_oid",
                                   gssMajor, gssMinor);
                return -1;
        }

        /* The key is in element 0 and the key type OID is in element 1 */
        if (!sessionKey ||
            (sessionKey->count < 1) ||
            !sessionKey->elements[0].value ||
            (0 == sessionKey->elements[0].length)) {
                smb2_set_error(smb2, "Invalid session key");
                return -1;
        }

        smb2->session_key = (uint8_t *) malloc(sessionKey->elements[0].length);
        if (smb2->session_key == NULL) {
                smb2_set_error(smb2, "Failed to allocate SessionKey");
                return -1;
        }
        memset(smb2->session_key, 0, sessionKey->elements[0].length);
        memcpy(smb2->session_key, sessionKey->elements[0].value,
               sessionKey->elements[0].length);
        smb2->session_key_size = sessionKey->elements[0].length;

        gss_release_buffer_set(&gssMinor, &sessionKey);

        return 0;
}

/* RFC 4178: a mechListMIC from the acceptor must verify. */
static int
iakerb_verify_acceptor_mic(struct smb2_context *smb2,
                           struct private_auth_data *auth_data,
                           const unsigned char *buf, int len)
{
        gss_buffer_desc msg = { sizeof(iakerb_mech_types), iakerb_mech_types };
        gss_buffer_desc mic;
        const uint8_t *p;
        uint32_t maj, min;
        int n;

        if (buf == NULL || auth_data->iakerb_mic_verified) {
                return 0;
        }
        n = smb2_spnego_find_mech_list_mic(smb2, buf, len, &p);
        if (n <= 0) {
                return n;
        }
        mic.value = discard_const(p);
        mic.length = n;
        maj = gss_verify_mic(&min, auth_data->context, &msg, &mic, NULL);
        if (GSS_ERROR(maj)) {
                krb5_set_gss_error(smb2, "SPNEGO mechListMIC", maj, min);
                return -1;
        }
        auth_data->iakerb_mic_verified = 1;
        return 0;
}

int
krb5_session_request(struct smb2_context *smb2,
                     struct private_auth_data *auth_data,
                     unsigned char *buf, int len)
{
        uint32_t maj, min;
        gss_buffer_desc *input_token = NULL;
        gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
        unsigned char *reframed = NULL, *out_tok;
        size_t reframed_len, out_len;
        int initial;

        initial = (auth_data->context == GSS_C_NO_CONTEXT);
        free(auth_data->spnego_buf);
        auth_data->spnego_buf = NULL;
        auth_data->spnego_len = 0;

        /* The final SPNEGO reply only carries the acceptor's mechListMIC. */
        if (auth_data->iakerb_complete) {
                return iakerb_verify_acceptor_mic(smb2, auth_data, buf, len);
        }

        if (buf) {
                /* release the previous token */
                gss_release_buffer(&min, &auth_data->output_token);
                auth_data->output_token.length = 0;
                auth_data->output_token.value = NULL;

                token.value = buf;
                token.length = len;
                if (smb2->sec == SMB2_SEC_IAKERB) {
                        uint8_t *inner = NULL;
                        uint32_t mechs = 0;
                        int inner_len;

                        /* Server replies are SPNEGO negTokenResp. The
                         * mechanism only understands its own token. */
                        inner_len = smb2_spnego_unwrap_blob(smb2, buf, len, 0,
                                                            &inner, &mechs);
                        if (inner_len < 0) {
                                return -1;
                        }
                        token.value = inner;
                        token.length = inner_len;
                        reframed = iakerb_reframe(inner, inner_len,
                                                  smb2_krb5_oid, sizeof(smb2_krb5_oid),
                                                  smb2_iakerb_oid, sizeof(smb2_iakerb_oid),
                                                  0, &reframed_len);
                        if (reframed) {
                                token.value = reframed;
                                token.length = reframed_len;
                        }
                }
                input_token = &token;
        }

        /* TODO return -errno instead of just -1 */
        /* NOTE: this call is not async, a helper thread should be used if that
         * is an issue */
        auth_data->req_flags =    GSS_C_SEQUENCE_FLAG
                                | GSS_C_MUTUAL_FLAG
                                /* setting this flag gives a delegatable ticket
                                 * without server doing s4u2proxy */
                                /*| GSS_C_DELEG_FLAG */
                                | GSS_C_REPLAY_FLAG;

        maj = gss_init_sec_context(&min, auth_data->cred,
                                   &auth_data->context,
                                   auth_data->target_name,
                                   discard_const(auth_data->mech_type),
                                   auth_data->req_flags,
                                   GSS_C_INDEFINITE,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   input_token,
                                   NULL,
                                   &auth_data->output_token,
                                   NULL,
                                   NULL);
        free(reframed);

        /* GSS_C_MUTUAL_FLAG expects the acceptor to send a token so
         * a second call to gss_init_sec_context is required to complete the session.
         * A second call is required even if the first call returns GSS_S_COMPLETE
         */
        if (GSS_ERROR(maj)) {
                krb5_set_gss_error(smb2, "gss_init_sec_context", maj, min);
                return -1;
        }

        /*
         * The AP-REP completed the context and there is no mechanism token
         * left, but the acceptor still wants SPNEGO's mechListMIC: a MIC
         * over the DER mechTypes list we offered, which is IAKerb alone.
         */
        if (smb2->sec == SMB2_SEC_IAKERB && maj == GSS_S_COMPLETE &&
            auth_data->output_token.length == 0) {
                gss_buffer_desc msg = { sizeof(iakerb_mech_types), iakerb_mech_types };
                gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
                void *wrapped = NULL;
                int wlen;

                auth_data->iakerb_complete = 1;
                if (iakerb_verify_acceptor_mic(smb2, auth_data, buf, len) < 0) {
                        return -1;
                }
                maj = gss_get_mic(&min, auth_data->context, GSS_C_QOP_DEFAULT, &msg, &mic);
                if (GSS_ERROR(maj)) {
                        krb5_set_gss_error(smb2, "gss_get_mic", maj, min);
                        return -1;
                }
                wlen = smb2_spnego_wrap_mic_resp(smb2, mic.value, (int)mic.length, &wrapped);
                gss_release_buffer(&min, &mic);
                if (wlen <= 0 || wrapped == NULL) {
                        free(wrapped);
                        return -1;
                }
                auth_data->spnego_buf = wrapped;
                auth_data->spnego_len = wlen;
                return 0;
        }

        /* Windows Negotiate accepts IAKerb as a SPNEGO mech, not as a raw
         * GSS token. The optimistic mech list is IAKerb alone. */
        if (smb2->sec == SMB2_SEC_IAKERB &&
            auth_data->output_token.length > 0) {
                void *wrapped = NULL;
                int wlen;

                out_tok = auth_data->output_token.value;
                out_len = auth_data->output_token.length;
                reframed = iakerb_reframe(out_tok, out_len,
                                          smb2_iakerb_oid, sizeof(smb2_iakerb_oid),
                                          smb2_krb5_oid, sizeof(smb2_krb5_oid),
                                          1, &reframed_len);
                if (reframed) {
                        out_tok = reframed;
                        out_len = reframed_len;
                }
                if (initial) {
                        wlen = smb2_spnego_wrap_iakerb_init(smb2, out_tok, (int)out_len, &wrapped);
                } else {
                        wlen = smb2_spnego_wrap_iakerb_resp(smb2, out_tok, (int)out_len, &wrapped);
                }
                free(reframed);
                if (wlen <= 0 || wrapped == NULL) {
                        free(wrapped);
                        if (wlen <= 0) {
                                smb2_set_error(smb2, "Failed to wrap IAKerb "
                                               "token in SPNEGO");
                        }
                        return -1;
                }
                auth_data->spnego_buf = wrapped;
                auth_data->spnego_len = wlen;
        }

        return 0;
}

#if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H)
static OM_uint32
establish_contexts(struct smb2_context *smb2,
                      gss_OID imech,
                      gss_cred_id_t icred, gss_cred_id_t acred,
                      gss_name_t tname, OM_uint32 flags,
                      gss_ctx_id_t *ictx,
                      gss_ctx_id_t *actx,
                      gss_name_t *src_name,
                      gss_OID *amech,
                      gss_cred_id_t *deleg_cred)
{
        OM_uint32 minor, imaj, amaj;
        gss_buffer_desc itok, atok;

        *ictx = *actx = GSS_C_NO_CONTEXT;
        imaj = amaj = GSS_S_CONTINUE_NEEDED;
        itok.value = atok.value = NULL;
        itok.length = atok.length = 0;
        while (1) {
                (void)gss_release_buffer(&minor, &itok);
                imaj = gss_init_sec_context(&minor, icred, ictx, tname, imech, flags,
                        GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, &atok, NULL, &itok,
                                NULL, NULL);
                if (GSS_ERROR(imaj)) {
                        krb5_set_gss_error(smb2, "gss_init_sec_context (est)", imaj, minor);
                        break;
                }
                if (amaj == GSS_S_COMPLETE)
                        break;

                (void)gss_release_buffer(&minor, &atok);
                amaj = gss_accept_sec_context(&minor, actx, acred, &itok, GSS_C_NO_CHANNEL_BINDINGS,
                        src_name, amech, &atok, NULL, NULL,
                                deleg_cred);
                if (GSS_ERROR(amaj)) {
                        krb5_set_gss_error(smb2, "gss_accept_sec_context (est)", amaj, minor);
                        break;
                }
                (void)gss_release_buffer(&minor, &itok);
                if (imaj == GSS_S_COMPLETE)
                        break;
        }

        (void)gss_release_buffer(&minor, &itok);
        (void)gss_release_buffer(&minor, &atok);
        return imaj | amaj;
}

static OM_uint32
init_accept_sec_context(struct smb2_context *smb2,
                        gss_OID mech,
                        gss_cred_id_t claimant_cred_handle,
                        gss_cred_id_t verifier_cred_handle,
                        gss_cred_id_t *deleg_cred_handle)
{
        OM_uint32 major, minor, flags;
        gss_name_t source_name = GSS_C_NO_NAME, target_name = GSS_C_NO_NAME;
        gss_ctx_id_t initiator_context, acceptor_context;

        *deleg_cred_handle = GSS_C_NO_CREDENTIAL;

        major = gss_inquire_cred(&minor, verifier_cred_handle, &target_name, NULL,
                        NULL, NULL);
        if (GSS_ERROR(major)) {
                krb5_set_gss_error(smb2, "gss_inquire_cred (est)", major, minor);
        }

        flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
        establish_contexts(smb2, mech,
                        claimant_cred_handle, verifier_cred_handle,
                        target_name, flags,
                        &initiator_context,
                        &acceptor_context,
                        &source_name,
                        NULL,
                        deleg_cred_handle);

        (void)gss_release_name(&minor, &source_name);
        (void)gss_release_name(&minor, &target_name);
        (void)gss_delete_sec_context(&minor, &initiator_context, NULL);
        (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
        return major;
}
#endif

static OM_uint32
server_acquire_cred(struct smb2_server *server, struct smb2_context *smb2,
                    gss_name_t target_name, gss_OID_set mechs,
                    gss_cred_usage_t cred_usage, gss_cred_id_t *cred,
                    uint32_t *min)
{
#if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H)
        /*
         * server->auth_data is private_auth_data only when a keytab was
         * configured at server start (see krb5_init_server_credentials).
         */
        if (server->keytab_path[0] && server->auth_data &&
            ((struct private_auth_data *)server->auth_data)->keytab) {
                struct private_auth_data *server_auth_data;
                char keytab_path[256];
                char ccache_path[256];
                const char *cctype, *ccname;
                gss_key_value_element_desc kve[2];
                gss_key_value_set_desc kvd;
                int ret;

                server_auth_data = (struct private_auth_data *)server->auth_data;

                ret = krb5_kt_get_name(server_auth_data->krb5_cctx,
                               server_auth_data->keytab, keytab_path, sizeof(keytab_path));
                if (ret) {
                        smb2_set_error(smb2, "krb5_kt_get_name: %d", ret);
                        return GSS_S_FAILURE;
                }

                cctype = krb5_cc_get_type(server_auth_data->krb5_cctx, server_auth_data->krb5_Ccache);
                ccname = krb5_cc_get_name(server_auth_data->krb5_cctx, server_auth_data->krb5_Ccache);

                if (!cctype || !ccname) {
                        smb2_set_error(smb2, "Can't get ccache name");
                        return GSS_S_FAILURE;
                }

                snprintf(ccache_path, sizeof(ccache_path), "%s:%s", cctype, ccname);

                /* set the keytable and cache to what we used when server started */
                kve[0].key = "keytab";
                kve[0].value = keytab_path;

                kve[1].key = "ccache";
                kve[1].value = ccache_path;

                kvd.count = 2;
                kvd.elements = kve;

                return gss_acquire_cred_from(min,
                                        target_name,
                                        GSS_C_INDEFINITE,
                                        mechs,
                                        cred_usage,
                                        &kvd,
                                        cred,
                                        NULL, NULL);
        } else
#endif
        {
                return gss_acquire_cred(min,
                                       smb2->sec == SMB2_SEC_NTLMSSP ?
                                                GSS_C_NO_NAME : target_name,
                                       GSS_C_INDEFINITE,
                                       mechs,
                                       cred_usage,
                                       cred,
                                       NULL, NULL);
        }
}

struct private_auth_data *
krb5_init_server_client_cred(struct smb2_server *server, struct smb2_context *smb2, const char *password)
{
        struct private_auth_data *auth_data;
        char user_principal[1024];
        gss_buffer_desc name_buf;
        gss_cred_usage_t cred_usage;
        uint32_t maj, min;
        char *spos;
        gss_OID mech = GSS_C_NO_OID;

#if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H)
        if (smb2->sec != SMB2_SEC_KRB5) {
                mech = discard_const(gss_mech_krb5);
        } else {
                mech = GSS_C_NO_OID;
        }
#endif
        gss_OID_set mechs = GSS_C_NO_OID_SET;
        gss_OID_set_desc mechlist;

        if (mech != GSS_C_NO_OID) {
                mechlist.count = 1;
                mechlist.elements = mech;
                mechs = &mechlist;
        }

        auth_data = calloc(1, sizeof(struct private_auth_data));
        if (auth_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate private_auth_data");
                return NULL;
        }
        auth_data->context = GSS_C_NO_CONTEXT;
        auth_data->get_proxy_cred = server->proxy_authentication;

        /* strip any port off server host */
        strncpy(user_principal, server->hostname, sizeof(user_principal) - 1);
        user_principal[sizeof(user_principal) - 1] = '\0';
        spos = strchr(user_principal, ':');
        if (spos) {
                *spos = '\0';
        }
        /* form spn cifs/hostname, gss will append realm itself */
        if (asprintf(&auth_data->g_server, "cifs@%s", user_principal) < 0) {
                smb2_set_error(smb2, "Failed to allocate server string");
                return NULL;
        }
        name_buf.value = auth_data->g_server;
        name_buf.length = strlen(name_buf.value) + 1;

        maj = gss_import_name(&min, &name_buf,
                        GSS_C_NT_HOSTBASED_SERVICE, &auth_data->target_name);

        if (maj != GSS_S_COMPLETE) {
                krb5_set_gss_error(smb2, "gss_import_name", maj, min);
                return NULL;
        }

        if (auth_data->get_proxy_cred) {
                /* do constrained delegation */
                cred_usage = GSS_C_BOTH;
        } else {
                cred_usage = GSS_C_ACCEPT;
        }
        maj = server_acquire_cred(server, smb2, auth_data->target_name, mechs,
                                  cred_usage, &auth_data->cred, &min);
        if (GSS_ERROR(maj)) {
                krb5_set_gss_error(smb2, "gss_acquire_cred (server)", maj, min);
                return NULL;
        }

#if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H)
        mechlist.count = 1;
        mechlist.elements = &smb2_mech_iakerb;
        maj = server_acquire_cred(server, smb2, auth_data->target_name, &mechlist,
                                  GSS_C_ACCEPT, &auth_data->iakerb_cred, &min);
        if (GSS_ERROR(maj)) {
                auth_data->iakerb_cred = GSS_C_NO_CREDENTIAL;
        }
#endif

        return auth_data;
}

#if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H)
#define SPNEGO_ACCEPT_COMPLETED  0
#define SPNEGO_ACCEPT_INCOMPLETE 1

static int
iakerb_server_wrap(struct smb2_context *smb2, struct private_auth_data *auth_data,
                   int neg_state, int first,
                   const gss_buffer_desc *mic)
{
        void *wrapped = NULL;
        int wlen;

        wlen = smb2_spnego_wrap_acceptor_resp(smb2, neg_state, first,
                                              auth_data->output_token.value,
                                              (int)auth_data->output_token.length,
                                              mic ? mic->value : NULL,
                                              mic ? (int)mic->length : 0,
                                              &wrapped);
        if (wlen <= 0 || wrapped == NULL) {
                free(wrapped);
                return -1;
        }
        auth_data->spnego_buf = wrapped;
        auth_data->spnego_len = wlen;
        return 0;
}

static int
iakerb_server_verify_mic(struct smb2_context *smb2, struct private_auth_data *auth_data,
                         const uint8_t *client_mic, int mic_len)
{
        gss_buffer_desc msg = { auth_data->mech_types_len, auth_data->mech_types };
        gss_buffer_desc mic = { mic_len, discard_const(client_mic) };
        uint32_t maj, min;

        maj = gss_verify_mic(&min, auth_data->context, &msg, &mic, NULL);
        if (GSS_ERROR(maj)) {
                krb5_set_gss_error(smb2, "SPNEGO mechListMIC", maj, min);
                return -1;
        }
        auth_data->iakerb_mic_verified = 1;
        return 0;
}

/*
 * The context is established and output_token holds the AP-REP. Windows
 * sends it with its mechListMIC and accept-incomplete, and waits for the
 * initiator's MIC in one more leg, unless that MIC came with the AP-REQ.
 */
static int
iakerb_server_finish(struct smb2_context *smb2, struct private_auth_data *auth_data,
                     const uint8_t *client_mic, int mic_len,
                     int *more_processing_needed)
{
        gss_buffer_desc msg = { auth_data->mech_types_len, auth_data->mech_types };
        gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
        uint32_t maj, min;
        int ret;

        if (mic_len > 0 &&
            iakerb_server_verify_mic(smb2, auth_data, client_mic, mic_len) < 0) {
                return -1;
        }
        maj = gss_get_mic(&min, auth_data->context, GSS_C_QOP_DEFAULT, &msg, &mic);
        if (GSS_ERROR(maj)) {
                krb5_set_gss_error(smb2, "gss_get_mic", maj, min);
                return -1;
        }
        ret = iakerb_server_wrap(smb2, auth_data,
                                 auth_data->iakerb_mic_verified ?
                                 SPNEGO_ACCEPT_COMPLETED : SPNEGO_ACCEPT_INCOMPLETE,
                                 0, &mic);
        gss_release_buffer(&min, &mic);
        if (ret < 0) {
                return -1;
        }
        if (!auth_data->iakerb_mic_verified) {
                auth_data->iakerb_complete = 1;
                *more_processing_needed = 1;
        }
        return 0;
}
#endif

int
krb5_session_reply(struct smb2_context *smb2,
                     struct private_auth_data *auth_data,
                     unsigned char *buf, int len,
                     int *more_processing_needed)
{
        uint32_t maj, min;
        gss_buffer_desc *input_token = NULL;
        gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
        gss_cred_id_t ret_delegated_cred_handle;

        OM_uint32 ret_timefor;
        OM_uint32 ret_flags = 0;
        gss_cred_id_t acceptor_cred = auth_data->cred;
        const uint8_t *client_mic = NULL;
        int mic_len = 0;
        int iakerb_first = 0;

        *more_processing_needed = 0;

        if (auth_data->output_token.value) {
                gss_release_buffer(&min, &auth_data->output_token);
                auth_data->output_token.length = 0;
                auth_data->output_token.value = NULL;
        }
        free(auth_data->spnego_buf);
        auth_data->spnego_buf = NULL;
        auth_data->spnego_len = 0;

        /* accept client context
        */
        token.value = buf;
        token.length = len;
        input_token = &token;

#if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H)
        if (auth_data->iakerb_server) {
                uint8_t *tok = NULL;
                uint32_t neg_state = 0;
                int n;

                if (auth_data->iakerb_complete) {
                        mic_len = smb2_spnego_find_mech_list_mic(smb2, buf, len, &client_mic);
                        if (mic_len <= 0) {
                                if (mic_len == 0) {
                                        smb2_set_error(smb2, "IAKerb: no mechListMIC "
                                                       "from the client");
                                }
                                return -1;
                        }
                        if (iakerb_server_verify_mic(smb2, auth_data, client_mic, mic_len) < 0) {
                                return -1;
                        }
                        return iakerb_server_wrap(smb2, auth_data,
                                                  SPNEGO_ACCEPT_COMPLETED, 0, NULL);
                }
                n = smb2_spnego_unwrap_targ(smb2, buf, len, &tok, &neg_state);
                if (n <= 0) {
                        if (n == 0) {
                                smb2_set_error(smb2, "IAKerb: no mechanism token");
                        }
                        return -1;
                }
                mic_len = smb2_spnego_find_mech_list_mic(smb2, buf, len, &client_mic);
                if (mic_len < 0) {
                        return -1;
                }
                token.value = tok;
                token.length = n;
                acceptor_cred = auth_data->iakerb_cred;
        } else if (auth_data->context == GSS_C_NO_CONTEXT &&
                   auth_data->iakerb_cred != GSS_C_NO_CREDENTIAL) {
                /* MIT's SPNEGO never negotiates IAKerb, as it is not a
                 * default mech, so do SPNEGO here when it is preferred. */
                const uint8_t *types = NULL, *tok = NULL;
                int types_len = 0, n;

                n = smb2_spnego_unwrap_iakerb_init(smb2, buf, len,
                                                   &types, &types_len, &tok);
                if (n > 0) {
                        auth_data->mech_types = malloc(types_len);
                        if (auth_data->mech_types == NULL) {
                                smb2_set_error(smb2, "Failed to allocate mechTypes");
                                return -1;
                        }
                        memcpy(auth_data->mech_types, types, types_len);
                        auth_data->mech_types_len = types_len;
                        auth_data->iakerb_server = 1;
                        iakerb_first = 1;
                        token.value = discard_const(tok);
                        token.length = n;
                        acceptor_cred = auth_data->iakerb_cred;
                }
        }
#endif

        maj = gss_accept_sec_context(&min,
                                   &auth_data->context,
                                   acceptor_cred,
                                   input_token,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &auth_data->user_name,
                                   NULL,
                                   &auth_data->output_token,
                                   &ret_flags,
                                   &ret_timefor,
                                   &ret_delegated_cred_handle);

        if (maj & GSS_S_CONTINUE_NEEDED) {
                *more_processing_needed = 1;
#if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H)
                if (auth_data->iakerb_server) {
                        return iakerb_server_wrap(smb2, auth_data,
                                                  SPNEGO_ACCEPT_INCOMPLETE,
                                                  iakerb_first, NULL);
                }
#endif
                return 0;
        }

        if (GSS_ERROR(maj)) {
                krb5_set_gss_error(smb2, "gss_accept_sec_context", maj, min);
                return -1;
        }

        /* client name is in user@domain format, so set that into our context
        */
        maj = gss_display_name(&min, auth_data->user_name, &token, NULL);
        if (GSS_ERROR(maj)) {
                krb5_set_gss_error(smb2, "gss_display_name", maj, min);
                return -1;
        }

#if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H)
        free(smb2->local_user);
        smb2->local_user = NULL;
        {
                gss_buffer_desc lname = GSS_C_EMPTY_BUFFER;
                OM_uint32 lmin;

                if (gss_localname(&lmin, auth_data->user_name, GSS_C_NO_OID,
                                  &lname) == GSS_S_COMPLETE) {
                        smb2->local_user = strndup(lname.value, lname.length);
                        gss_release_buffer(&lmin, &lname);
                }
        }
#endif

        if (token.length && (char*)token.value) {
                char *user;
                char *dpos;
                int namelen = token.length;;

                user = malloc(namelen + 1);
                if (!user) {
                        smb2_set_error(smb2, "can not alloc name buffer");
                        return -1;
                }
                memcpy(user, (char*)token.value, namelen);
                user[namelen] = 0;

                dpos = strchr(user, '@');
                if (dpos) {
                        *dpos++ = '\0';
                }

                smb2_set_user(smb2, user);
                smb2_set_domain(smb2, dpos ? dpos : "");

                gss_release_buffer(&min, &token);

                /* strip domain off user for s4u2 */
                token.value = user;
                token.length = strlen(user);

                gss_release_name(&min, &auth_data->user_name);
                maj = gss_import_name(&min, &token, GSS_C_NT_USER_NAME, &auth_data->user_name);
                if (GSS_ERROR(maj)) {
                        krb5_set_gss_error(smb2, "gss_import_name", maj, min);
                        return -1;
                }

                free(user);
        }

        if (auth_data->get_proxy_cred && (!(ret_flags & GSS_C_DELEG_FLAG) ||
                        (ret_delegated_cred_handle == GSS_C_NO_CREDENTIAL))) {
                /* did not got a proxy credential when accepting the
                 * the client context, so attempt an s4u2self
                 * with user-name to get one
                 */
#if defined(__APPLE__) && defined(HAVE_GSS_GSS_H)
                smb2_set_error(smb2, "Apple has no way to proxy credentials");
                return -1;
#else
                gss_cred_id_t user_cred_handle = GSS_C_NO_CREDENTIAL;
                gss_OID mech;
                OM_uint32 xmin;

                gss_OID_set mechs = GSS_C_NO_OID_SET;
                gss_OID_set_desc mechlist;

                mech = auth_data->use_spnego ?
                       discard_const(&gss_mech_spnego) : discard_const(gss_mech_krb5);

                if (mech != GSS_C_NO_OID) {
                        mechlist.count = 1;
                        mechlist.elements = discard_const(mech);
                        mechs = &mechlist;
                }
                maj = gss_acquire_cred_impersonate_name(&min,
                                auth_data->cred,
                                auth_data->user_name,
                                GSS_C_INDEFINITE,
                                mechs,
                                GSS_C_INITIATE,
                                &user_cred_handle,
                                NULL,
                                NULL);

                if (maj != GSS_S_COMPLETE) {
                        krb5_set_gss_error(smb2, "gss_acquire_cred_impersonate_name", maj, min);
                        return -1;
                }
                maj = init_accept_sec_context(smb2, mech,
                                user_cred_handle, auth_data->cred,
                                &ret_delegated_cred_handle);

                (void)gss_release_cred(&xmin, &user_cred_handle);

                if (maj != GSS_S_COMPLETE) {
                        krb5_set_gss_error(smb2, "init_accept_sec_context (impersonate)", maj, min);
                        return -1;
                }
#endif
        }
        /* if the client credential is delegatable and the client is pass-through
         * save the client's cred for use in a proxy client
         */
        if ((ret_flags & GSS_C_DELEG_FLAG) && (ret_delegated_cred_handle)) {
                if (smb2->passthrough) {
                        smb2->cred_handle = ret_delegated_cred_handle;
                } else {
                        smb2->cred_handle = NULL;
                        maj = gss_release_cred(&min, &ret_delegated_cred_handle);
                }
        }
#if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H)
        if (auth_data->iakerb_server) {
                return iakerb_server_finish(smb2, auth_data, client_mic, mic_len,
                                            more_processing_needed);
        }
#endif
        return 0;
}


int
krb5_renew_server_credentials(struct smb2_server *server)
{
        struct private_auth_data *auth_data;
        int ret;

        /*
         * server->auth_data is only a private_auth_data when we initialized
         * Kerberos with a keytab. Otherwise it may be NULL or (historically)
         * some other app pointer — never dereference keytab without a keytab
         * path set by the server.
         */
        if (server == NULL || server->keytab_path[0] == '\0') {
                return 0;
        }
        auth_data = server->auth_data;
        if (!auth_data || !auth_data->keytab || !auth_data->krb5_cctx ||
            !auth_data->principal || !auth_data->krb5_Ccache) {
                return 0;
        }

        do { /* try */
                /* this is the equivalent of "kinit -kt keytab_path -c ccache_path principal"
                */
                ret = krb5_get_init_creds_keytab(auth_data->krb5_cctx, &auth_data->server_cred,
                                auth_data->principal, auth_data->keytab, 0, NULL, NULL);
                if (ret) {
                        snprintf(server->error, sizeof(server->error), "Can't init creds with keytab: %d", ret);
                        break;
                }
                ret = krb5_cc_store_cred(auth_data->krb5_cctx, auth_data->krb5_Ccache, &auth_data->server_cred);
                if (ret) {
                        snprintf(server->error, sizeof(server->error), "Can't store creds: %d", ret);
                        break;
                }
        }
        while (0); /* catch */

        return ret;
}

int
krb5_init_server_credentials(struct smb2_server *server, const char *keytab_path)
{
        struct private_auth_data *auth_data;
        gss_buffer_desc name;
        char hostname[128];
        char principal_name[256];
        char *spos;
        OM_uint32 maj, min;
        int ret = -1;

        server->error[0] = '\0';

        /* without a key table path, there is no need for this as the default one will
         * be used in gss_acquire_cred and the initial creds will have to be done via kinit
         */
        if (!server || !keytab_path || !keytab_path[0]) {
                return 0;
        }

        do { // try
                auth_data = calloc(1, sizeof(struct private_auth_data));
                if (auth_data == NULL) {
                        snprintf(server->error, sizeof(server->error), "Can't alloc auth_data");
                        break;
                }

                /* strip any port off server host */
                strncpy(hostname, server->hostname, sizeof(hostname) - 1);
                hostname[sizeof(hostname) - 1] = '\0';
                spos = strchr(hostname, ':');
                if (spos) {
                        *spos = '\0';
                }

                snprintf(principal_name, sizeof(principal_name), "cifs/%s", hostname);

                /* form spn cifs/hostname.domain */
                if (asprintf(&auth_data->g_server, "cifs@%s", hostname) < 0) {
                        snprintf(server->error, sizeof(server->error),
                                       "Failed to allocate server string");
                        ret = -1;
                        break;
                }

                name.value = auth_data->g_server;
                name.length = strlen(auth_data->g_server);

                maj = gss_import_name(&min, &name, GSS_C_NT_HOSTBASED_SERVICE,
                                      &auth_data->target_name);

                if (maj != GSS_S_COMPLETE) {
                        snprintf(server->error, sizeof(server->error),
                                        "gss_import_name %u %u", maj, min);
                        ret = -1;
                        break;
                }

                ret = krb5_init_context(&auth_data->krb5_cctx);
                if (ret) {
                        snprintf(server->error, sizeof(server->error),
                                        "Can't init krb5 context: %d", ret);
                        break;
                }

                ret = krb5_parse_name(auth_data->krb5_cctx, principal_name, &auth_data->principal);
                if (ret) {
                        snprintf(server->error, sizeof(server->error),
                                        "Can't parse principal name: %d", ret);
                        break;
                }

                ret = krb5_kt_resolve(auth_data->krb5_cctx, keytab_path, &auth_data->keytab);
                if (ret) {
                        snprintf(server->error, sizeof(server->error),
                                        "Can't resolve krb5 key table: %d", ret);
                        break;
                }

                if (1) {
                        const char *cname;

                        /* use a private memory cache for server credentials instead of default, so a client
                         * can kinit on the same machine and not mess up our creds */

                        ret = krb5_cc_new_unique(auth_data->krb5_cctx, "MEMORY", NULL, &auth_data->krb5_Ccache);
                        if (ret != 0) {
                                snprintf(server->error, sizeof(server->error),
                                                "Failed to create krb5 credentials cache");
                                break;
                        }

                        ret = krb5_cc_initialize(auth_data->krb5_cctx, auth_data->krb5_Ccache, auth_data->principal);
                        if (ret != 0) {
                                snprintf(server->error, sizeof(server->error),
                                                "Failed to initialze krb5 credentials cache");
                                break;
                        }

                        cname = krb5_cc_get_name(auth_data->krb5_cctx, auth_data->krb5_Ccache);
                        if (cname == NULL) {
                                snprintf(server->error, sizeof(server->error),
                                               "Failed to retrieve the credentials cache name");
                                break;
                        }

                        maj = gss_krb5_ccache_name(&min, cname, NULL);
                        if (maj != GSS_S_COMPLETE) {
                                snprintf(server->error, sizeof(server->error),
                                               "gss_krb5_ccache_name %u %u", maj, min);
                                ret = -1;
                                break;
                        }
                } else {
                        /* use default cache */
                        ret = krb5_cc_default(auth_data->krb5_cctx, &auth_data->krb5_Ccache);
                        if (ret) {
                                snprintf(server->error, sizeof(server->error),
                                               "Can't get default ccache: %d", ret);
                                break;
                        }
                }

                ret = krb5_cc_initialize(auth_data->krb5_cctx, auth_data->krb5_Ccache, auth_data->principal);
                if (ret != 0) {
                        snprintf(server->error, sizeof(server->error),
                                       "Failed to initialze krb5 credentials cache: %d", ret);
                        break;
                }

                server->auth_data = auth_data;
        }
        while (0); /* catch */

        if (ret) {
                if (auth_data) {
                        krb5_free_auth_data(auth_data);
                }
                server->auth_data = NULL;
        } else {
                server->auth_data = auth_data;
        }
        return ret;
}


void
krb5_free_server_credentials(struct smb2_server *server)
{
        /*
         * Only free when we installed private_auth_data for a keytab.
         * Without a keytab path, auth_data must not be treated as Kerberos
         * state (application code may leave it NULL or use other meaning).
         */
        if (server == NULL || server->keytab_path[0] == '\0' ||
            server->auth_data == NULL) {
                return;
        }
        krb5_free_auth_data(server->auth_data);
        server->auth_data = NULL;
}

int
krb5_get_output_token_length(struct private_auth_data *auth_data)
{
        if (auth_data->spnego_buf) {
                return auth_data->spnego_len;
        }
        return auth_data->output_token.length;
}

unsigned char *
krb5_get_output_token_buffer(struct private_auth_data *auth_data)
{
        if (auth_data->spnego_buf) {
                return auth_data->spnego_buf;
        }
        return auth_data->output_token.value;
}

int
krb5_can_do_ntlmssp(void)
{
#if !defined(__APPLE__) || !defined(HAVE_GSS_GSS_H)
        gss_OID_set mech_attrs;
        gss_OID_set known_mech_attrs;
        uint32_t maj, min;

        gss_OID mech = discard_const(&spnego_mech_ntlmssp);

        /* if we can acquire an initiator context with an ntlmssp mechanism
         * it means krb5 has the ntlmssp plugin installed and we can use
         * krb5 for all authentication purposes
         */
        maj = gss_inquire_attrs_for_mech(&min,
                               mech,
                               &mech_attrs,
                               &known_mech_attrs);

        if (GSS_ERROR(maj)) {
                krb5_set_gss_error(NULL, "gss_inquire_attrs_for_mech (ntlmssp cap check)", maj, min);
                return 0;
        }

        gss_release_oid_set(&min, &mech_attrs);
        gss_release_oid_set(&min, &known_mech_attrs);
        return 1;
#else
        return 0;
#endif
}

#endif /* HAVE_LIBKRB5 */
