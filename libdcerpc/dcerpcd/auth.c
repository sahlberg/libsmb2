/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Authentication for dcerpcd: guest, NTLMSSP (passwd file), and optional
 * Kerberos via GSSAPI (libsmb2 SPNEGO). Kerberos can be turned off with
 * "krb5: 0" in the CONFIG YAML (/etc/dcerpcd/config).
 *
 * Loads a YAML passwd file for NTLMSSP. Real users must also exist in the
 * local account database (getpwnam). Tracks per-connection auth state.
 *
 */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <errno.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "smb2.h"
#include "libsmb2.h"

#include "dcerpcd.h"

#ifndef _U_
#define _U_ __attribute__((unused))
#endif

/* Monotonic session id assigned at client connect; wrap is ignored. */
static uint32_t next_session_id = 1;

static void
conn_free(struct dcerpcd_conn *conn)
{
        if (conn == NULL) {
                return;
        }
        dcerpcd_pipe_conn_cleanup(conn);
        free(conn->username);
        free(conn->pending_username);
        free(conn);
}

int
dcerpcd_auth_init(const char *passwd_path)
{
        if (passwd_path == NULL) {
                return -1;
        }
        return dcerpcd_passwd_load(passwd_path);
}

void
dcerpcd_auth_shutdown(void)
{
        dcerpcd_passwd_free();
}

void *
dcerpcd_auth_passwd_db(void)
{
        return (void *)dcerpcd_passwd_get();
}

struct dcerpcd_conn *
dcerpcd_auth_conn(struct smb2_context *smb2)
{
        return (struct dcerpcd_conn *)smb2_get_opaque(smb2);
}

int
dcerpcd_conn_is_root(const struct dcerpcd_conn *conn)
{
        /*
         * Must be a real NTLMSSP user session (not guest) whose local
         * account uid is 0. Guest/anonymous never count as root.
         */
        return conn != NULL &&
               conn->auth_kind == DCERPCD_AUTH_USER &&
               conn->uid == 0;
}

void
dcerpcd_auth_setup_client(struct smb2_context *smb2)
{
        struct dcerpcd_conn *conn;

        conn = calloc(1, sizeof(*conn));
        if (conn == NULL) {
                fprintf(stderr, "auth: out of memory for connection state\n");
                smb2_close_context(smb2);
                return;
        }
        conn->session_id = next_session_id++;
        conn->auth_kind = DCERPCD_AUTH_NONE;
        conn->uid = (uid_t)-1;
        conn->pending_kind = DCERPCD_AUTH_NONE;
        conn->pending_uid = (uid_t)-1;
        conn->pipes = NULL;
        smb2_set_opaque(smb2, conn);

        /*
         * SPNEGO mechs: NTLMSSP always. Kerberos when config allows it
         * (SMB2_SEC_UNDEFINED ⇒ both mechs in negotiate). "krb5: 0"
         * forces NTLMSSP-only so clients never attempt GSSAPI.
         */
        if (dcerpcd_config_get()->krb5) {
                smb2_set_authentication(smb2, SMB2_SEC_UNDEFINED);
        } else {
                smb2_set_authentication(smb2, SMB2_SEC_NTLMSSP);
        }
        /*
         * Server-side IOCTL replies (FSCTL_PIPE_TRANSCEIVE) carry opaque
         * DCERPC PDUs; passthrough copies the output buffer as-is.
         */
        smb2_set_passthrough(smb2, 1);
}

int
dcerpcd_auth_destruction(struct smb2_server *srvr _U_,
                         struct smb2_context *smb2)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);

        if (conn) {
                printf("connection closed: session=%u user=%s auth=%s\n",
                       conn->session_id,
                       conn->username ? conn->username : "(none)",
                       conn->auth_kind == DCERPCD_AUTH_USER ? "user" :
                       conn->auth_kind == DCERPCD_AUTH_GUEST ? "guest" : "none");
                conn_free(conn);
                smb2_set_opaque(smb2, NULL);
        }
        return 0;
}

/*
 * Called by the NTLMSSP server path before verifying the client's response.
 * Install the cleartext password for the claimed user, or allow guest.
 * Real users must exist both in our passwd file and as a local account.
 * The claimed identity stays pending until the proof is verified and
 * dcerpcd_auth_session_established() is called.
 */
int
dcerpcd_auth_authorize_user(struct smb2_server *srvr _U_,
                            struct smb2_context *smb2,
                            const char *user,
                            const char *domain,
                            const char *workstation)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        const dcerpcd_user *ent;
        struct passwd *pw;

        if (conn == NULL) {
                fprintf(stderr, "authorize: missing connection state\n");
                return -1;
        }

        /* Guest / anonymous */
        if (user == NULL || user[0] == '\0' || strcasecmp(user, "guest") == 0) {
                free(conn->pending_username);
                conn->pending_username = strdup("guest");
                conn->pending_kind = DCERPCD_AUTH_GUEST;
                conn->pending_uid = (uid_t)-1;
                smb2_set_user(smb2, "guest");
                /* No password: allow_anonymous handles NTLMSSP guest. */
                smb2_set_password(smb2, NULL);
                printf("authorize: session=%u guest from %s\\%s\n",
                       conn->session_id,
                       domain ? domain : "",
                       workstation ? workstation : "");
                return 0;
        }

        ent = dcerpcd_passwd_find(dcerpcd_passwd_get(), user);
        if (ent == NULL) {
                fprintf(stderr,
                        "authorize: session=%u unknown user \"%s\" "
                        "(not in passwd file)\n",
                        conn->session_id, user);
                return -1;
        }

        pw = getpwnam(ent->user);
        if (pw == NULL) {
                fprintf(stderr,
                        "authorize: session=%u user \"%s\" is in passwd file "
                        "but not a local account\n",
                        conn->session_id, ent->user);
                return -1;
        }

        free(conn->pending_username);
        conn->pending_username = strdup(ent->user);
        if (conn->pending_username == NULL) {
                return -1;
        }
        conn->pending_kind = DCERPCD_AUTH_USER;
        conn->pending_uid = pw->pw_uid;

        smb2_set_user(smb2, ent->user);
        smb2_set_password(smb2, ent->password);

        printf("authorize: session=%u user=%s uid=%u from %s\\%s\n",
               conn->session_id, ent->user, (unsigned)pw->pw_uid,
               domain ? domain : "",
               workstation ? workstation : "");
        return 0;
}

int
dcerpcd_auth_session_established(struct smb2_server *srvr _U_,
                                 struct smb2_context *smb2)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        const char *user;

        if (conn == NULL) {
                return -1;
        }

        /* The NTLMSSP proof checked out: the pending identity is ours */
        if (conn->pending_kind != DCERPCD_AUTH_NONE) {
                free(conn->username);
                conn->username = conn->pending_username;
                conn->pending_username = NULL;
                conn->auth_kind = conn->pending_kind;
                conn->uid = conn->pending_uid;
                conn->pending_kind = DCERPCD_AUTH_NONE;
                conn->pending_uid = (uid_t)-1;
        }

        /*
         * NTLMSSP sets auth_kind through authorize_user() above.
         * Kerberos/GSSAPI never calls that path; libsmb2 sets smb2
         * user/domain from the ticket principal (user@REALM → user +
         * domain). Map that to a local uid.
         */
        if (conn->auth_kind != DCERPCD_AUTH_USER) {
                user = smb2_get_user(smb2);
                if (user != NULL && user[0] != '\0' &&
                    strcasecmp(user, "guest") != 0) {
                        struct passwd *pw = getpwnam(user);

                        if (pw == NULL) {
                                fprintf(stderr,
                                        "session: session=%u Kerberos user "
                                        "\"%s\" has no local account\n",
                                        conn->session_id, user);
                                return -1;
                        }
                        free(conn->username);
                        conn->username = strdup(user);
                        if (conn->username == NULL) {
                                return -1;
                        }
                        conn->auth_kind = DCERPCD_AUTH_USER;
                        conn->uid = pw->pw_uid;
                        printf("session established: session=%u user=%s "
                               "uid=%u dialect=0x%04x (kerberos)\n",
                               conn->session_id, conn->username,
                               (unsigned)conn->uid,
                               smb2_get_dialect(smb2));
                        return 0;
                }
        }

        if (conn->auth_kind == DCERPCD_AUTH_USER) {
                printf("session established: session=%u user=%s uid=%u "
                       "dialect=0x%04x (ntlmssp)\n",
                       conn->session_id,
                       conn->username ? conn->username : "?",
                       (unsigned)conn->uid,
                       smb2_get_dialect(smb2));
        } else {
                printf("session established: session=%u user=guest "
                       "dialect=0x%04x (guest)\n",
                       conn->session_id,
                       smb2_get_dialect(smb2));
                conn->auth_kind = DCERPCD_AUTH_GUEST;
                if (conn->username == NULL) {
                        conn->username = strdup("guest");
                }
        }
        return 0;
}
