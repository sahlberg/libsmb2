/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Minimal SMB2 server that exports only the IPC$ share.
 * Supports guest/anonymous, NTLMSSP (YAML passwd file), and optional
 * Kerberos via GSSAPI. Config: /etc/dcerpcd/config (see config.c);
 * set "krb5: 0" in the CONFIG YAML to advertise NTLMSSP only.
 * Authenticated users must exist in the local account database (getpwnam).
 * Endpoint mapper: in-memory registry of ncacn_np endpoints (epm.c).
 * External services: Unix domain socket (default
 * /var/run/dcerpcd/dcerpcd.sock) for worker registration (external.c).
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
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

#include "dcerpcd.h"

#define DEFAULT_PASSWD_PATH "/etc/dcerpcd/passwd"
#define DEFAULT_CONFIG_PATH "/etc/dcerpcd/config"

/* Common maximal access mask for IPC$ pipe shares. */
#define IPC_MAXIMAL_ACCESS 0x001f00a9

static int
path_is_ipc(const uint16_t *path, uint16_t path_length)
{
        char *utf8;
        const char *p;
        size_t nchars;
        int is_ipc = 0;

        if (path == NULL || path_length < 8) {
                return 0;
        }

        nchars = path_length / 2;
        utf8 = (char *)smb2_utf16_to_utf8(path, nchars);
        if (utf8 == NULL) {
                return 0;
        }

        /*
         * Tree-connect path is typically \\server\IPC$ (or //server/IPC$).
         * Accept any path whose final component is IPC$ (case-insensitive).
         */
        p = strrchr(utf8, '\\');
        if (p == NULL) {
                p = strrchr(utf8, '/');
        }
        if (p != NULL) {
                p++;
        } else {
                p = utf8;
        }

        is_ipc = (strcasecmp(p, "IPC$") == 0);
        free(utf8);
        return is_ipc;
}

static int
logoff_cmd(struct smb2_server *srvr _U_, struct smb2_context *smb2)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);

        printf("session logoff: session=%u user=%s\n",
               conn ? conn->session_id : 0,
               conn && conn->username ? conn->username : "?");
        return 0;
}

static int
tree_connect_cmd(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                 struct smb2_tree_connect_request *req,
                 struct smb2_tree_connect_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);

        if (!path_is_ipc(req->path, req->path_length)) {
                fprintf(stderr,
                        "tree connect rejected: session=%u only IPC$ is exported\n",
                        conn ? conn->session_id : 0);
                return -1;
        }

        rep->share_type = SMB2_SHARE_TYPE_PIPE;
        rep->share_flags = 0;
        rep->capabilities = 0;
        rep->maximal_access = IPC_MAXIMAL_ACCESS;

        printf("tree connect: session=%u IPC$ user=%s auth=%s\n",
               conn ? conn->session_id : 0,
               conn && conn->username ? conn->username : "?",
               conn && conn->auth_kind == DCERPCD_AUTH_USER ? "user" : "guest");
        return 0;
}

static int
tree_disconnect_cmd(struct smb2_server *srvr _U_,
                    struct smb2_context *smb2,
                    const uint32_t tree_id)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);

        printf("tree disconnect: session=%u tree_id=0x%08x\n",
               conn ? conn->session_id : 0, tree_id);
        return 0;
}

static int
echo_cmd(struct smb2_server *srvr _U_, struct smb2_context *smb2 _U_)
{
        return 0;
}

static struct smb2_server_request_handlers handlers = {
        .destruction_event = dcerpcd_auth_destruction,
        .authorize_user = dcerpcd_auth_authorize_user,
        .session_established = dcerpcd_auth_session_established,
        .logoff_cmd = logoff_cmd,
        .tree_connect_cmd = tree_connect_cmd,
        .tree_disconnect_cmd = tree_disconnect_cmd,
        .create_cmd = dcerpcd_pipe_create,
        .close_cmd = dcerpcd_pipe_close,
        .flush_cmd = NULL,
        .read_cmd = dcerpcd_pipe_read,
        .write_cmd = dcerpcd_pipe_write,
        .oplock_break_cmd = NULL,
        .lease_break_cmd = NULL,
        .lock_cmd = NULL,
        .ioctl_cmd = dcerpcd_pipe_ioctl,
        .cancel_cmd = NULL,
        .echo_cmd = echo_cmd,
        .query_directory_cmd = NULL,
        .change_notify_cmd = NULL,
        .query_info_cmd = NULL,
        .set_info_cmd = NULL,
};

static struct smb2_server server;

static void
on_smb2_error(struct smb2_context *smb2, const char *error_string)
{
        if (error_string) {
                fprintf(stderr, "smb2 %p: %s\n", (void *)smb2, error_string);
        }
}

static void
on_new_client(struct smb2_context *smb2, void *cb_data)
{
        struct dcerpcd_conn *conn;

        (void)cb_data;

        smb2_set_version(smb2, SMB2_VERSION_ANY);
        dcerpcd_auth_setup_client(smb2);
        conn = dcerpcd_auth_conn(smb2);
        printf("new connection: session=%u %p\n",
               conn ? conn->session_id : 0, (void *)smb2);
        smb2_register_error_callback(smb2, on_smb2_error);
}

static void
usage(const char *prog)
{
        fprintf(stderr,
                "Usage: %s [-c config] [-f passwd-file] [-s svc-socket] [port]\n"
                "\n"
                "Minimal SMB2 server exporting only IPC$.\n"
                "  - guest / anonymous access (allow_anonymous)\n"
                "  - NTLMSSP users from a YAML passwd file (default: %s)\n"
                "  - Kerberos/GSSAPI when enabled in config (default: %s)\n"
                "      set \"krb5: 0\" in CONFIG YAML to turn Kerberos off\n"
                "  - external service control socket (default: %s)\n"
                "Default port is %d (requires root or CAP_NET_BIND_SERVICE).\n",
                prog, DEFAULT_PASSWD_PATH, DEFAULT_CONFIG_PATH,
                DCERPCD_DEFAULT_SVC_SOCK, DEFAULT_PORT);
        exit(1);
}

int
main(int argc, char *argv[])
{
        int err;
        int i;
        const char *passwd_path = DEFAULT_PASSWD_PATH;
        const char *config_path = DEFAULT_CONFIG_PATH;
        const char *svc_sock = DCERPCD_DEFAULT_SVC_SOCK;
        const dcerpcd_config *cfg;

        for (i = 1; i < argc; i++) {
                if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
                        usage(argv[0]);
                }
                if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) {
                        if (i + 1 >= argc) {
                                usage(argv[0]);
                        }
                        config_path = argv[++i];
                        continue;
                }
                if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--passwd")) {
                        if (i + 1 >= argc) {
                                usage(argv[0]);
                        }
                        passwd_path = argv[++i];
                        continue;
                }
                if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--svc-socket")) {
                        if (i + 1 >= argc) {
                                usage(argv[0]);
                        }
                        svc_sock = argv[++i];
                        continue;
                }
                if (argv[i][0] == '-') {
                        usage(argv[0]);
                }
        }

        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);

        /*
         * Network servers must ignore SIGPIPE: a client that closes while we
         * still have outbound data would otherwise kill the whole process
         * (exit 141) instead of surfacing EPIPE on write.
         */
        signal(SIGPIPE, SIG_IGN);

        if (dcerpcd_config_load(config_path) != 0) {
                fprintf(stderr, "dcerpcd: failed to load config \"%s\"\n",
                        config_path);
                return 1;
        }
        cfg = dcerpcd_config_get();

        if (dcerpcd_auth_init(passwd_path) != 0) {
                fprintf(stderr, "dcerpcd: failed to load passwd file \"%s\"\n",
                        passwd_path);
                dcerpcd_config_free();
                return 1;
        }

        memset(&server, 0, sizeof(server));
        server.handlers = &handlers;
        server.port = cfg->port;
        server.allow_anonymous = 1;
        /*
         * Signing remains disabled: guest sessions have no session key.
         * Authenticated NTLM/KRB sessions still work without signing.
         */
        server.signing_enabled = 0;
        /*
         * server.auth_data is owned by libsmb2 Kerberos (private_auth_data
         * when a keytab is configured). Do NOT store the NTLM passwd DB
         * here: krb5_renew_server_credentials() / krb5_free_server_credentials()
         * would treat it as Kerberos state and crash. NTLM looks up users
         * via dcerpcd_passwd_get() instead.
         */
        server.auth_data = NULL;

        if (cfg->hostname && cfg->hostname[0]) {
                strncpy(server.hostname, cfg->hostname,
                        sizeof(server.hostname) - 1);
        } else {
                gethostname(server.hostname, sizeof(server.hostname));
        }
        if (cfg->domain && cfg->domain[0]) {
                strncpy(server.domain, cfg->domain, sizeof(server.domain) - 1);
        } else {
                strncpy(server.domain, "WORKGROUP",
                        sizeof(server.domain) - 1);
        }

        /*
         * Kerberos: smb2_serve_port() calls krb5_init_server_credentials()
         * with server->keytab_path. Empty path skips keytab init (default
         * GSS acceptor creds). When krb5 is disabled we leave keytab empty
         * and force NTLMSSP-only on each connection.
         */
        if (cfg->krb5 && cfg->keytab && cfg->keytab[0]) {
                strncpy(server.keytab_path, cfg->keytab,
                        sizeof(server.keytab_path) - 1);
        }

        if (dcerpcd_epm_init(server.hostname) != 0) {
                fprintf(stderr, "dcerpcd: failed to init endpoint mapper\n");
                dcerpcd_auth_shutdown();
                dcerpcd_config_free();
                return 1;
        }

        if (dcerpcd_external_init(svc_sock) != 0) {
                fprintf(stderr,
                        "dcerpcd: failed to open service socket \"%s\"\n",
                        svc_sock);
                dcerpcd_epm_shutdown();
                dcerpcd_auth_shutdown();
                dcerpcd_config_free();
                return 1;
        }

        printf("dcerpcd: listening on port %u (guest + NTLMSSP%s, IPC$, "
               "epmapper np, svc sock %s, %u endpoint(s))\n",
               cfg->port,
               cfg->krb5 ? " + Kerberos/GSSAPI" : " (Kerberos disabled)",
               svc_sock, dcerpcd_epm_count());
        if (cfg->krb5 && cfg->keytab && cfg->keytab[0]) {
                printf("dcerpcd: keytab %s\n", cfg->keytab);
        }

        server.extra_fdset = dcerpcd_external_serve_fdset;
        server.extra_service = dcerpcd_external_serve_service;

        err = smb2_serve_port(&server, 4, on_new_client, NULL);
        if (err) {
                fprintf(stderr, "smb2_serve_port failed: %d (%s)\n",
                        err, strerror(-err));
                if (server.error[0]) {
                        fprintf(stderr, "dcerpcd: %s\n", server.error);
                }
                dcerpcd_external_shutdown();
                dcerpcd_epm_shutdown();
                dcerpcd_auth_shutdown();
                dcerpcd_config_free();
                return 1;
        }

        dcerpcd_external_shutdown();
        dcerpcd_epm_shutdown();
        dcerpcd_auth_shutdown();
        dcerpcd_config_free();
        return 0;
}
