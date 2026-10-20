/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * dcerpcd internal structures and authentication helpers.
 *
 */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _DCERPCD_H_
#define _DCERPCD_H_

#include <stdint.h>
#include <sys/select.h>
#include <sys/types.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/epm.h>

struct smb2_context;
struct smb2_server;

#define DEFAULT_PORT 445

/*
 * Runtime configuration from /etc/dcerpcd/config (or -c path).
 * Same layout as config.idl / struct config_CONFIG (kept as a dcerpc
 * mem-tree root when loaded from YAML; free with dcerpcd_config_free()).
 *
 * Example:
 *   CONFIG:
 *     port: 445
 *     krb5: 1
 *     keytab: /etc/krb5.keytab
 *     hostname: fileserver
 *     domain: EXAMPLE.COM
 *
 * krb5: 0 — do not advertise or accept Kerberos/GSSAPI (NTLMSSP only).
 * krb5: 1 — enable Kerberos (default when the file is absent).
 */
#include "config_coder.h"
typedef struct config_CONFIG dcerpcd_config;

/* path may be NULL or missing file → defaults; returns 0 / -1 */
int dcerpcd_config_load(const char *path);
/* Process-lifetime config pointer (never NULL after successful load/defaults). */
const dcerpcd_config *dcerpcd_config_get(void);
/* Free YAML mem-tree if any; safe to call more than once. */
void dcerpcd_config_free(void);

/*
 * NTLM password database from /etc/dcerpcd/passwd (or -f path).
 * Same layout as passwd.idl / struct passwd_PASSWD (kept as a dcerpc
 * mem-tree root when loaded from YAML; free with dcerpcd_passwd_free()).
 *
 * Example:
 *   PASSWD:
 *     count: 1
 *     entry:
 *       - user: alice
 *         password: secret
 *
 * The file must be a regular file owned by the process euid with mode 0600.
 */
#include "passwd_coder.h"
typedef struct passwd_entry  dcerpcd_user;
typedef struct passwd_PASSWD dcerpcd_passwd;

/*
 * Per-connection authentication state, stored via smb2_set_opaque().
 */
enum dcerpcd_auth_kind {
        DCERPCD_AUTH_NONE = 0,
        DCERPCD_AUTH_GUEST,
        DCERPCD_AUTH_USER,
};

/*
 * RPC service backing a named pipe.
 *
 * BUILTIN_* handlers run in-process. EXTERNAL services are separate
 * processes that connect to dcerpcd over the control Unix domain socket
 * and register the pipe they serve (see external.c); dcerpcd forwards the
 * pipe's bytes and the DCE/RPC is theirs.
 */
enum dcerpcd_service_kind {
        DCERPCD_SVC_NONE = 0,
        DCERPCD_SVC_BUILTIN_EPM,  /* in-process endpoint mapper */
        DCERPCD_SVC_EXTERNAL,     /* service process via control UDS */
};

struct dcerpcd_service {
        const char *pipe_name;    /* base name: "epmapper", "srvsvc", ... */
        enum dcerpcd_service_kind kind;
        const char *annotation;
        int conn_fd;              /* EXTERNAL: live control-socket fd, else -1 */
};

struct dcerpcd_pipe;

struct dcerpcd_conn {
        uint32_t session_id;    /* unique per client connection (monotonic) */
        enum dcerpcd_auth_kind auth_kind;
        uid_t uid;              /* valid when auth_kind == DCERPCD_AUTH_USER */
        char *username;         /* "guest" or the authenticated local user */
        /*
         * Who NTLMSSP authorize_user() is checking the client's proof
         * for. Only once the proof is verified does
         * dcerpcd_auth_session_established() make it the identity above.
         */
        enum dcerpcd_auth_kind pending_kind;
        uid_t pending_uid;
        char *pending_username;
        struct dcerpcd_pipe *pipes; /* open named pipes on this connection */
};

/* Resolve a pipe base name to a known service, or NULL if unknown. */
const struct dcerpcd_service *dcerpcd_service_lookup(const char *pipe_name);

/*
 * Dynamic EXTERNAL service registry (pipe.c).
 * pipe_name is the base name ("srvsvc"), not the full \\pipe\\ path.
 * conn_fd is the service's control-socket connection. Returns -1 if the
 * pipe is a builtin or already registered.
 */
int dcerpcd_service_add_external(const char *pipe_name,
                                 const char *annotation,
                                 int conn_fd);
void dcerpcd_service_remove_by_fd(int conn_fd);

/*
 * Pipes of EXTERNAL services (external.c, framing in dcerpcd_proto.h).
 *
 * dcerpcd_external_open() tells the service on conn_fd that a client
 * opened its pipe and returns the pipe's id. cb is called with each pipe
 * message the service sends for it: data is malloc'd and the callee's.
 * cb with data NULL means the pipe is broken (the service closed it or
 * went away); it is not called again and the id is gone.
 *
 * dcerpcd_external_write() forwards what the client wrote and
 * dcerpcd_external_close() the client's close; cb is not called after it.
 * Messages are queued, so neither blocks on the service.
 */
typedef void (*dcerpcd_external_pipe_cb)(void *cb_data,
                                         uint8_t *data,
                                         uint32_t len);

int dcerpcd_external_open(int conn_fd,
                          uint32_t session_id,
                          int32_t uid,
                          const char *user,
                          dcerpcd_external_pipe_cb cb,
                          void *cb_data,
                          uint32_t *pipe_id);
int dcerpcd_external_write(uint32_t pipe_id, const uint8_t *buf, size_t len);
void dcerpcd_external_close(uint32_t pipe_id);

/*
 * Integrate external control sockets into smb2_serve_port's select loop:
 *   dcerpcd_external_fdset()   — listen + all services
 *   dcerpcd_external_service() — accept, registration, pipe messages
 */
void dcerpcd_external_fdset(fd_set *rfds, fd_set *wfds, int *maxfd);
void dcerpcd_external_service(fd_set *rfds, fd_set *wfds);

/* smb2_server.extra_* wrappers (server arg unused). */
void dcerpcd_external_serve_fdset(struct smb2_server *server,
                                  fd_set *rfds, fd_set *wfds, int *maxfd);
void dcerpcd_external_serve_service(struct smb2_server *server,
                                    fd_set *rfds, fd_set *wfds);

/*
 * Load / free the passwd database (passwd.c) via dcerpc_read_yaml_file().
 * path is a YAML file as above (passwd.idl PASSWD root).
 * Returns 0 on success, -1 on error (message on stderr).
 * get() is NULL until a successful load (no built-in defaults).
 */
int dcerpcd_passwd_load(const char *path);
const dcerpcd_passwd *dcerpcd_passwd_get(void);
void dcerpcd_passwd_free(void);
const dcerpcd_user *dcerpcd_passwd_find(const dcerpcd_passwd *db,
                                        const char *user);

/*
 * Authentication subsystem (auth.c).
 *
 * dcerpcd_auth_init() loads the passwd file.
 * dcerpcd_auth_setup_client() attaches per-connection state and selects
 * NTLMSSP-only or NTLMSSP+Kerberos (GSSAPI) from the config.
 * Handler helpers below are installed on the smb2_server.
 */
int dcerpcd_auth_init(const char *passwd_path);
void dcerpcd_auth_shutdown(void);
void *dcerpcd_auth_passwd_db(void);

void dcerpcd_auth_setup_client(struct smb2_context *smb2);
struct dcerpcd_conn *dcerpcd_auth_conn(struct smb2_context *smb2);

/* True if the SMB session authenticated as local uid 0 (root). */
int dcerpcd_conn_is_root(const struct dcerpcd_conn *conn);

int dcerpcd_auth_destruction(struct smb2_server *srvr,
                             struct smb2_context *smb2);
int dcerpcd_auth_authorize_user(struct smb2_server *srvr,
                                struct smb2_context *smb2,
                                const char *user,
                                const char *domain,
                                const char *workstation);
int dcerpcd_auth_session_established(struct smb2_server *srvr,
                                     struct smb2_context *smb2);

/*
 * Endpoint mapper registry (epm.c) — ncacn_np / named pipe transport only.
 *
 * Maintains the list of registered endpoints and implements ept_* operations
 * against it. Full SMB named-pipe I/O for \pipe\epmapper is layered on later.
 */
int dcerpcd_epm_init(const char *hostname);
void dcerpcd_epm_shutdown(void);

/*
 * Register a named-pipe endpoint.
 * pipe: pipe path as stored in the tower (e.g. "\\pipe\\epmapper" or "srvsvc").
 * object: optional object UUID (NULL => nil UUID).
 * host: NetBIOS/host for the tower (NULL => hostname from epm_init).
 * owner_fd: if >= 0, entry is owned by that external control-socket fd and
 *           is removed by dcerpcd_epm_unregister_by_owner() on disconnect.
 */
int dcerpcd_epm_register_np(const dcerpc_uuid_t *iface,
                            uint16_t vers_major, uint16_t vers_minor,
                            const dcerpc_uuid_t *object,
                            const char *pipe,
                            const char *annotation,
                            const char *host,
                            int owner_fd);

/* Drop all EPM entries registered with the given owner_fd. */
void dcerpcd_epm_unregister_by_owner(int owner_fd);

uint32_t dcerpcd_epm_count(void);

/*
 * External service control channel (external.c).
 *
 * Listens on a Unix domain socket (default: /var/run/dcerpcd/dcerpcd.sock).
 * Services connect, send a YAML registration, and stay connected so that
 * dcerpcd can forward their pipe's traffic. On disconnect, EPM + service
 * entries go away and the open pipes break.
 */
#define DCERPCD_DEFAULT_SVC_SOCK "/var/run/dcerpcd/dcerpcd.sock"

int dcerpcd_external_init(const char *sock_path);
void dcerpcd_external_shutdown(void);

/* Wire framing for the pipes of external services (also used by them). */
#include "dcerpcd_proto.h"

/*
 * ept_* handlers (named-pipe endpoints only). What a reply points to is
 * allocated on pdu, the request's, and freed with it.
 */
int dcerpcd_epm_Lookup(struct dcerpc_pdu *pdu,
                       const struct epm_Lookup_req *req,
                       struct epm_Lookup_rep *rep);
int dcerpcd_epm_Map(struct dcerpc_pdu *pdu,
                    const struct epm_Map_req *req,
                    struct epm_Map_rep *rep);
int dcerpcd_epm_LookupHandleFree(const struct epm_LookupHandleFree_req *req,
                                 struct epm_LookupHandleFree_rep *rep);

/*
 * Named-pipe server (pipe.c): CREATE/CLOSE of known pipes, and
 * FSCTL_PIPE_TRANSCEIVE/READ/WRITE carrying DCE/RPC to libdcerpc's server
 * runtime (<dcerpc/server.h>) for the builtin endpoint mapper, one
 * endpoint per open, or as bytes to the process of an EXTERNAL service.
 */
void dcerpcd_pipe_conn_cleanup(struct dcerpcd_conn *conn);

int dcerpcd_pipe_create(struct smb2_server *srvr, struct smb2_context *smb2,
                        struct smb2_create_request *req,
                        struct smb2_create_reply *rep);
int dcerpcd_pipe_close(struct smb2_server *srvr, struct smb2_context *smb2,
                       struct smb2_close_request *req,
                       struct smb2_close_reply *rep);
int dcerpcd_pipe_ioctl(struct smb2_server *srvr, struct smb2_context *smb2,
                       struct smb2_ioctl_request *req,
                       struct smb2_ioctl_reply *rep);
int dcerpcd_pipe_read(struct smb2_server *srvr, struct smb2_context *smb2,
                      struct smb2_read_request *req,
                      struct smb2_read_reply *rep);
int dcerpcd_pipe_write(struct smb2_server *srvr, struct smb2_context *smb2,
                       struct smb2_write_request *req,
                       struct smb2_write_reply *rep);

#endif /* _DCERPCD_H_ */
