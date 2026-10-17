/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Named pipes for dcerpcd: CREATE/CLOSE of the pipes of known services,
 * and FSCTL_PIPE_TRANSCEIVE, READ and WRITE carrying DCE/RPC. The DCE/RPC
 * of the builtin endpoint mapper (BIND, fragments, dispatch) is libdcerpc's
 * server runtime (<dcerpc/server.h>), one endpoint per open pipe, served
 * from the epm coders and the stubs below. The pipes of EXTERNAL services
 * are only bytes here: what the client writes goes to the service process,
 * which runs the DCE/RPC, and what it sends back is queued for the
 * client's reads.
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
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

#include <dcerpc/dcerpc.h>
#include <dcerpc/epm.h>
#include <dcerpc/server.h>

#include "dcerpcd.h"

/*
 * Builtin services run in-process. EXTERNAL services are registered at
 * runtime when a worker connects on the control UDS (external.c).
 */
static const struct dcerpcd_service builtin_services[] = {
        {
                .pipe_name = "epmapper",
                .kind = DCERPCD_SVC_BUILTIN_EPM,
                .annotation = "Endpoint Mapper",
                .conn_fd = -1,
        },
        { NULL, DCERPCD_SVC_NONE, NULL, -1 }
};

/* Dynamically registered EXTERNAL services (owned strings). */
struct dcerpcd_ext_svc {
        struct dcerpcd_ext_svc *next;
        struct dcerpcd_service svc;
        char *pipe_name_owned;
        char *annotation_owned;
};

static struct dcerpcd_ext_svc *ext_services;
static pthread_mutex_t svc_lock = PTHREAD_MUTEX_INITIALIZER;

/* A pipe message from an EXTERNAL service, not yet read by the client */
struct pipe_msg {
        struct pipe_msg *next;
        uint8_t *data;
        uint32_t len;
        uint32_t off;               /* read so far */
};

struct dcerpcd_pipe {
        struct dcerpcd_pipe *next;
        smb2_file_id file_id;
        char *name;                 /* base pipe name, e.g. "epmapper" */
        struct smb2_context *smb2;
        enum dcerpcd_service_kind kind;

        /* builtin: this open's DCE/RPC endpoint and pipe */
        struct dcerpc_server *srv;
        struct dcerpc_server_pipe *rpc;

        /* EXTERNAL: the pipe at the service, and what it sent */
        uint32_t ext_id;
        int broken;                 /* the service closed it or went away */
        struct pipe_msg *out;
        struct pipe_msg **out_tail;

        /* TRANSCEIVE or READ waiting for the service's output */
        uint8_t wait_cmd;           /* 0, SMB2_IOCTL or SMB2_READ */
        uint64_t wait_msgid;
        uint32_t wait_max;
        uint32_t wait_flags;
};

static uint64_t next_fid = 1;

const struct dcerpcd_service *
dcerpcd_service_lookup(const char *pipe_name)
{
        const struct dcerpcd_service *s;
        struct dcerpcd_ext_svc *e;

        if (pipe_name == NULL || pipe_name[0] == '\0') {
                return NULL;
        }
        for (s = builtin_services; s->pipe_name; s++) {
                if (strcasecmp(s->pipe_name, pipe_name) == 0) {
                        return s;
                }
        }
        pthread_mutex_lock(&svc_lock);
        for (e = ext_services; e; e = e->next) {
                if (e->svc.pipe_name &&
                    strcasecmp(e->svc.pipe_name, pipe_name) == 0) {
                        pthread_mutex_unlock(&svc_lock);
                        return &e->svc;
                }
        }
        pthread_mutex_unlock(&svc_lock);
        return NULL;
}

int
dcerpcd_service_add_external(const char *pipe_name,
                             const char *annotation,
                             int conn_fd)
{
        struct dcerpcd_ext_svc *e;

        if (pipe_name == NULL || pipe_name[0] == '\0' || conn_fd < 0) {
                return -1;
        }
        /* Refuse shadowing a builtin pipe name. */
        {
                const struct dcerpcd_service *s;

                for (s = builtin_services; s->pipe_name; s++) {
                        if (strcasecmp(s->pipe_name, pipe_name) == 0) {
                                fprintf(stderr,
                                        "service: cannot override builtin "
                                        "pipe %s\n", pipe_name);
                                return -1;
                        }
                }
        }

        e = calloc(1, sizeof(*e));
        if (e == NULL) {
                return -1;
        }
        e->pipe_name_owned = strdup(pipe_name);
        e->annotation_owned = strdup(annotation ? annotation : "");
        if (e->pipe_name_owned == NULL || e->annotation_owned == NULL) {
                free(e->pipe_name_owned);
                free(e->annotation_owned);
                free(e);
                return -1;
        }
        e->svc.pipe_name = e->pipe_name_owned;
        e->svc.kind = DCERPCD_SVC_EXTERNAL;
        e->svc.annotation = e->annotation_owned;
        e->svc.conn_fd = conn_fd;

        pthread_mutex_lock(&svc_lock);
        /* A pipe belongs to the first service that registers it */
        {
                struct dcerpcd_ext_svc *cur;

                for (cur = ext_services; cur; cur = cur->next) {
                        if (cur->svc.conn_fd == conn_fd ||
                            strcasecmp(cur->svc.pipe_name, pipe_name) == 0) {
                                pthread_mutex_unlock(&svc_lock);
                                fprintf(stderr, "service: pipe %s is already "
                                        "registered\n", pipe_name);
                                free(e->pipe_name_owned);
                                free(e->annotation_owned);
                                free(e);
                                return -1;
                        }
                }
        }
        e->next = ext_services;
        ext_services = e;
        pthread_mutex_unlock(&svc_lock);

        printf("service: registered EXTERNAL pipe=%s conn_fd=%d (%s)\n",
               pipe_name, conn_fd, annotation ? annotation : "");
        return 0;
}

void
dcerpcd_service_remove_by_fd(int conn_fd)
{
        struct dcerpcd_ext_svc **pp;
        int removed = 0;

        if (conn_fd < 0) {
                return;
        }
        pthread_mutex_lock(&svc_lock);
        pp = &ext_services;
        while (*pp) {
                struct dcerpcd_ext_svc *cur = *pp;

                if (cur->svc.conn_fd == conn_fd) {
                        *pp = cur->next;
                        printf("service: unregistered EXTERNAL pipe=%s "
                               "conn_fd=%d\n",
                               cur->svc.pipe_name ? cur->svc.pipe_name : "?",
                               conn_fd);
                        free(cur->pipe_name_owned);
                        free(cur->annotation_owned);
                        free(cur);
                        removed++;
                        continue;
                }
                pp = &cur->next;
        }
        pthread_mutex_unlock(&svc_lock);
        (void)removed;
}

static const char *
service_kind_str(enum dcerpcd_service_kind kind)
{
        switch (kind) {
        case DCERPCD_SVC_BUILTIN_EPM:
                return "builtin-epm";
        case DCERPCD_SVC_EXTERNAL:
                return "external";
        default:
                return "none";
        }
}


/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static void
put_le32(uint8_t *p, uint32_t v)
{
        p[0] = (uint8_t)(v & 0xff);
        p[1] = (uint8_t)((v >> 8) & 0xff);
        p[2] = (uint8_t)((v >> 16) & 0xff);
        p[3] = (uint8_t)((v >> 24) & 0xff);
}

static int
fid_equal(const smb2_file_id a, const smb2_file_id b)
{
        return memcmp(a, b, SMB2_FD_SIZE) == 0;
}

static void
fid_assign(smb2_file_id dst, uint64_t persistent, uint64_t volatile_id)
{
        put_le32(dst, (uint32_t)(persistent & 0xffffffff));
        put_le32(dst + 4, (uint32_t)(persistent >> 32));
        put_le32(dst + 8, (uint32_t)(volatile_id & 0xffffffff));
        put_le32(dst + 12, (uint32_t)(volatile_id >> 32));
}

/*
 * Create name is typically "epmapper" (relative to IPC$). Accept common
 * variants and return a malloc'd base name, or NULL if not a pipe we serve.
 */
static char *
pipe_basename(const char *name)
{
        const char *p;

        if (name == NULL || name[0] == '\0') {
                return NULL;
        }
        p = name;
        /* strip leading slashes / backslashes and optional "pipe\" */
        while (*p == '\\' || *p == '/') {
                p++;
        }
        if (!strncasecmp(p, "pipe", 4) && (p[4] == '\\' || p[4] == '/')) {
                p += 5;
                while (*p == '\\' || *p == '/') {
                        p++;
                }
        }
        if (*p == '\0') {
                return NULL;
        }
        return strdup(p);
}

static struct dcerpcd_pipe *
pipe_find(struct dcerpcd_conn *conn, const smb2_file_id fid)
{
        struct dcerpcd_pipe *p;

        if (conn == NULL) {
                return NULL;
        }
        for (p = conn->pipes; p; p = p->next) {
                if (fid_equal(p->file_id, fid)) {
                        return p;
                }
        }
        return NULL;
}


static void
pipe_free(struct dcerpcd_pipe *p)
{
        if (p == NULL) {
                return;
        }
        if (p->kind == DCERPCD_SVC_EXTERNAL && !p->broken) {
                dcerpcd_external_close(p->ext_id);
        }
        while (p->out) {
                struct pipe_msg *m = p->out;

                p->out = m->next;
                free(m->data);
                free(m);
        }
        if (p->rpc) {
                dcerpc_server_pipe_destroy(p->rpc);
        }
        if (p->srv) {
                dcerpc_server_destroy(p->srv);
        }
        free(p->name);
        free(p);
}

void
dcerpcd_pipe_conn_cleanup(struct dcerpcd_conn *conn)
{
        struct dcerpcd_pipe *p;

        if (conn == NULL) {
                return;
        }
        while (conn->pipes) {
                p = conn->pipes;
                conn->pipes = p->next;
                pipe_free(p);
        }
}

/* ------------------------------------------------------------------ */
/* Builtin endpoint mapper                                             */
/* ------------------------------------------------------------------ */

/* The dcerpcd pipe of the call a stub is running for */
static struct dcerpcd_pipe *
stub_pipe(struct dcerpc_pdu *pdu)
{
        struct dcerpc_server_call *call = dcerpc_pdu_server_call(pdu);
        struct dcerpc_server_pipe *rpc;

        rpc = call ? dcerpc_server_call_get_pipe(call) : NULL;
        return rpc ? dcerpc_server_pipe_get_private(rpc) : NULL;
}

/*
 * ept_Lookup and ept_Map are open to any session, guests included; the
 * other ept_* operations need a session authenticated as local root.
 */
static int
epm_allowed(struct dcerpc_pdu *pdu, const char *op)
{
        struct dcerpcd_pipe *p = stub_pipe(pdu);
        struct dcerpcd_conn *conn = p ? dcerpcd_auth_conn(p->smb2) : NULL;

        if (dcerpcd_conn_is_root(conn)) {
                return 1;
        }
        fprintf(stderr, "pipe: epm %s denied session=%u user=%s uid=%ld "
                "(root required)\n", op, conn ? conn->session_id : 0,
                conn && conn->username ? conn->username : "?",
                conn ? (long)conn->uid : -1L);
        return 0;
}

static int
epm_lookup_stub(struct dcerpc_context *dce _U_, struct dcerpc_pdu *pdu,
                void *req, void *rep)
{
        return dcerpcd_epm_Lookup(pdu, req, rep) ? -1 : 0;
}

static int
epm_map_stub(struct dcerpc_context *dce _U_, struct dcerpc_pdu *pdu,
             void *req, void *rep)
{
        return dcerpcd_epm_Map(pdu, req, rep) ? -1 : 0;
}

static int
epm_lookuphandlefree_stub(struct dcerpc_context *dce _U_,
                          struct dcerpc_pdu *pdu, void *req, void *rep)
{
        if (!epm_allowed(pdu, "LookupHandleFree")) {
                return DCERPC_FAULT_ACCESS_DENIED;
        }
        return dcerpcd_epm_LookupHandleFree(req, rep) ? -1 : 0;
}

static const struct dcerpc_stub epm_stubs[] = {
        { EPM_LOOKUP, "Lookup", epm_lookup_stub },
        { EPM_MAP, "Map", epm_map_stub },
        { EPM_LOOKUPHANDLEFREE, "LookupHandleFree",
          epm_lookuphandlefree_stub },
        { -1, NULL, NULL }
};

/* ------------------------------------------------------------------ */
/* Pipe messages                                                       */
/* ------------------------------------------------------------------ */

static int
pipe_has_output(struct dcerpcd_pipe *pipe)
{
        if (pipe->kind == DCERPCD_SVC_EXTERNAL) {
                return pipe->out != NULL;
        }
        return dcerpc_server_pipe_has_output(pipe->rpc);
}

/*
 * Up to max bytes of the next pipe message. *more is set when the
 * message did not fit and the rest is returned by the next read.
 */
static size_t
pipe_take(struct dcerpcd_pipe *pipe, uint8_t *buf, size_t max, int *more)
{
        struct pipe_msg *m = pipe->out;
        size_t n;

        if (pipe->kind != DCERPCD_SVC_EXTERNAL) {
                return dcerpc_server_pipe_read(pipe->rpc, buf, max, more);
        }
        *more = 0;
        if (m == NULL) {
                return 0;
        }
        n = m->len - m->off;
        if (n > max) {
                n = max;
                *more = 1;
        }
        memcpy(buf, m->data + m->off, n);
        m->off += (uint32_t)n;
        if (m->off == m->len) {
                pipe->out = m->next;
                if (pipe->out == NULL) {
                        pipe->out_tail = &pipe->out;
                }
                free(m->data);
                free(m);
        }
        return n;
}

/*
 * Answer a TRANSCEIVE (SMB2_IOCTL) or READ with the next pipe message,
 * truncated to max bytes with STATUS_BUFFER_OVERFLOW if it does not fit.
 * Without output the reply is empty.
 */
static int
pipe_send_message(struct dcerpcd_pipe *pipe, uint8_t cmd, uint64_t msgid,
                  uint32_t max, uint32_t flags)
{
        struct smb2_context *smb2 = pipe->smb2;
        struct smb2_pdu *pdu;
        uint8_t *data;
        size_t len;
        int more;

        /* a message is at most one fragment */
        data = malloc(max < 0x10000 ? (max ? max : 1) : 0x10000);
        if (data == NULL) {
                return -1;
        }
        len = pipe_take(pipe, data, max < 0x10000 ? max : 0x10000, &more);
        if (cmd == SMB2_READ) {
                struct smb2_read_reply rep;

                memset(&rep, 0, sizeof(rep));
                rep.data = data;
                rep.data_length = (uint32_t)len;
                /* the encoder takes ownership of data when len > 0 */
                pdu = smb2_cmd_read_reply_async(smb2, &rep, NULL, NULL);
                if (len == 0) {
                        free(data);
                }
        } else {
                struct smb2_ioctl_reply rep;

                memset(&rep, 0, sizeof(rep));
                rep.ctl_code = SMB2_FSCTL_PIPE_TRANSCEIVE;
                memcpy(rep.file_id, pipe->file_id, SMB2_FD_SIZE);
                rep.output = data;
                rep.output_count = (uint32_t)len;
                rep.flags = flags;
                /* the encoder copies output */
                pdu = smb2_cmd_ioctl_reply_async(smb2, &rep, NULL, NULL);
                free(data);
        }
        if (pdu == NULL) {
                return -1;
        }
        if (more) {
                smb2_set_pdu_status(smb2, pdu, SMB2_STATUS_BUFFER_OVERFLOW);
        }
        smb2_set_pdu_message_id(smb2, pdu, msgid);
        smb2_queue_pdu(smb2, pdu);
        return 0;
}

static void
pipe_send_error(struct smb2_context *smb2, uint8_t cmd, uint64_t msgid,
                uint32_t status)
{
        struct smb2_error_reply err;
        struct smb2_pdu *pdu;

        memset(&err, 0, sizeof(err));
        pdu = smb2_cmd_error_reply_async(smb2, &err, cmd, (int)status,
                                         NULL, NULL);
        if (pdu == NULL) {
                return;
        }
        smb2_set_pdu_message_id(smb2, pdu, msgid);
        smb2_queue_pdu(smb2, pdu);
}

/*
 * Complete a TRANSCEIVE/READ that was waiting for the service: with its
 * output, or STATUS_PIPE_BROKEN once there will be none.
 */
static void
pipe_complete_wait(struct dcerpcd_pipe *pipe)
{
        uint8_t cmd = pipe->wait_cmd;

        if (cmd == 0) {
                return;
        }
        if (!pipe_has_output(pipe) && !pipe->broken) {
                return;
        }
        pipe->wait_cmd = 0;
        if (!pipe_has_output(pipe) ||
            pipe_send_message(pipe, cmd, pipe->wait_msgid, pipe->wait_max,
                              pipe->wait_flags)) {
                pipe_send_error(pipe->smb2, cmd, pipe->wait_msgid,
                                SMB2_STATUS_PIPE_BROKEN);
        }
}

/* The service sent a pipe message, or broke the pipe (data NULL) */
static void
external_output(void *cb_data, uint8_t *data, uint32_t len)
{
        struct dcerpcd_pipe *pipe = cb_data;
        struct pipe_msg *m;

        if (data == NULL) {
                printf("pipe: %s: the service closed the pipe\n", pipe->name);
                pipe->broken = 1;
                pipe_complete_wait(pipe);
                return;
        }
        m = calloc(1, sizeof(*m));
        if (m == NULL) {
                free(data);
                return;
        }
        m->data = data;
        m->len = len;
        *pipe->out_tail = m;
        pipe->out_tail = &m->next;
        pipe_complete_wait(pipe);
}

/* The endpoint for a new open of a builtin service's pipe */
static struct dcerpc_server *
service_endpoint(const struct dcerpcd_service *svc, const char *name)
{
        struct dcerpc_server *srv;

        if (svc->kind != DCERPCD_SVC_BUILTIN_EPM) {
                return NULL;
        }
        srv = dcerpc_server_create(name);
        if (srv == NULL) {
                return NULL;
        }
        if (dcerpc_server_add_interface(srv, &epm_interface, epm_procs,
                                        epm_stubs, DCERPC_SERVER_ALL_NDR)) {
                dcerpc_server_destroy(srv);
                return NULL;
        }
        return srv;
}

/* ------------------------------------------------------------------ */
/* SMB2 server handlers                                                */
/* ------------------------------------------------------------------ */

int
dcerpcd_pipe_create(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                    struct smb2_create_request *req,
                    struct smb2_create_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        struct dcerpcd_pipe *p;
        const struct dcerpcd_service *svc;
        char *base;

        if (conn == NULL) {
                return -1;
        }
        base = pipe_basename(req->name);
        svc = dcerpcd_service_lookup(base);
        if (base == NULL || svc == NULL) {
                fprintf(stderr,
                        "pipe: CREATE rejected session=%u name=\"%s\" "
                        "(unknown service)\n",
                        conn->session_id,
                        req->name ? req->name : "(null)");
                free(base);
                return -1;
        }
        if (svc->kind == DCERPCD_SVC_EXTERNAL && svc->conn_fd < 0) {
                fprintf(stderr,
                        "pipe: CREATE session=%u %s: EXTERNAL service not "
                        "connected\n",
                        conn->session_id, base);
                free(base);
                return -1;
        }

        p = calloc(1, sizeof(*p));
        if (p == NULL) {
                free(base);
                return -1;
        }
        p->name = base;
        p->smb2 = smb2;
        p->kind = svc->kind;
        p->out_tail = &p->out;
        if (svc->kind == DCERPCD_SVC_EXTERNAL) {
                if (dcerpcd_external_open(svc->conn_fd, conn->session_id,
                                          conn->auth_kind == DCERPCD_AUTH_USER ?
                                          (int32_t)conn->uid :
                                          DCERPCD_UID_GUEST,
                                          conn->username,
                                          external_output, p,
                                          &p->ext_id)) {
                        fprintf(stderr, "pipe: CREATE session=%u %s: the "
                                "service did not take it\n",
                                conn->session_id, base);
                        p->broken = 1;
                        pipe_free(p);
                        return -1;
                }
        } else {
                p->srv = service_endpoint(svc, base);
                p->rpc = p->srv ? dcerpc_server_pipe_create(p->srv, p) : NULL;
                if (p->rpc == NULL) {
                        fprintf(stderr, "pipe: CREATE session=%u %s: no "
                                "DCE/RPC endpoint\n", conn->session_id, base);
                        pipe_free(p);
                        return -1;
                }
        }
        fid_assign(p->file_id, next_fid, next_fid + 0x10000);
        next_fid++;
        p->next = conn->pipes;
        conn->pipes = p;

        memset(rep, 0, sizeof(*rep));
        rep->oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        rep->create_action = SMB2_FILE_OPEN; /* FILE_OPENED */
        rep->file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
        memcpy(rep->file_id, p->file_id, SMB2_FD_SIZE);

        printf("pipe: CREATE session=%u %s service=%s kind=%s\n",
               conn->session_id, p->name, svc->pipe_name,
               service_kind_str(svc->kind));
        return 0;
}

int
dcerpcd_pipe_close(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                   struct smb2_close_request *req,
                   struct smb2_close_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        struct dcerpcd_pipe **pp;

        memset(rep, 0, sizeof(*rep));
        if (conn == NULL) {
                return 0;
        }
        for (pp = &conn->pipes; *pp; pp = &(*pp)->next) {
                if (fid_equal((*pp)->file_id, req->file_id)) {
                        struct dcerpcd_pipe *p = *pp;

                        *pp = p->next;
                        if (p->wait_cmd) {
                                pipe_send_error(smb2, p->wait_cmd,
                                                p->wait_msgid,
                                                SMB2_STATUS_PIPE_BROKEN);
                        }
                        printf("pipe: CLOSE session=%u %s kind=%s\n",
                               conn->session_id,
                               p->name ? p->name : "?",
                               service_kind_str(p->kind));
                        pipe_free(p);
                        return 0;
                }
        }
        return 0;
}

/*
 * Park a TRANSCEIVE/READ until the service sends output, as a read of an
 * empty pipe blocks. Only one may wait at a time.
 */
static int
pipe_wait(struct dcerpcd_pipe *pipe, uint8_t cmd, uint32_t max,
          uint32_t flags)
{
        uint64_t msgid = smb2_get_last_request_message_id(pipe->smb2);

        if (pipe->wait_cmd) {
                pipe_send_error(pipe->smb2, cmd, msgid, SMB2_STATUS_PIPE_BUSY);
                return 1;
        }
        pipe->wait_cmd = cmd;
        pipe->wait_msgid = msgid;
        pipe->wait_max = max;
        pipe->wait_flags = flags;
        return 1;
}

/* What the client wrote, to the DCE/RPC of the pipe. -1 on error. */
static int
pipe_input(struct dcerpcd_pipe *p, const uint8_t *buf, size_t len)
{
        if (p->kind == DCERPCD_SVC_EXTERNAL) {
                return dcerpcd_external_write(p->ext_id, buf, len);
        }
        if (dcerpc_server_pipe_write(p->rpc, buf, len)) {
                fprintf(stderr, "pipe: %s: not DCE/RPC\n", p->name);
                return -1;
        }
        return 0;
}

int
dcerpcd_pipe_ioctl(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                   struct smb2_ioctl_request *req,
                   struct smb2_ioctl_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        struct dcerpcd_pipe *p;

        memset(rep, 0, sizeof(*rep));
        rep->ctl_code = req->ctl_code;
        memcpy(rep->file_id, req->file_id, SMB2_FD_SIZE);

        if (req->ctl_code == SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO) {
                /* library handles this before calling us, but be safe */
                return -1;
        }

        if (req->ctl_code != SMB2_FSCTL_PIPE_TRANSCEIVE) {
                fprintf(stderr, "pipe: unsupported ioctl session=%u 0x%08x\n",
                        conn ? conn->session_id : 0, req->ctl_code);
                return -1;
        }

        p = pipe_find(conn, req->file_id);
        if (p == NULL) {
                fprintf(stderr,
                        "pipe: TRANSCEIVE session=%u on unknown file_id\n",
                        conn ? conn->session_id : 0);
                return -1;
        }

        if (p->broken) {
                pipe_send_error(smb2, SMB2_IOCTL,
                                smb2_get_last_request_message_id(smb2),
                                SMB2_STATUS_PIPE_BROKEN);
                return 1;
        }
        if (pipe_input(p, req->input, req->input_count)) {
                return -1;
        }
        if (!pipe_has_output(p) && p->kind == DCERPCD_SVC_EXTERNAL) {
                /* the reply comes when the service sends it */
                return pipe_wait(p, SMB2_IOCTL, req->max_output_response,
                                 req->flags);
        }
        if (pipe_send_message(p, SMB2_IOCTL,
                              smb2_get_last_request_message_id(smb2),
                              req->max_output_response, req->flags)) {
                return -1;
        }
        return 1;
}

int
dcerpcd_pipe_read(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                  struct smb2_read_request *req,
                  struct smb2_read_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        struct dcerpcd_pipe *p;

        memset(rep, 0, sizeof(*rep));
        p = pipe_find(conn, req->file_id);
        if (p == NULL) {
                fprintf(stderr, "pipe: READ session=%u on unknown file_id\n",
                        conn ? conn->session_id : 0);
                return -1;
        }
        if (!pipe_has_output(p)) {
                if (p->kind == DCERPCD_SVC_EXTERNAL && !p->broken) {
                        return pipe_wait(p, SMB2_READ, req->length, 0);
                }
                pipe_send_error(smb2, SMB2_READ,
                                smb2_get_last_request_message_id(smb2),
                                p->broken ? SMB2_STATUS_PIPE_BROKEN :
                                SMB2_STATUS_PIPE_EMPTY);
                return 1;
        }
        if (pipe_send_message(p, SMB2_READ,
                              smb2_get_last_request_message_id(smb2),
                              req->length, 0)) {
                return -1;
        }
        return 1;
}

int
dcerpcd_pipe_write(struct smb2_server *srvr _U_, struct smb2_context *smb2,
                   struct smb2_write_request *req,
                   struct smb2_write_reply *rep)
{
        struct dcerpcd_conn *conn = dcerpcd_auth_conn(smb2);
        struct dcerpcd_pipe *p;

        memset(rep, 0, sizeof(*rep));
        p = pipe_find(conn, req->file_id);
        if (p == NULL) {
                fprintf(stderr, "pipe: WRITE session=%u on unknown file_id\n",
                        conn ? conn->session_id : 0);
                return -1;
        }
        if (p->broken) {
                pipe_send_error(smb2, SMB2_WRITE,
                                smb2_get_last_request_message_id(smb2),
                                SMB2_STATUS_PIPE_BROKEN);
                return 1;
        }
        if (pipe_input(p, req->buf, req->length)) {
                return -1;
        }
        rep->count = req->length;
        return 0;
}
