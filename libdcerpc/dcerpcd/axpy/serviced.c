/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Generic external DCE/RPC service worker for dcerpcd.
 *
 * Built once per interface with -DSERVICE=<name> (unquoted identifier),
 * e.g. -DSERVICE=srvsvc.  SERVICE is token-pasted onto IDL-generated
 * symbols (<name>_procs, <name>_stubs, <name>_find_proc, <name>_server.h)
 * and registration macros.  The wire pipe name comes from <name>_PIPE_NAME
 * in the generated header (from the IDL endpoint attribute).
 *
 * Connects to dcerpcd's control Unix domain socket, registers the service,
 * then loops reading RPC proxy messages (dcerpcd_proto.h).  Each request is
 * looked up in the IDL-generated procedure table and decoded with the
 * matching req coder.  When the worker runs as root, stubs run under the
 * caller's euid (seteuid around the call; guest leaves credentials unchanged).
 * Non-root workers skip switching and run stubs as themselves.
 */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef SERVICE
#error "SERVICE must be defined as an identifier (e.g. -DSERVICE=srvsvc)"
#endif

/* Token paste / stringify (double expansion so SERVICE is expanded first). */
#define SERVICE_PASTE2(a, b) a##b
#define SERVICE_PASTE(a, b)  SERVICE_PASTE2(a, b)
#define SERVICE_STR2(x)      #x
#define SERVICE_STR(x)       SERVICE_STR2(x)

#define SERVICE_SERVER_H     SERVICE_STR(SERVICE_PASTE(SERVICE, _server.h))
#define SERVICE_FIND_PROC    SERVICE_PASTE(SERVICE, _find_proc)
#define SERVICE_STUBS        SERVICE_PASTE(SERVICE, _stubs)
/* Registration strings come from the IDL-generated <service>_server.h */
#define SERVICE_UUID_STR     SERVICE_PASTE(SERVICE, _UUID_STR)
#define SERVICE_VERSION_STR  SERVICE_PASTE(SERVICE, _VERSION_STR)
#define SERVICE_ANNOTATION   SERVICE_PASTE(SERVICE, _ANNOTATION)
#define SERVICE_PIPE_NAME    SERVICE_PASTE(SERVICE, _PIPE_NAME)
/* Log / display name: wire pipe base when available (e.g. "srvsvc"). */
#define SERVICE_NAME         SERVICE_PIPE_NAME

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * We only need an smb2_context for dcerpc_create_context(); avoid pulling
 * the full libsmb2 headers into the generic worker.
 */
struct smb2_context;
struct smb2_context *smb2_init_context(void);
void smb2_destroy_context(struct smb2_context *smb2);

#include "dcerpcd_proto.h"
#include SERVICE_SERVER_H

/*
 * Look up an entry in a null-terminated dcerpc_stub table by wire opnum.
 * stubs is typically an IDL-generated table (e.g. srvsvc_stubs).
 */
const struct dcerpc_stub *
dcerpc_find_stub(const struct dcerpc_stub *stubs, int opnum)
{
        const struct dcerpc_stub *s;

        if (stubs == NULL) {
                return NULL;
        }
        for (s = stubs; s->name != NULL; s++) {
                if (s->opnum == opnum) {
                        return s;
                }
        }
        return NULL;
}

/* Must match DCERPCD_DEFAULT_SVC_SOCK in dcerpcd.h */
#define DCERPCD_DEFAULT_SVC_SOCK "/var/run/dcerpcd/dcerpcd.sock"

/*
 * Drop effective uid to the request caller for the duration of a stub.
 *
 * Only meaningful when the worker runs as root (euid 0): seteuid() to a
 * normal user and back requires root.  If we are not root, both enter and
 * leave are no-ops and the stub runs as the worker's own euid.
 *
 * Guest (DCERPCD_RPC_UID_GUEST / -1) leaves euid unchanged.  *saved_euid is
 * always set for leave_request_uid().
 */
static int
enter_request_uid(int32_t uid, uid_t *saved_euid)
{
        *saved_euid = geteuid();

        /* Non-root workers cannot switch credentials and return. */
        if (*saved_euid != 0) {
                return 0;
        }
        if (uid == DCERPCD_RPC_UID_GUEST) {
                return 0;
        }
        if (uid < 0) {
                errno = EINVAL;
                return -1;
        }
        if ((uid_t)uid == 0) {
                return 0;
        }
        if (seteuid((uid_t)uid) != 0) {
                return -1;
        }
        return 0;
}

static int
leave_request_uid(uid_t saved_euid)
{
        if (geteuid() == saved_euid) {
                return 0;
        }
        /* Only entered a drop when we were root; restore must succeed. */
        if (seteuid(saved_euid) != 0) {
                return -1;
        }
        return 0;
}

static volatile sig_atomic_t stop_flag;

static void
on_signal(int sig)
{
        (void)sig;
        stop_flag = 1;
}

static int
write_all(int fd, const void *buf, size_t len)
{
        const uint8_t *p = buf;

        while (len) {
                ssize_t n = write(fd, p, len);

                if (n < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        return -1;
                }
                if (n == 0) {
                        return -1;
                }
                p += (size_t)n;
                len -= (size_t)n;
        }
        return 0;
}

static int
read_all(int fd, void *buf, size_t len)
{
        uint8_t *p = buf;

        while (len) {
                ssize_t n = read(fd, p, len);

                if (n < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        return -1;
                }
                if (n == 0) {
                        return -1; /* EOF */
                }
                p += (size_t)n;
                len -= (size_t)n;
        }
        return 0;
}

static int
send_registration(int fd)
{
        /*
         * YAML registration for the control protocol documented in
         * external.c. Length prefix is little-endian uint32.
         */
        static const char yaml[] =
                "Service:\n"
                "  name: " SERVICE_NAME "\n"
                "  uuid: " SERVICE_UUID_STR "\n"
                "  version: " SERVICE_VERSION_STR "\n"
                "  annotation: " SERVICE_ANNOTATION "\n"
                "  endpoints:\n"
                "    - transport: ncacn_np\n"
                "      endpoint: \\pipe\\" SERVICE_NAME "\n";
        uint32_t body_len = (uint32_t)(sizeof(yaml) - 1);
        uint8_t hdr[4];

        hdr[0] = (uint8_t)(body_len & 0xff);
        hdr[1] = (uint8_t)((body_len >> 8) & 0xff);
        hdr[2] = (uint8_t)((body_len >> 16) & 0xff);
        hdr[3] = (uint8_t)((body_len >> 24) & 0xff);

        if (write_all(fd, hdr, 4) != 0 ||
            write_all(fd, yaml, body_len) != 0) {
                fprintf(stderr, SERVICE_NAME ": write registration: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

static int
read_reply(int fd)
{
        char buf[512];
        size_t total = 0;

        for (;;) {
                ssize_t n = read(fd, buf + total, sizeof(buf) - 1 - total);

                if (n < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        fprintf(stderr, SERVICE_NAME ": read reply: %s\n",
                                strerror(errno));
                        return -1;
                }
                if (n == 0) {
                        break;
                }
                total += (size_t)n;
                buf[total] = '\0';
                if (memchr(buf, '\n', total) != NULL) {
                        break;
                }
                if (total >= sizeof(buf) - 1) {
                        break;
                }
        }
        if (total == 0) {
                fprintf(stderr, SERVICE_NAME ": empty reply from dcerpcd\n");
                return -1;
        }
        fputs(buf, stdout);
        if (strncmp(buf, "OK", 2) != 0) {
                return -1;
        }
        return 0;
}

/*
 * Encode a reply structure to an NDR stub. *out_buf is malloc'd; the caller
 * frees it. request is optional (some coders use size_is from the request).
 */
static int
encode_response(struct smb2_context *smb2,
                void *request,
                void *reply,
                dcerpc_coder coder,
                uint8_t **out_buf,
                size_t *out_len)
{
        struct dcerpc_context *dce;
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov = {0};
        int rc = -1;

        *out_buf = NULL;
        *out_len = 0;

        dce = dcerpc_create_context(smb2);
        if (dce == NULL) {
                return -1;
        }
        /* Little-endian NDR32 */
        pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE | ENCODING_NDR, 16);
        if (pdu == NULL) {
                dcerpc_destroy_context(dce);
                return -1;
        }
        if (request) {
                dcerpc_set_request(pdu, request);
        }
        /* A growable iovec: the buffer is malloc'd and grows as needed */
        if (dcerpc_do_coder("Response", dce, pdu, &iov, reply, coder)) {
                fprintf(stderr, SERVICE_NAME ": NDR encode failed: %s\n",
                        dcerpc_get_error(dce));
                dcerpc_free_iovec(&iov);
                goto out;
        }
        *out_buf = iov.buf;
        *out_len = iov.offset;
        rc = 0;
out:
        dcerpc_free_pdu(dce, pdu);
        dcerpc_destroy_context(dce);
        return rc;
}

static int
send_proxy_response(int fd, uint32_t session_id, uint32_t msgid, uint32_t opnum,
                    int32_t status, const uint8_t *ndr, uint32_t ndr_len)
{
        struct dcerpcd_rpc_hdr hdr;
        uint8_t lenbuf[4];
        uint8_t pad[3];
        unsigned npad;

        memset(&hdr, 0, sizeof(hdr));
        hdr.magic[0] = DCERPCD_RPC_MAGIC0;
        hdr.magic[1] = DCERPCD_RPC_MAGIC1;
        hdr.magic[2] = DCERPCD_RPC_MAGIC2;
        hdr.magic[3] = DCERPCD_RPC_MAGIC3;
        hdr.uid_or_status = status;
        hdr.session_id = session_id;
        hdr.msgid = msgid;
        hdr.opnum = opnum;

        if (status != DCERPCD_RPC_STATUS_OK) {
                ndr_len = 0;
                ndr = NULL;
        }

        lenbuf[0] = (uint8_t)(ndr_len & 0xff);
        lenbuf[1] = (uint8_t)((ndr_len >> 8) & 0xff);
        lenbuf[2] = (uint8_t)((ndr_len >> 16) & 0xff);
        lenbuf[3] = (uint8_t)((ndr_len >> 24) & 0xff);
        npad = dcerpcd_rpc_ndr_pad(ndr_len);
        memset(pad, 0, sizeof(pad));

        if (write_all(fd, &hdr, sizeof(hdr)) != 0 ||
            write_all(fd, lenbuf, 4) != 0) {
                fprintf(stderr, SERVICE_NAME ": write response header: %s\n",
                        strerror(errno));
                return -1;
        }
        if (ndr_len && write_all(fd, ndr, ndr_len) != 0) {
                fprintf(stderr, SERVICE_NAME ": write response ndr: %s\n",
                        strerror(errno));
                return -1;
        }
        if (npad && write_all(fd, pad, npad) != 0) {
                fprintf(stderr, SERVICE_NAME ": write response pad: %s\n",
                        strerror(errno));
                return -1;
        }
        printf(SERVICE_NAME ": sent %s response session=%u msgid=%u opnum=%u "
               "ndr_len=%u\n",
               status == DCERPCD_RPC_STATUS_OK ? "OK" : "FAIL",
               session_id, msgid, opnum, ndr_len);
        return 0;
}

static int
send_fail_response(int fd, uint32_t session_id, uint32_t msgid, uint32_t opnum)
{
        return send_proxy_response(fd, session_id, msgid, opnum,
                                   DCERPCD_RPC_STATUS_FAIL, NULL, 0);
}

/*
 * Decode NDR request stub with the procedure's req_coder into a heap
 * buffer of req_size bytes. Pointer targets live until free_pdu.
 */
static int
decode_request(struct smb2_context *smb2,
               const uint8_t *ndr, uint32_t ndr_len,
               const struct dcerpc_procedure *proc,
               void **req_out,
               struct dcerpc_context **dce_out,
               struct dcerpc_pdu **pdu_out)
{
        struct dcerpc_context *dce;
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov;
        void *req;

        *req_out = NULL;
        *dce_out = NULL;
        *pdu_out = NULL;

        if (proc == NULL || proc->req_coder == NULL || proc->req_size <= 0) {
                return -1;
        }

        req = calloc(1, (size_t)proc->req_size);
        if (req == NULL) {
                return -1;
        }

        dce = dcerpc_create_context(smb2);
        if (dce == NULL) {
                free(req);
                return -1;
        }
        /* Little-endian NDR32 */
        pdu = dcerpc_allocate_pdu(dce, DCERPC_DECODE | ENCODING_NDR,
                                  proc->req_size);
        if (pdu == NULL) {
                dcerpc_destroy_context(dce);
                free(req);
                return -1;
        }
        iov = (struct dcerpc_iovec){
                .buf = (uint8_t *)(uintptr_t)ndr,
                .max_offset = ndr_len,
        };
        if (dcerpc_do_coder("Request", dce, pdu, &iov, req,
                            proc->req_coder)) {
                const char *err = dcerpc_get_error(dce);

                fprintf(stderr,
                        SERVICE_NAME ": NDR decode failed for %s "
                        "(ndr_len=%u offset=%zu): %s\n",
                        proc->name ? proc->name : "?",
                        ndr_len, iov.offset,
                        (err && err[0]) ? err : "(no error string)");
                dcerpc_free_pdu(dce, pdu);
                dcerpc_destroy_context(dce);
                free(req);
                return -1;
        }

        *req_out = req;
        *dce_out = dce;
        *pdu_out = pdu;
        return 0;
}

static void
decode_done(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
            void *req, void *rep)
{
        if (pdu) {
                dcerpc_free_pdu(dce, pdu);
        }
        if (dce) {
                dcerpc_destroy_context(dce);
        }
        free(req);
        free(rep);
}

/*
 * Read one framed RPC proxy message, look up the opnum in SERVICE_procs,
 * decode the NDR request, allocate a response, and invoke the matching
 * implementation stub from SERVICE_stubs[].
 * Returns 0 on success, -1 on EOF/error.
 */
static int
handle_one_request(int fd, struct smb2_context *smb2)
{
        struct dcerpcd_rpc_hdr hdr;
        uint8_t lenbuf[4];
        uint32_t ndr_len;
        unsigned npad;
        uint8_t *ndr = NULL;
        uint8_t pad[3];
        const struct dcerpc_procedure *proc;
        const struct dcerpc_stub *stub;
        void *req = NULL;
        void *rep = NULL;
        struct dcerpc_context *dce = NULL;
        struct dcerpc_pdu *pdu = NULL;
        int stub_rc;

        if (read_all(fd, &hdr, sizeof(hdr)) != 0) {
                return -1;
        }
        if (!dcerpcd_rpc_hdr_ok(&hdr)) {
                fprintf(stderr,
                        SERVICE_NAME ": bad RPC magic "
                        "(got %02x %02x %02x %02x)\n",
                        (unsigned)(uint8_t)hdr.magic[0],
                        (unsigned)(uint8_t)hdr.magic[1],
                        (unsigned)(uint8_t)hdr.magic[2],
                        (unsigned)(uint8_t)hdr.magic[3]);
                return -1;
        }

        if (read_all(fd, lenbuf, 4) != 0) {
                return -1;
        }
        ndr_len = (uint32_t)lenbuf[0] |
                  ((uint32_t)lenbuf[1] << 8) |
                  ((uint32_t)lenbuf[2] << 16) |
                  ((uint32_t)lenbuf[3] << 24);

        if (ndr_len > 16 * 1024 * 1024) {
                fprintf(stderr, SERVICE_NAME ": ndr_len %u too large\n",
                        ndr_len);
                return -1;
        }

        if (ndr_len) {
                ndr = malloc(ndr_len);
                if (ndr == NULL) {
                        fprintf(stderr, SERVICE_NAME ": out of memory\n");
                        return -1;
                }
                if (read_all(fd, ndr, ndr_len) != 0) {
                        free(ndr);
                        return -1;
                }
        }

        npad = dcerpcd_rpc_ndr_pad(ndr_len);
        if (npad && read_all(fd, pad, npad) != 0) {
                free(ndr);
                return -1;
        }

        printf(SERVICE_NAME ": request session=%u uid=%d msgid=%u opnum=%u "
               "(0x%x) ndr_len=%u\n",
               hdr.session_id,
               (int)hdr.uid_or_status,
               hdr.msgid,
               hdr.opnum, hdr.opnum,
               ndr_len);

        proc = SERVICE_FIND_PROC((int)hdr.opnum);
        if (proc == NULL) {
                fprintf(stderr, SERVICE_NAME ": unknown opnum %u\n",
                        hdr.opnum);
                free(ndr);
                if (send_fail_response(fd, hdr.session_id, hdr.msgid,
                                       hdr.opnum) != 0) {
                        return -1;
                }
                return 0; /* keep serving */
        }
        printf(SERVICE_NAME ": procedure %s (opnum 0x%x)\n",
               proc->name ? proc->name : "?", proc->opnum);

        if (decode_request(smb2, ndr, ndr_len, proc, &req, &dce, &pdu) != 0) {
                free(ndr);
                if (send_fail_response(fd, hdr.session_id, hdr.msgid,
                                       hdr.opnum) != 0) {
                        return -1;
                }
                return 0; /* keep serving */
        }
        free(ndr);
        ndr = NULL;

        stub = dcerpc_find_stub(SERVICE_STUBS, (int)hdr.opnum);
        if (stub == NULL || stub->fn == NULL) {
                fprintf(stderr,
                        SERVICE_NAME ": no implementation stub for opnum %u\n",
                        hdr.opnum);
                decode_done(dce, pdu, req, NULL);
                if (send_fail_response(fd, hdr.session_id, hdr.msgid,
                                       hdr.opnum) != 0) {
                        return -1;
                }
                return 0;
        }

        rep = calloc(1, (size_t)proc->rep_size);
        if (rep == NULL) {
                fprintf(stderr, SERVICE_NAME ": out of memory for response\n");
                decode_done(dce, pdu, req, NULL);
                if (send_fail_response(fd, hdr.session_id, hdr.msgid,
                                       hdr.opnum) != 0) {
                        return -1;
                }
                return 0;
        }

        /*
         * Run the stub as the SMB caller.  Decode/encode stay at the
         * worker's original euid; only the implementation drops.
         */
        {
                uid_t saved_euid;

                if (enter_request_uid(hdr.uid_or_status, &saved_euid) != 0) {
                        fprintf(stderr,
                                SERVICE_NAME ": seteuid(%d) failed: %s\n",
                                (int)hdr.uid_or_status, strerror(errno));
                        free(rep);
                        decode_done(dce, pdu, req, NULL);
                        if (send_fail_response(fd, hdr.session_id, hdr.msgid,
                                               hdr.opnum) != 0) {
                                return -1;
                        }
                        return 0;
                }

                stub_rc = stub->fn(dce, pdu, req, rep);

                if (leave_request_uid(saved_euid) != 0) {
                        fprintf(stderr,
                                SERVICE_NAME ": CRITICAL: failed to restore "
                                "euid %u after stub: %s\n",
                                (unsigned)saved_euid, strerror(errno));
                        free(rep);
                        decode_done(dce, pdu, req, NULL);
                        (void)send_fail_response(fd, hdr.session_id, hdr.msgid,
                                                 hdr.opnum);
                        return -1;
                }
        }

        if (stub_rc != 0) {
                printf(SERVICE_NAME ": stub %s failed (rc=%d)\n",
                       stub->name ? stub->name : "?", stub_rc);
                if (send_fail_response(fd, hdr.session_id, hdr.msgid,
                                       hdr.opnum) != 0) {
                        decode_done(dce, pdu, req, rep);
                        return -1;
                }
                decode_done(dce, pdu, req, rep);
                return 0;
        }

        printf(SERVICE_NAME ": stub %s succeeded; encoding NDR response\n",
               stub->name ? stub->name : "?");

        /*
         * Encode while nested allocations (from the stub) still live on
         * the decode pdu. Use a separate ENCODE context for the blob.
         */
        {
                uint8_t *rep_ndr = NULL;
                size_t rep_ndr_len = 0;

                if (encode_response(smb2, req, rep, proc->rep_coder,
                                    &rep_ndr, &rep_ndr_len) != 0) {
                        fprintf(stderr, SERVICE_NAME ": encode failed for %s\n",
                                stub->name ? stub->name : "?");
                        if (send_fail_response(fd, hdr.session_id, hdr.msgid,
                                               hdr.opnum) != 0) {
                                decode_done(dce, pdu, req, rep);
                                return -1;
                        }
                        decode_done(dce, pdu, req, rep);
                        return 0;
                }
                if (send_proxy_response(fd, hdr.session_id, hdr.msgid,
                                        hdr.opnum, DCERPCD_RPC_STATUS_OK,
                                        rep_ndr, (uint32_t)rep_ndr_len) != 0) {
                        free(rep_ndr);
                        decode_done(dce, pdu, req, rep);
                        return -1;
                }
                free(rep_ndr);
        }

        decode_done(dce, pdu, req, rep);
        return 0;
}

static void
usage(const char *prog)
{
        fprintf(stderr,
                "Usage: %s [socket-path]\n"
                "\n"
                "Register " SERVICE_NAME " with dcerpcd over the control "
                "Unix socket\n"
                "(default: %s), then process forwarded RPC requests until\n"
                "SIGINT/SIGTERM or disconnect.\n",
                prog, DCERPCD_DEFAULT_SVC_SOCK);
        exit(1);
}

int
main(int argc, char *argv[])
{
        const char *sock_path = DCERPCD_DEFAULT_SVC_SOCK;
        struct sockaddr_un addr;
        struct smb2_context *smb2 = NULL;
        int fd = -1;
        int rc = 1;

        if (argc > 1) {
                if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
                        usage(argv[0]);
                }
                sock_path = argv[1];
        }
        if (argc > 2) {
                usage(argv[0]);
        }

        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);

        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);
        signal(SIGPIPE, SIG_IGN);

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, SERVICE_NAME ": smb2_init_context failed\n");
                return 1;
        }

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
                fprintf(stderr, SERVICE_NAME ": socket: %s\n",
                        strerror(errno));
                goto out;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        if (strlen(sock_path) >= sizeof(addr.sun_path)) {
                fprintf(stderr, SERVICE_NAME ": socket path too long\n");
                goto out;
        }
        strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                fprintf(stderr, SERVICE_NAME ": connect %s: %s\n", sock_path,
                        strerror(errno));
                goto out;
        }

        if (send_registration(fd) != 0) {
                goto out;
        }
        if (read_reply(fd) != 0) {
                fprintf(stderr, SERVICE_NAME ": registration rejected\n");
                goto out;
        }

        printf(SERVICE_NAME ": registered with dcerpcd on %s; "
               "waiting for requests\n",
               sock_path);

        while (!stop_flag) {
                if (handle_one_request(fd, smb2) != 0) {
                        if (!stop_flag) {
                                fprintf(stderr,
                                        SERVICE_NAME ": control connection "
                                        "closed or read error\n");
                        }
                        break;
                }
        }
        printf(SERVICE_NAME ": shutting down\n");
        rc = 0;

out:
        if (fd >= 0) {
                close(fd);
        }
        if (smb2) {
                smb2_destroy_context(smb2);
        }
        return rc;
}
