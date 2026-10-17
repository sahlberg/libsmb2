/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Generic external DCE/RPC service for dcerpcd.
 *
 * Connects to dcerpcd's control Unix domain socket and registers a named
 * pipe; dcerpcd then forwards the pipe's traffic (dcerpcd_proto.h) and
 * the DCE/RPC is all here: libdcerpc's server runtime (<dcerpc/server.h>)
 * does BIND, fragments and NDR32/NDR64 in either byte order, and calls
 * the IDL-generated stubs. Each client open of the pipe is its own
 * dcerpc_server_pipe.
 *
 * Built once per service with -DSERVICE=<name> (an identifier):
 *   - alone, the pipe serves the one interface <name>, on the pipe its
 *     IDL names (<name>_PIPE_NAME, e.g. -DSERVICE=axpy);
 *   - with -DSERVICE_INTERFACES='X(lsa) X(dssetup)', the pipe <name>
 *     (or -DSERVICE_PIPE_NAME='"..."') serves all of those interfaces.
 * Each X(i) links i_interface and i_procs from the coder and i_stubs from
 * the stubs .c.
 *
 * With -DSERVICE_INIT=<fn>, int fn(const char *config) is called before
 * registering, with the -c argument or NULL; if it fails the service does
 * not start.
 *
 * When the service runs as root, a client's DCE/RPC runs under its euid
 * (seteuid around each write; guest leaves credentials unchanged).
 * Non-root services skip switching and run stubs as themselves.
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

#include <dcerpc/dcerpc.h>
#include <dcerpc/server.h>

#include "dcerpcd_proto.h"

#ifdef SERVICE_INTERFACES
#ifndef SERVICE_PIPE_NAME
#define SERVICE_PIPE_NAME    SERVICE_STR(SERVICE)
#endif
#ifndef SERVICE_ANNOTATION
#define SERVICE_ANNOTATION   SERVICE_PIPE_NAME
#endif
#else
/* One interface, named SERVICE, on the pipe its IDL names */
#define SERVICE_SERVER_H     SERVICE_STR(SERVICE_PASTE(SERVICE, _server.h))
#include SERVICE_SERVER_H
#define SERVICE_INTERFACES   X(SERVICE)
#ifndef SERVICE_PIPE_NAME
#define SERVICE_PIPE_NAME    SERVICE_PASTE(SERVICE, _PIPE_NAME)
#endif
#ifndef SERVICE_ANNOTATION
#define SERVICE_ANNOTATION   SERVICE_PASTE(SERVICE, _ANNOTATION)
#endif
#endif

/* Log name */
#define SERVICE_NAME         SERVICE_PIPE_NAME

/* What idlcomp generates for each interface: coders and the stub table */
#define X(i)                                                            \
        extern p_syntax_id_t SERVICE_PASTE(i, _interface);              \
        extern struct dcerpc_procedure SERVICE_PASTE(i, _procs)[];      \
        extern struct dcerpc_stub SERVICE_PASTE(i, _stubs)[];
SERVICE_INTERFACES
#undef X

struct service_interface {
        const char *name;
        const p_syntax_id_t *iface;
        const struct dcerpc_procedure *procs;
        const struct dcerpc_stub *stubs;
};

static const struct service_interface service_interfaces[] = {
#define X(i) { SERVICE_STR(i), &SERVICE_PASTE(i, _interface),           \
               SERVICE_PASTE(i, _procs), SERVICE_PASTE(i, _stubs) },
        SERVICE_INTERFACES
#undef X
        { NULL, NULL, NULL, NULL }
};

#ifdef SERVICE_INIT
int SERVICE_INIT(const char *config);
#endif

/* Must match DCERPCD_DEFAULT_SVC_SOCK in dcerpcd.h */
#define DCERPCD_DEFAULT_SVC_SOCK "/var/run/dcerpcd/dcerpcd.sock"

/* A client's open of the pipe */
struct service_pipe {
        struct service_pipe *next;
        uint32_t id;
        uint32_t session_id;
        int32_t uid;
        struct dcerpc_server_pipe *rpc;
};

static struct dcerpc_server *srv;
static struct service_pipe *pipes;

/*
 * Run the DCE/RPC of a client's write as the client.
 *
 * Only meaningful when the service runs as root (euid 0): seteuid() to a
 * normal user and back requires root.  If we are not root, both enter and
 * leave are no-ops and the stubs run as the service's own euid.
 *
 * Guest (DCERPCD_UID_GUEST / -1) leaves euid unchanged.  *saved_euid is
 * always set for leave_request_uid().
 */
static int
enter_request_uid(int32_t uid, uid_t *saved_euid)
{
        *saved_euid = geteuid();

        /* Non-root services cannot switch credentials and return. */
        if (*saved_euid != 0) {
                return 0;
        }
        if (uid == DCERPCD_UID_GUEST) {
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
                        if (errno == EINTR && !stop_flag) {
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

/*
 * YAML registration for the control protocol documented in external.c:
 * the pipe, and the interfaces on it for dcerpcd's endpoint mapper.
 * Length prefix is little-endian uint32.
 */
static int
send_registration(int fd)
{
        char yaml[4096];
        const struct service_interface *si;
        size_t len;
        uint8_t hdr[4];

        len = (size_t)snprintf(yaml, sizeof(yaml),
                               "Service:\n"
                               "  pipe: %s\n"
                               "  annotation: %s\n"
                               "  interfaces:\n",
                               SERVICE_PIPE_NAME, SERVICE_ANNOTATION);
        for (si = service_interfaces; si->name && len < sizeof(yaml);
             si++) {
                const dcerpc_uuid_t *u = &si->iface->uuid;

                len += (size_t)snprintf(yaml + len, sizeof(yaml) - len,
                        "    - uuid: %08x-%04x-%04x-%02x%02x-"
                        "%02x%02x%02x%02x%02x%02x\n"
                        "      version: %u.%u\n",
                        u->v1, u->v2, u->v3, u->v4[0], u->v4[1],
                        u->v4[2], u->v4[3], u->v4[4], u->v4[5],
                        u->v4[6], u->v4[7],
                        si->iface->vers, si->iface->vers_minor);
        }
        if (len >= sizeof(yaml)) {
                fprintf(stderr, SERVICE_NAME ": registration too large\n");
                return -1;
        }

        dcerpcd_put_le32(hdr, (uint32_t)len);
        if (write_all(fd, hdr, 4) != 0 ||
            write_all(fd, yaml, len) != 0) {
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

        /*
         * Byte by byte: pipe messages follow the reply on the same
         * socket and must stay unread.
         */
        while (total < sizeof(buf) - 1) {
                ssize_t n = read(fd, buf + total, 1);

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
                if (buf[total++] == '\n') {
                        break;
                }
        }
        buf[total] = '\0';
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

static int
send_msg(int fd, uint32_t type, uint32_t pipe_id, const uint8_t *data,
         uint32_t len)
{
        uint8_t hdr[DCERPCD_MSG_HDR_SIZE];

        dcerpcd_msg_hdr_encode(hdr, type, pipe_id, len);
        if (write_all(fd, hdr, sizeof(hdr)) != 0 ||
            (len && write_all(fd, data, len) != 0)) {
                fprintf(stderr, SERVICE_NAME ": write to dcerpcd: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

static struct service_pipe **
pipe_find(uint32_t id)
{
        struct service_pipe **pp;

        for (pp = &pipes; *pp; pp = &(*pp)->next) {
                if ((*pp)->id == id) {
                        return pp;
                }
        }
        return NULL;
}

static void
pipe_destroy(struct service_pipe **pp)
{
        struct service_pipe *p = *pp;

        *pp = p->next;
        dcerpc_server_pipe_destroy(p->rpc);
        free(p);
}

/* A client opened the pipe: a DCE/RPC pipe of our endpoint for it */
static int
pipe_open(int fd, uint32_t id, const uint8_t *data, uint32_t len)
{
        struct service_pipe *p;

        if (len < DCERPCD_OPEN_SIZE || pipe_find(id)) {
                fprintf(stderr, SERVICE_NAME ": bad OPEN of pipe %u\n", id);
                return -1;
        }
        p = calloc(1, sizeof(*p));
        if (p == NULL) {
                return send_msg(fd, DCERPCD_MSG_CLOSE, id, NULL, 0);
        }
        p->id = id;
        p->session_id = dcerpcd_get_le32(data);
        p->uid = (int32_t)dcerpcd_get_le32(data + 4);
        p->rpc = dcerpc_server_pipe_create(srv, p);
        if (p->rpc == NULL) {
                free(p);
                return send_msg(fd, DCERPCD_MSG_CLOSE, id, NULL, 0);
        }
        p->next = pipes;
        pipes = p;
        printf(SERVICE_NAME ": open pipe=%u session=%u uid=%d user=%.*s\n",
               id, p->session_id, (int)p->uid,
               (int)(len - DCERPCD_OPEN_SIZE),
               (const char *)data + DCERPCD_OPEN_SIZE);
        return 0;
}

/* Send dcerpcd each DCE/RPC fragment the pipe has for the client */
static int
pipe_send_output(int fd, struct service_pipe *p)
{
        uint8_t *buf = NULL;
        size_t cap = 0;
        int rc = 0;

        while (rc == 0 && dcerpc_server_pipe_has_output(p->rpc)) {
                size_t len = 0;
                int more;

                do {
                        if (cap - len < 0x10000) {
                                uint8_t *nb = realloc(buf, cap + 0x10000);

                                if (nb == NULL) {
                                        free(buf);
                                        return -1;
                                }
                                buf = nb;
                                cap += 0x10000;
                        }
                        len += dcerpc_server_pipe_read(p->rpc, buf + len,
                                                       cap - len, &more);
                } while (more);
                rc = send_msg(fd, DCERPCD_MSG_OUTPUT, p->id, buf,
                              (uint32_t)len);
        }
        free(buf);
        return rc;
}

/*
 * The client wrote to the pipe: run the DCE/RPC, whose stubs are called
 * before dcerpc_server_pipe_write() returns, as the client.
 */
static int
pipe_write(int fd, uint32_t id, const uint8_t *data, uint32_t len)
{
        struct service_pipe **pp = pipe_find(id);
        uid_t saved_euid;
        int rc;

        if (pp == NULL) {
                return 0; /* we closed it meanwhile */
        }
        if (enter_request_uid((*pp)->uid, &saved_euid) != 0) {
                fprintf(stderr, SERVICE_NAME ": seteuid(%d) failed: %s\n",
                        (int)(*pp)->uid, strerror(errno));
                pipe_destroy(pp);
                return send_msg(fd, DCERPCD_MSG_CLOSE, id, NULL, 0);
        }
        rc = dcerpc_server_pipe_write((*pp)->rpc, data, len);
        if (leave_request_uid(saved_euid) != 0) {
                fprintf(stderr, SERVICE_NAME ": CRITICAL: failed to restore "
                        "euid %u: %s\n", (unsigned)saved_euid,
                        strerror(errno));
                return -1;
        }
        if (rc) {
                fprintf(stderr, SERVICE_NAME ": pipe=%u: not DCE/RPC\n", id);
                pipe_destroy(pp);
                return send_msg(fd, DCERPCD_MSG_CLOSE, id, NULL, 0);
        }
        return pipe_send_output(fd, *pp);
}

/*
 * Read and handle one message from dcerpcd.
 * Returns 0 on success, -1 on EOF/error.
 */
static int
handle_one_message(int fd)
{
        uint8_t hbuf[DCERPCD_MSG_HDR_SIZE];
        struct dcerpcd_msg_hdr hdr;
        struct service_pipe **pp;
        uint8_t *data = NULL;
        int rc = 0;

        if (read_all(fd, hbuf, sizeof(hbuf)) != 0) {
                return -1;
        }
        if (dcerpcd_msg_hdr_decode(hbuf, &hdr)) {
                fprintf(stderr, SERVICE_NAME ": bad message from dcerpcd\n");
                return -1;
        }
        if (hdr.len) {
                data = malloc(hdr.len);
                if (data == NULL) {
                        fprintf(stderr, SERVICE_NAME ": out of memory\n");
                        return -1;
                }
                if (read_all(fd, data, hdr.len) != 0) {
                        free(data);
                        return -1;
                }
        }

        switch (hdr.type) {
        case DCERPCD_MSG_OPEN:
                rc = pipe_open(fd, hdr.pipe_id, data, hdr.len);
                break;
        case DCERPCD_MSG_WRITE:
                rc = pipe_write(fd, hdr.pipe_id, data, hdr.len);
                break;
        case DCERPCD_MSG_CLOSE:
                pp = pipe_find(hdr.pipe_id);
                if (pp) {
                        printf(SERVICE_NAME ": close pipe=%u\n", hdr.pipe_id);
                        pipe_destroy(pp);
                }
                break;
        default:
                fprintf(stderr, SERVICE_NAME ": unexpected message type %u\n",
                        hdr.type);
                rc = -1;
                break;
        }
        free(data);
        return rc;
}

static void
usage(const char *prog)
{
        fprintf(stderr,
                "Usage: %s [-c config] [socket-path]\n"
                "Register \\pipe\\" SERVICE_PIPE_NAME " with dcerpcd and "
                "serve it.\n"
#ifdef SERVICE_INIT
                "  -c config    the service's config file\n"
#endif
                "socket-path defaults to " DCERPCD_DEFAULT_SVC_SOCK "\n",
                prog);
        exit(1);
}

/* Our endpoint: every interface of the service on the one pipe */
static int
create_endpoint(void)
{
        const struct service_interface *si;

        srv = dcerpc_server_create(SERVICE_PIPE_NAME);
        if (srv == NULL) {
                return -1;
        }
        for (si = service_interfaces; si->name; si++) {
                if (dcerpc_server_add_interface(srv, si->iface, si->procs,
                                                si->stubs,
                                                DCERPC_SERVER_ALL_NDR)) {
                        fprintf(stderr, SERVICE_NAME ": cannot serve %s\n",
                                si->name);
                        return -1;
                }
                printf(SERVICE_NAME ": serving %s v%u.%u\n", si->name,
                       si->iface->vers, si->iface->vers_minor);
        }
        return 0;
}

int
main(int argc, char *argv[])
{
        const char *sock_path = DCERPCD_DEFAULT_SVC_SOCK;
        const char *config = NULL;
        struct sockaddr_un addr;
        int fd = -1;
        int rc = 1;
        int i;

        for (i = 1; i < argc; i++) {
                if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
                        usage(argv[0]);
                }
#ifdef SERVICE_INIT
                if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) {
                        if (i + 1 >= argc) {
                                usage(argv[0]);
                        }
                        config = argv[++i];
                        continue;
                }
#endif
                if (argv[i][0] == '-' || i != argc - 1) {
                        usage(argv[0]);
                }
                sock_path = argv[i];
        }

#ifdef SERVICE_INIT
        /* the service cannot work without it: do not start */
        if (SERVICE_INIT(config) != 0) {
                fprintf(stderr, SERVICE_NAME ": no config, not starting\n");
                return 1;
        }
#else
        (void)config;
#endif

        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);

        /* no SA_RESTART: a signal must end the wait for dcerpcd */
        {
                struct sigaction sa;

                memset(&sa, 0, sizeof(sa));
                sa.sa_handler = on_signal;
                sigemptyset(&sa.sa_mask);
                sigaction(SIGINT, &sa, NULL);
                sigaction(SIGTERM, &sa, NULL);
        }
        signal(SIGPIPE, SIG_IGN);

        if (create_endpoint() != 0) {
                goto out;
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

        printf(SERVICE_NAME ": registered \\pipe\\" SERVICE_PIPE_NAME
               " with dcerpcd on %s\n", sock_path);

        while (!stop_flag) {
                if (handle_one_message(fd) != 0) {
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
        while (pipes) {
                pipe_destroy(&pipes);
        }
        if (srv) {
                dcerpc_server_destroy(srv);
        }
        if (fd >= 0) {
                close(fd);
        }
        return rc;
}
