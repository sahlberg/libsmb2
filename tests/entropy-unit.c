/* Context setup and accepted socket ownership. LGPL-2.1-or-later. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"

static int ready;
static int draws;

static int test_random(void *buf, size_t len)
{
        if (!ready) {
                return EAGAIN;
        }
        memset(buf, ++draws, len);
        return 0;
}

static int connect_to_listener(const struct sockaddr_in *addr)
{
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        assert(fd >= 0);
        assert(connect(fd, (const struct sockaddr *)addr, sizeof(*addr)) == 0);
        return fd;
}

int main(void)
{
        struct smb2_context *smb2 = NULL;
        struct sockaddr_in addr;
        struct pollfd pfd;
        socklen_t len = sizeof(addr);
        int listener, client;
        ssize_t count;
        char byte;

        smb2_set_random_provider(test_random);
        assert(smb2_init_context() == NULL && errno == EAGAIN);
        assert(smb2_bind_and_listen(0, 2, &listener) == 0);
        assert(getsockname(listener, (struct sockaddr *)&addr, &len) == 0);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        client = connect_to_listener(&addr);
        assert(smb2_serve_port_async(listener, 1000, &smb2) == -EAGAIN);
        assert(smb2 == NULL);
        pfd.fd = client;
        pfd.events = POLLIN;
        assert(poll(&pfd, 1, 1000) == 1);
        count = recv(client, &byte, 1, 0);
        assert(count == 0 || (count < 0 && errno == ECONNRESET));
        close(client);

        ready = 1;
        client = connect_to_listener(&addr);
        assert(smb2_serve_port_async(listener, 1000, &smb2) == 0);
        assert(smb2 != NULL && draws > 0);
        smb2_destroy_context(smb2);
        close(client);
        close(listener);
        smb2_set_random_provider(NULL);
        return 0;
}
