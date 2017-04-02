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

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

#define MAX_URL_SIZE 256

#define CIFS_PORT 445

int
smb2_which_events(struct smb2_context *smb2)
{
	int events = smb2->is_connected ? POLLIN : POLLOUT;

        if (smb2->outqueue != NULL) {
                events |= POLLOUT;
        }
        
	return events;
}

int smb2_get_fd(struct smb2_context *smb2)
{
        return smb2->fd;
}

static int
smb2_write_to_socket(struct smb2_context *smb2)
{
        struct smb2_pdu *pdu;
        
	if (smb2->fd == -1) {
		smb2_set_error(smb2, "trying to write but not connected");
		return -1;
	}

	while ((pdu = smb2->outqueue) != NULL) {
                struct iovec iov[SMB2_MAX_VECTORS];
                struct iovec *tmpiov;
                struct smb2_pdu *tmp_pdu;
                size_t num_done = pdu->out.num_done;
                int i, niov = 1;
                ssize_t count;
                uint32_t spl = 0, tmp_spl;

                /* Count/copy all the vectors from all PDUs in the
                 * compound set.
                 */
                for (tmp_pdu = pdu; tmp_pdu; tmp_pdu = tmp_pdu->next_compound) {
                        for (i = 0; i < tmp_pdu->out.niov; i++, niov++) {
                                iov[niov].iov_base = tmp_pdu->out.iov[i].buf;
                                iov[niov].iov_len = tmp_pdu->out.iov[i].len;
                                spl += tmp_pdu->out.iov[i].len;
                        }
                }

                /* Add the SPL vector as the first vector */
                tmp_spl = htobe32(spl);
                iov[0].iov_base = &tmp_spl;
                iov[0].iov_len = SMB2_SPL_SIZE;

                tmpiov = iov;

                /* Skip the vectors we have alredy written */
                while (num_done >= tmpiov->iov_len) {
                        num_done -= tmpiov->iov_len;
                        tmpiov++;
                        niov--;
                }

                /* Adjust the first vector to send */
                tmpiov->iov_base = (char *)tmpiov->iov_base + num_done;
                tmpiov->iov_len -= num_done;

                count = writev(smb2->fd, tmpiov, niov);
                if (count == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                return 0;
                        }
                        smb2_set_error(smb2, "Error when writing to "
                                       "socket :%d %s", errno,
                                       smb2_get_error(smb2));
                        return -1;
                }
                
                pdu->out.num_done += count;

                if (pdu->out.num_done == SMB2_SPL_SIZE + spl) {
                        SMB2_LIST_REMOVE(&smb2->outqueue, pdu);
                        while (pdu) {
                                tmp_pdu = pdu->next_compound;

                                /* As we have now sent all the PDUs we
                                 * can remove the chaining.
                                 * On the receive side we will treat all
                                 * PDUs as individual PDUs.
                                 */
                                pdu->next_compound = NULL;

                                SMB2_LIST_ADD_END(&smb2->waitqueue, pdu);
                                pdu = tmp_pdu;
                        }
                }
	}
	return 0;
}

static int
smb2_read_from_socket(struct smb2_context *smb2)
{
	int available;
	ssize_t count;

        /* initialize the input vectors to the spl and the header
         * which are both static data in the smb2 context.
         * additional vectors will be added when we can map this to
         * the corresponding pdu.
         */
        if (smb2->in.num_done == 0) {
                smb2->in.niov = 2;
                smb2->in.iov[0].buf = smb2->header;
                smb2->in.iov[0].len = SMB2_SPL_SIZE;
                smb2->in.iov[0].free = NULL;
                smb2->in.iov[1].buf = smb2->header + SMB2_SPL_SIZE;
                smb2->in.iov[1].len = SMB2_HEADER_SIZE;
                smb2->in.iov[0].free = NULL;
        }
        
	/* check how much data is in the input buffer of the socket and read
         * as many PDUs as available
         */
	if (ioctl(smb2->fd, FIONREAD, &available) < 0) {
		return -1;
	}

	while (available > 0) {
                struct iovec iov[SMB2_MAX_VECTORS];
                struct iovec *tmpiov;
                int i, niov = smb2->in.niov;
                size_t num_done;

                num_done = smb2->in.num_done;

                for (i = 0; i < niov; i++) {
                        iov[i].iov_base = smb2->in.iov[i].buf;
                        iov[i].iov_len = smb2->in.iov[i].len;
                }
                tmpiov = iov;
                
                /* Skip the vectors we have alredy read */
                while (num_done >= tmpiov->iov_len) {
                        num_done -= tmpiov->iov_len;
                        tmpiov++;
                        niov--;
                }

                /* Adjust the first vector to read */
                tmpiov->iov_base = (char *)tmpiov->iov_base + num_done;
                tmpiov->iov_len -= num_done;

		count = readv(smb2->fd, tmpiov, niov);
		if (count < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				return 0;
			}
			smb2_set_error(smb2, "Read from socket failed, "
                                       "errno:%d. Closing socket.", errno);
			return -1;
		}
		if (count == 0) {
			/* remote side has closed the socket. */
			return -1;
		}
		smb2->in.num_done += count;
		available -= count;

                if (smb2->in.num_done < SMB2_SPL_SIZE + SMB2_HEADER_SIZE) {
                        continue;
                }
                
                /* make sure stream protocol length is in host endianness */
                if (smb2->in.num_done == SMB2_SPL_SIZE + SMB2_HEADER_SIZE) {
                        memcpy(&smb2->in.total_size,
                               smb2->in.iov[0].buf, 4);
                        smb2->in.total_size = be32toh(smb2->in.total_size) + 4;
                }

                if (smb2->in.num_done == SMB2_SPL_SIZE + SMB2_HEADER_SIZE &&
                    smb2->in.total_size > smb2->in.num_done) {
                        struct smb2_pdu *pdu;
                        struct smb2_header hdr;
                        char magic[4] = {0xFE, 'S', 'M', 'B'};
                        size_t tmp_size = smb2->in.num_done;
                        
                        if (smb2_decode_header(smb2, &smb2->in.iov[1],
                                               &hdr) != 0) {
                                smb2_set_error(smb2, "Failed to decode smb2 "
                                               "header");
                                return -1;
                        }
                        if (memcmp(&hdr.protocol_id, magic, 4)) {
                                smb2_set_error(smb2, "received non-SMB2");
                                return -1;
                        }
                        if (!(hdr.flags & SMB2_FLAGS_SERVER_TO_REDIR)) {
                                smb2_set_error(smb2, "received non-reply");
                                return -1;
                        }
                        pdu = smb2_find_pdu(smb2, hdr.message_id);
                        if (pdu == NULL) {
                                smb2_set_error(smb2, "no matching PDU found");
                                return -1;
                        }
                        SMB2_LIST_REMOVE(&smb2->waitqueue, pdu);
                        smb2->pdu = pdu;
                        
                        /* copy any io-vectors we got from the pdu */
                        for (i = 0; i < pdu->in.niov; i++) {
                                struct smb2_iovec *v = &pdu->in.iov[i];

                                smb2->in.iov[smb2->in.niov].buf = v->buf;
                                smb2->in.iov[smb2->in.niov].len = v->len;
                                smb2->in.iov[smb2->in.niov].free = NULL;
                                tmp_size += v->len;
                                if (tmp_size > smb2->in.total_size) {
                                        smb2->in.iov[smb2->in.niov].len -= tmp_size - smb2->in.total_size;
                                        tmp_size -= tmp_size - smb2->in.total_size;
                                        smb2->in.niov++;
                                        break;
                                }
                                
                                smb2->in.niov++;
                        }

                        if (tmp_size == smb2->in.total_size) {
                                continue;
                        }

                        /* We were not given enough vectors from the pdu
                         * so we need to manually allocate one more.
                         */
                        pdu->in.iov[pdu->in.niov].len = smb2->in.total_size - tmp_size;
                        pdu->in.iov[pdu->in.niov].buf = malloc(pdu->in.iov[pdu->in.niov].len);
                        pdu->in.iov[pdu->in.niov].free = free;

                        smb2->in.iov[smb2->in.niov].len = pdu->in.iov[pdu->in.niov].len;
                        smb2->in.iov[smb2->in.niov].buf = pdu->in.iov[pdu->in.niov].buf;
                        smb2->in.iov[smb2->in.niov].free = NULL;
                        
                        pdu->in.niov++;
                        smb2->in.niov++;
                        continue;
                }
                
		if (smb2->in.num_done >= SMB2_SPL_SIZE + SMB2_HEADER_SIZE &&
                    smb2->in.num_done == smb2->in.total_size) {
                        /* Update pdu so that header now contains the
                         * reply header.
                         */
                        smb2_decode_header(smb2, &smb2->in.iov[1],
                                           &smb2->pdu->header);

			if (smb2_process_pdu(smb2, smb2->pdu) != 0) {
				smb2_set_error(smb2, "Invalid/garbage pdu received from server. Closing socket. %s", smb2_get_error(smb2));
                                smb2->in.num_done  = 0;
                                smb2_free_iovector(smb2, &smb2->in);
                                smb2_free_pdu(smb2, smb2->pdu);
                                smb2->pdu = NULL;
				return -1;
			}
			smb2->in.num_done  = 0;
                        smb2_free_iovector(smb2, &smb2->in);
                        smb2_free_pdu(smb2, smb2->pdu);
                        smb2->pdu = NULL;
		}
	}

	return 0;
}

int
smb2_service(struct smb2_context *smb2, int revents)
{
	if (smb2->fd < 0) {
		return 0;
	}

        if (revents & POLLERR) {
		int err = 0;
		socklen_t err_size = sizeof(err);

		if (getsockopt(smb2->fd, SOL_SOCKET, SO_ERROR,
			       (char *)&err, &err_size) != 0 || err != 0) {
			if (err == 0) {
				err = errno;
			}
			smb2_set_error(smb2, "smb2_service: socket error "
					"%s(%d).",
					strerror(err), err);
		} else {
			smb2_set_error(smb2, "smb2_service: POLLERR, "
					"Unknown socket error.");
		}
		return -1;
	}
	if (revents & POLLHUP) {
		smb2_set_error(smb2, "smb2_service: POLLHUP, "
				"socket error.");
                return -1;
	}

	if (smb2->is_connected == 0 && revents & POLLOUT) {
		int err = 0;
		socklen_t err_size = sizeof(err);

		if (getsockopt(smb2->fd, SOL_SOCKET, SO_ERROR,
			       (char *)&err, &err_size) != 0 || err != 0) {
			if (err == 0) {
				err = errno;
			}
			smb2_set_error(smb2, "smb2_service: socket error "
					"%s(%d) while connecting.",
					strerror(err), err);
			if (smb2->connect_cb) {
				smb2->connect_cb(smb2, err,
                                                 NULL, smb2->connect_data);
				smb2->connect_cb = NULL;
			}
                        return -1;
		}

		smb2->is_connected = 1;
		if (smb2->connect_cb) {
			smb2->connect_cb(smb2, 0, NULL,	smb2->connect_data);
			smb2->connect_cb = NULL;
		}
		return 0;
	}

	if (revents & POLLIN) {
		if (smb2_read_from_socket(smb2) != 0) {
                        return -1;
		}
	}
        
	if (revents & POLLOUT && smb2->outqueue != NULL) {
		if (smb2_write_to_socket(smb2) != 0) {
                        return -1;
		}
	}

        
        return 0;
}

static void
set_nonblocking(int fd)
{
#if defined(WIN32)
	unsigned long opt = 1;
	ioctlsocket(fd, FIONBIO, &opt);
#else
	unsigned v;
	v = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, v | O_NONBLOCK);
#endif
}

static int
set_tcp_sockopt(int sockfd, int optname, int value)
{
	int level;
#ifndef SOL_TCP
	struct protoent *buf;

	if ((buf = getprotobyname("tcp")) != NULL) {
		level = buf->p_proto;
        } else {
		return -1;
        }
#else
        level = SOL_TCP;
#endif

	return setsockopt(sockfd, level, optname, (char *)&value, sizeof(value));
}

int
smb2_connect_async(struct smb2_context *smb2, const char *server,
                   smb2_command_cb cb, void *private_data)
{
        char *addr, *host;
        struct addrinfo *ai = NULL;
        struct sockaddr_storage ss;
        socklen_t socksize;
        int family;

        if (smb2->fd != -1) {
                smb2_set_error(smb2, "Trying to connect but already "
                               "connected.");
                return -1;
        }

        addr = strdup(server);
        if (addr == NULL) {
                smb2_set_error(smb2, "Out-of-memory: "
                               "Failed to strdup server address.");
                return -1;
        }
        host = addr;

        /* ipv6 in [...] form ? */
        if (host[0] == '[') {
                char *str;
                
                host++;
                str = strchr(host, ']');
                if (str == NULL) {
                        free(addr);
                        smb2_set_error(smb2, "Invalid address:%s  "
                                "Missing ']' in IPv6 address", server);
                        return -1;
                }
                *str = 0;
        }

        /* is it a hostname ? */
        if (getaddrinfo(host, NULL, NULL, &ai) != 0) {
                free(addr);
                smb2_set_error(smb2, "Invalid address:%s  "
                               "Can not resolv into IPv4/v6.", server);
                return -1;
        }
        free(addr);

        memset(&ss, 0, sizeof(ss));
        switch (ai->ai_family) {
        case AF_INET:
                socksize = sizeof(struct sockaddr_in);
                memcpy(&ss, ai->ai_addr, socksize);
                ((struct sockaddr_in *)&ss)->sin_port = htons(CIFS_PORT);
#ifdef HAVE_SOCK_SIN_LEN
                ((struct sockaddr_in *)&ss)->sin_len = socksize;
#endif
                break;
#ifdef HAVE_SOCKADDR_IN6
        case AF_INET6:
                socksize = sizeof(struct sockaddr_in6);
                memcpy(&ss, ai->ai_addr, socksize);
                ((struct sockaddr_in6 *)&ss)->sin6_port = htons(CIFS_PORT);
#ifdef HAVE_SOCK_SIN_LEN
                ((struct sockaddr_in6 *)&ss)->sin6_len = socksize;
#endif
                break;
#endif
        default:
                smb2_set_error(smb2, "Unknown address family :%d. "
                                "Only IPv4/IPv6 supported so far.",
                                ai->ai_family);
                freeaddrinfo(ai);
                return -1;

        }
        family = ai->ai_family;
        freeaddrinfo(ai);

        smb2->connect_cb   = cb;
        smb2->connect_data = private_data;

      
	smb2->fd = socket(family, SOCK_STREAM, 0);
	if (smb2->fd == -1) {
		smb2_set_error(smb2, "Failed to open smb2 socket. "
                               "Errno:%s(%d).", strerror(errno), errno);
		return -1;
	}

	set_nonblocking(smb2->fd);
	set_tcp_sockopt(smb2->fd, TCP_NODELAY, 1);
        
	if (connect(smb2->fd, (struct sockaddr *)&ss, socksize) != 0
		&& errno != EINPROGRESS) {
		smb2_set_error(smb2, "Connect failed with errno : "
			"%s(%d)", strerror(errno), errno);
		close(smb2->fd);
		smb2->fd = -1;
		return -1;
	}

        return 0;
}

