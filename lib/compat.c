/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2020 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#include "compat.h"

#ifdef ESP_PLATFORM

#define NEED_READV
#define NEED_WRITEV

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <lwip/sockets.h>
#include <sys/uio.h>

#endif

#ifdef PICO_PLATFORM

#define NEED_BE64TOH
#define NEED_POLL

#include "lwip/def.h"
#include <unistd.h>
#include <lwip/sockets.h>

#endif /* PICO_PLATFORM */

#ifdef PS2_EE_PLATFORM

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#ifndef PS2IPS
#include <ps2ip.h>
#endif
#endif /* PS2_EE_PLATFORM */

#ifdef PS2_IOP_PLATFORM
#include <sysclib.h>

static unsigned long int next = 1; 

int random(void)
{ 
    next = next * 1103515245 + 12345; 
    return (unsigned int)(next/65536) % 32768; 
} 

void srandom(unsigned int seed) 
{ 
    next = seed; 
}

#include <thbase.h>
time_t time(time_t *tloc)
{
        u32 sec, usec;
        iop_sys_clock_t sys_clock;

        GetSystemTime(&sys_clock);
        SysClock2USec(&sys_clock, &sec, &usec);

        return sec;
}

#include <stdio.h>
#include <stdarg.h>
int asprintf(char **strp, const char *fmt, ...)
{
        int len;
        char *str;
        va_list args;        

        va_start(args, fmt);
        str = malloc(256);
        len = sprintf(str, fmt, args);
        va_end(args);
        *strp = str;
        return len;
}

int errno;

int iop_connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
        int rc;
        int err = 0;
        socklen_t err_size = sizeof(err);

        if ((rc = lwip_connect(sockfd, addr, addrlen)) < 0) {
                if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
			       (char *)&err, &err_size) != 0 || err != 0) {
                        errno = err;
                }
        }

        return rc;
}

#endif /* PS2_IOP_PLATFORM */

#ifdef PS3_PPU_PLATFORM

#include <stdlib.h>

int smb2_getaddrinfo(const char *node, const char*service,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
        struct sockaddr_in *sin;

        sin = malloc(sizeof(struct sockaddr_in));
        sin->sin_len = sizeof(struct sockaddr_in);
        sin->sin_family=AF_INET;

        /* Some error checking would be nice */
        sin->sin_addr.s_addr = inet_addr(node);

        sin->sin_port=0;
        if (service) {
                sin->sin_port=htons(atoi(service));
        } 

        *res = malloc(sizeof(struct addrinfo));

        (*res)->ai_family = AF_INET;
        (*res)->ai_addrlen = sizeof(struct sockaddr_in);
        (*res)->ai_addr = (struct sockaddr *)sin;

        return 0;
}

void smb2_freeaddrinfo(struct addrinfo *res)
{
        free(res->ai_addr);
        free(res);
}

#endif /* PS3_PPU_PLATFORM */

#ifdef __SWITCH__

#define NEED_READV
#define NEED_WRITEV

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/socket.h>
#include <switch/types.h>

#define __set_errno(e) (errno = (e))
#define __libc_use_alloca(size) ((size) <= __MAX_ALLOCA_CUTOFF)
#define __MAX_ALLOCA_CUTOFF 32768
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define __alloca alloca
#define __write write
#define __read read
#define __writev writev
#define __readv readv
#define __mempcpy mempcpy

static void
ifree (char **ptrp)
{
  free (*ptrp);
}

#endif /* __SWITCH__ */

#ifdef NEED_WRITEV
#ifdef __SWITCH__
/* Write data pointed by the buffers described by VECTOR, which
   is a vector of COUNT 'struct iovec's, to file descriptor FD.
   The data is written in the order specified.
   Operates just like 'write' (see <unistd.h>) except that the data
   are taken from VECTOR instead of a contiguous buffer.  */
ssize_t
__writev (int fd, const struct iovec *vector, int count)
#else
ssize_t writev(int fd, const struct iovec *vector, int count)
#endif
{
        /* Find the total number of bytes to be written.  */
        size_t bytes = 0;
        int i;
        char *buffer;
        size_t to_copy;
        char *bp;
		ssize_t bytes_written;
#ifdef __SWITCH__
		char *malloced_buffer __attribute__ ((__cleanup__ (ifree))) = NULL;
		for (i = 0; i < count; ++i)
		{
			/* Check for ssize_t overflow.  */
			if (SSIZE_MAX - bytes < vector[i].iov_len)
			{
				__set_errno (EINVAL);
				return -1;
			}
			bytes += vector[i].iov_len;
		}

		/* Allocate a temporary buffer to hold the data.  We should normally
		   use alloca since it's faster and does not require synchronization
		   with other threads.  But we cannot if the amount of memory
		   required is too large.  */
		if (__libc_use_alloca (bytes))
			buffer = (char *) __alloca (bytes);
		else
		{
			malloced_buffer = buffer = (char *) malloc (bytes);
			if (buffer == NULL)
				/* XXX I don't know whether it is acceptable to try writing
				the data in chunks.  Probably not so we just fail here.  */
			return -1;
		}
#else
        for (i = 0; i < count; ++i) {
                /* Check for ssize_t overflow.  */
                if (((ssize_t)-1) - bytes < vector[i].iov_len) {
                        errno = EINVAL;
                        return -1;
                }
                bytes += vector[i].iov_len;
        }

        buffer = (char *)malloc(bytes);
        if (buffer == NULL)
                /* XXX I don't know whether it is acceptable to try writing
                the data in chunks.  Probably not so we just fail here.  */
                return -1;
#endif
        /* Copy the data into BUFFER.  */
        to_copy = bytes;
        bp = buffer;
        for (i = 0; i < count; ++i) {
#ifdef __SWITCH__
				size_t copy = MIN (vector[i].iov_len, to_copy);

				bp = __mempcpy ((void *) bp, (void *) vector[i].iov_base, copy);
#else
                size_t copy = (vector[i].iov_len < to_copy) ? vector[i].iov_len : to_copy;

                memcpy((void *)bp, (void *)vector[i].iov_base, copy);
                
				bp += copy;
#endif

                to_copy -= copy;
                if (to_copy == 0)
                        break;
        }
        bytes_written = write(fd, buffer, bytes);
        free(buffer);
        return bytes_written;
}
#endif

#ifdef NEED_READV
#ifdef __SWITCH__
/* Read data from file descriptor FD, and put the result in the
   buffers described by VECTOR, which is a vector of COUNT 'struct iovec's.
   The buffers are filled in the order specified.
   Operates just like 'read' (see <unistd.h>) except that data are
   put in VECTOR instead of a contiguous buffer.  */
ssize_t
__readv (int fd, const struct iovec *vector, int count)
#else
ssize_t readv (int fd, const struct iovec *vector, int count)
#endif
{
        /* Find the total number of bytes to be read.  */
        size_t bytes = 0;
        int i;
        char *buffer;
        ssize_t bytes_read;
        char *bp;
#ifdef __SWITCH
		char *malloced_buffer __attribute__ ((__cleanup__ (ifree))) = NULL;
		for (i = 0; i < count; ++i)
		{
				/* Check for ssize_t overflow.  */
				if (SSIZE_MAX - bytes < vector[i].iov_len) {
					__set_errno (EINVAL);
					return -1;
				}		
				bytes += vector[i].iov_len;
        }
		/*  Allocate a temporary buffer to hold the data.  We should normally
			use alloca since it's faster and does not require synchronization
			with other threads.  But we cannot if the amount of memory
			required is too large.  */
		if (__libc_use_alloca (bytes))
			buffer = (char *) __alloca (bytes);
		else
		{
			malloced_buffer = buffer = (char *) malloc (bytes);
			if (buffer == NULL)
			return -1;
		}
#else
        for (i = 0; i < count; ++i)
        {
                /* Check for ssize_t overflow.  */
                if (((ssize_t)-1) - bytes < vector[i].iov_len) {
                        errno = EINVAL;
                        return -1;
                }
                bytes += vector[i].iov_len;
        }
        buffer = (char *)malloc(bytes);
        if (buffer == NULL)
                return -1;
#endif

        /* Read the data.  */
#ifdef __SWITCH__
        bytes_read = read(fd, buffer, bytes);
#else
        bytes_read = __read(fd, buffer, bytes);
#endif
        if (bytes_read < 0) {
                free(buffer);
                return -1;
        }

        /* Copy the data from BUFFER into the memory specified by VECTOR.  */
        bytes = bytes_read;
		bp = buffer;
		for (i = 0; i < count; ++i) {
#ifdef __SWITCH__
			size_t copy = MIN (vector[i].iov_len, bytes);

			(void) memcpy ((void *) vector[i].iov_base, (void *) buffer, copy);
#else
            size_t copy = (vector[i].iov_len < bytes) ? vector[i].iov_len : bytes;

            memcpy((void *)vector[i].iov_base, (void *)bp, copy);	
#endif
			bp += copy;
			bytes -= copy;
			if (bytes == 0)
				break;
		}

        free(buffer);
        return bytes_read;
}
#endif

#ifdef NEED_POLL
int poll(struct pollfd *fds, unsigned int nfds, int timo)
{
        struct timeval timeout, *toptr;
        fd_set ifds, ofds, efds, *ip, *op;
        unsigned int i, maxfd = 0;
        int  rc;

        FD_ZERO(&ifds);
        FD_ZERO(&ofds);
        FD_ZERO(&efds);
        for (i = 0, op = ip = 0; i < nfds; ++i) {
                fds[i].revents = 0;
                if(fds[i].events & (POLLIN|POLLPRI)) {
                        ip = &ifds;
                        FD_SET(fds[i].fd, ip);
                }
                if(fds[i].events & POLLOUT)  {
                        op = &ofds;
                        FD_SET(fds[i].fd, op);
                }
                FD_SET(fds[i].fd, &efds);
                if (fds[i].fd > maxfd) {
                        maxfd = fds[i].fd;
                }
        } 

        if(timo < 0) {
                toptr = NULL;
        } else {
#if defined(PS2_EE_PLATFORM) && defined(PS2IPS)                
                /*
                 * select() is broken on the ps2ips stack so we basically have
                 * to busy-wait.
                 */
                (void)timeout;
                timeout.tv_sec = 0;
                timeout.tv_usec = 10000;        
#else
                toptr = &timeout;
                timeout.tv_sec = timo / 1000;
                timeout.tv_usec = (timo - timeout.tv_sec * 1000) * 1000;
#endif        
        }

        rc = select(maxfd + 1, ip, op, &efds, toptr);

        if(rc <= 0)
                return rc;

        if(rc > 0)  {
                for (i = 0; i < nfds; ++i) {
                        int fd = fds[i].fd;
                        if(fds[i].events & (POLLIN|POLLPRI) && FD_ISSET(fd, &ifds))
                                fds[i].revents |= POLLIN;
                        if(fds[i].events & POLLOUT && FD_ISSET(fd, &ofds))
                                fds[i].revents |= POLLOUT;
                        if(FD_ISSET(fd, &efds))
                                fds[i].revents |= POLLHUP;
                }
        }
        return rc;
}
#endif

#ifdef NEED_STRDUP
char *strdup(const char *s)
{
        char *str;
        int len;

        len = strlen(s) + 1;
        str = malloc(len);
        if (str == NULL) {
#ifndef PS2_IOP_PLATFORM
                errno = ENOMEM;
#endif /* !PS2_IOP_PLATFORM */
                return NULL;
        }
        memcpy(str, s, len + 1);
        return str;
}
#endif /* NEED_STRDUP */

#ifdef NEED_BE64TOH
long long int be64toh(long long int x)
{
  long long int val;

  val = ntohl(x & 0xffffffff);
  val <<= 32;
  val ^= ntohl(x >> 32);
  return val;
}
#endif /* NEED_BE64TOH */
