/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2024
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#define _FILE_OFFSET_BITS 64
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <inttypes.h>
#if !defined(__amigaos4__) && !defined(__AMIGA__) && !defined(__AROS__)
#include <poll.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

#ifdef __AROS__
#include "asprintf.h"
#endif

struct file_context {
	int is_smb2;
	int fd;
	struct smb2_context *smb2;
	struct smb2fh *smb2fh;
	struct smb2_url *url;
};

void usage(void)
{
	fprintf(stderr, "Usage: smb2-cp <src> <dst>\n");
	fprintf(stderr, "<src>,<dst> can either be a local file or "
			"an smb2 URL.\n");
	exit(0);
}

static int
close_file(struct file_context *fc)
{
	if (fc->smb2fh != NULL) {
		struct smb2fh *fh = fc->smb2fh;
		fc->smb2fh = NULL;
		return smb2_close(fc->smb2, fh);
	}
	if (fc->fd != -1) {
		int fd = fc->fd;
		fc->fd = -1;
		return close(fd);
	}
	return 0;
}

static void
free_file_context(struct file_context *file_context)
{
	close_file(file_context);
	if (file_context->smb2 != NULL) {
		smb2_destroy_context(file_context->smb2);
	}
	smb2_destroy_url(file_context->url);
	free(file_context);
}

static const char *
file_error(struct file_context *fc)
{
	if (fc->is_smb2) {
		return smb2_get_error(fc->smb2);
	}
	return strerror(errno);
}

/* SMB file indices alone do not identify a file across volumes. For
 * unrecognized aliases the copy loop preserves the source through EOF. */
static int
same_file(struct file_context *src, struct file_context *dst, uint64_t *dst_size)
{
	struct stat src_st, dst_st;

	if (dst->is_smb2) {
		const char *src_domain, *dst_domain;
		const char *src_user, *dst_user;

		/* SEEK_END uses the size already returned by CREATE. */
		if (smb2_lseek(dst->smb2, dst->smb2fh, 0, SEEK_END, dst_size) < 0) {
			return -1;
		}
		if (!src->is_smb2) {
			return 0;
		}
		src_user = smb2_get_user(src->smb2);
		dst_user = smb2_get_user(dst->smb2);
		src_domain = smb2_get_domain(src->smb2);
		dst_domain = smb2_get_domain(dst->smb2);
		return src_user && dst_user && !strcmp(src_user, dst_user) &&
		       !strcmp(src_domain ? src_domain : "", dst_domain ? dst_domain : "") &&
		       !strcmp(src->url->server, dst->url->server) &&
		       !strcmp(src->url->share, dst->url->share) &&
		       src->url->path && dst->url->path && !strcmp(src->url->path, dst->url->path);
	}
	if (fstat(dst->fd, &dst_st) < 0) {
		return -1;
	}
	*dst_size = S_ISREG(dst_st.st_mode) && dst_st.st_size > 0 ? (uint64_t)dst_st.st_size : 0;
	if (src->is_smb2) {
		return 0;
	}
	if (fstat(src->fd, &src_st) < 0) {
		return -1;
	}
	return src_st.st_dev == dst_st.st_dev && src_st.st_ino == dst_st.st_ino;
}

static struct file_context *
open_file(const char *url, int flags)
{
	struct file_context *file_context;

	file_context = malloc(sizeof(struct file_context));
	if (file_context == NULL) {
		fprintf(stderr, "Failed to malloc file_context\n");
		return NULL;
	}
	file_context->is_smb2 = 0;
	file_context->fd     = -1;
	file_context->smb2    = NULL;
	file_context->smb2fh  = NULL;
	file_context->url    = NULL;

	if (strncmp(url, "smb://", 6)) {
		file_context->is_smb2 = 0;
		file_context->fd = open(url, flags, 0660);
		if (file_context->fd == -1) {		
			fprintf(stderr, "Failed to open %s\n", url);
			free_file_context(file_context);
			return NULL;
		}
		return file_context;
	}

	file_context->is_smb2 = 1;

	file_context->smb2 = smb2_init_context();
	if (file_context->smb2 == NULL) {
		fprintf(stderr, "failed to init context\n");
		free_file_context(file_context);
		return NULL;
	}

	file_context->url = smb2_parse_url(file_context->smb2, url);
	if (file_context->url == NULL) {
		fprintf(stderr, "%s\n", smb2_get_error(file_context->smb2));
		free_file_context(file_context);
		return NULL;
	}
	if (file_context->url->domain) {
		smb2_set_domain(file_context->smb2, file_context->url->domain);
	}

	if (smb2_connect_share(file_context->smb2, file_context->url->server,
			       file_context->url->share,
			       file_context->url->user) != 0) {
		fprintf(stderr, "Failed to mount smb2 share : %s\n",
			       smb2_get_error(file_context->smb2));
		free_file_context(file_context);
		return NULL;
	}

	file_context->smb2fh = smb2_open(file_context->smb2, file_context->url->path, flags);
	if (file_context->smb2fh == NULL) {
		fprintf(stderr, "Failed to open file %s: %s\n",
			       file_context->url->path,
			       smb2_get_error(file_context->smb2));
		free_file_context(file_context);
		return NULL;
	}
	return file_context;
}

#define BUFSIZE 1024*1024
static uint8_t buf[BUFSIZE];

int main(int argc, char *argv[])
{
	uint64_t dst_size;
	int same;
	struct file_context *src;
	struct file_context *dst;
	uint64_t off = 0;
	ssize_t count;
	int result = 10;
	
#ifdef WIN32
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		printf("Failed to start Winsock2\n");
		return 10;
	}
#endif

#ifdef AROS
	aros_init_socket();
#endif

	if (argc != 3) {
		usage();
	}

	src = open_file(argv[1], O_RDONLY);
	if (src == NULL) {
		fprintf(stderr, "Failed to open %s\n", argv[1]);
		return 10;
	}

	dst = open_file(argv[2], O_WRONLY|O_CREAT);
	if (dst == NULL) {
		fprintf(stderr, "Failed to open %s\n", argv[2]);
		free_file_context(src);
		return 10;
	}

	same = same_file(src, dst, &dst_size);
	if (same < 0) {
		fprintf(stderr, "Failed to inspect file: %s\n", file_error(dst));
		goto out;
	}
	if (same) {
		fprintf(stderr, "Source and destination are the same file\n");
		goto out;
	}

	for (;;) {
		ssize_t written = 0;

		count = src->is_smb2 ? smb2_pread(src->smb2, src->smb2fh, buf, sizeof(buf), off)
		                     : read(src->fd, buf, sizeof(buf));
		if (count < 0) {
			if (!src->is_smb2 && errno == EINTR) {
				continue;
			}
			fprintf(stderr, "Failed to read source: %s\n", file_error(src));
			goto out;
		}
		if (count == 0) {
			break;
		}
		while (written < count) {
			size_t left = (size_t)(count - written);
			ssize_t n = dst->is_smb2
				? smb2_pwrite(dst->smb2, dst->smb2fh, buf + written, left, off)
				: write(dst->fd, buf + written, left);
			if (n <= 0) {
				if (n < 0 && !dst->is_smb2 && errno == EINTR) {
					continue;
				}
				fprintf(stderr, "Failed to write destination: %s\n",
				        n == 0 ? "no progress" : file_error(dst));
				goto out;
			}
			written += n;
			off += n;
		}
	}
	/* Trim the old tail only after reading the source to EOF. Even a
	 * local path and a share URL can refer to the same underlying file. */
	if (off < dst_size &&
	    (dst->is_smb2 ? smb2_ftruncate(dst->smb2, dst->smb2fh, off)
	                  : ftruncate(dst->fd, (off_t)off)) < 0) {
		fprintf(stderr, "Failed to truncate destination: %s\n", file_error(dst));
		goto out;
	}
	if (close_file(dst) < 0) {
		fprintf(stderr, "Failed to close destination: %s\n", file_error(dst));
		goto out;
	}
	printf("copied %" PRIu64 " bytes\n", off);
	result = 0;
 out:
	free_file_context(src);
	free_file_context(dst);
	return result;
}
