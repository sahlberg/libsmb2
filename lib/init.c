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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdarg.h>
#include <stdio.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

#define MAX_URL_SIZE 256

struct smb2_url *smb2_parse_url(struct smb2_context *smb2, const char *url)
{
        struct smb2_url *u;
        char *ptr, *tmp, str[MAX_URL_SIZE];

        if (strncmp(url, "smb://", 6)) {
                smb2_set_error(smb2, "URL does not start with 'smb://'");
                return NULL;
        }
        if (strlen(url + 6) >= MAX_URL_SIZE) {
                smb2_set_error(smb2, "URL is too long");
                return NULL;
        }
	strncpy(str, url + 6, MAX_URL_SIZE);

        u = malloc(sizeof(struct smb2_url));
        if (u == NULL) {
                smb2_set_error(smb2, "Failed to allocate smb2_url");
                return NULL;
        }
        memset(u, 0, sizeof(struct smb2_url));
        
        ptr = str;

        /* domain */
        if ((tmp = strchr(ptr, ';')) != NULL) {
                *(tmp++) = '\0';
                u->domain = strdup(ptr);
                ptr = tmp;
        }
        /* user */
        if ((tmp = strchr(ptr, '@')) != NULL) {
                *(tmp++) = '\0';
                u->user = strdup(ptr);
                ptr = tmp;
        }
        /* server */
        if ((tmp = strchr(ptr, '/')) != NULL) {
                *(tmp++) = '\0';
                u->server = strdup(ptr);
                ptr = tmp;
        }

        /* Do we just have a share or do we have both a share and an object */
        tmp = strchr(ptr, '/');
        
        /* We only have a share */
        if (tmp == NULL) {
                u->share = strdup(ptr);
                return u;
        }

        /* we have both share and object path */
        *(tmp++) = '\0';
        u->share = strdup(ptr);
        u->path = strdup(tmp);

        return u;
}

void smb2_destroy_url(struct smb2_url *url)
{
        if (url == NULL) {
                return;
        }
        free(url->domain);
        free(url->user);
        free(url->server);
        free(url->share);
        free(url->path);
        free(url);
}

struct smb2_context *smb2_init_context(void)
{
        struct smb2_context *smb2;

        smb2 = malloc(sizeof(struct smb2_context));
        if (smb2 == NULL) {
                return NULL;
        }
        memset(smb2, 0, sizeof(struct smb2_context));

        smb2->fd = -1;
        
        snprintf(smb2->client_guid, 16, "libnfs-%d", getpid());
        
        return smb2;
}

void smb2_destroy_context(struct smb2_context *smb2)
{
        if (smb2 == NULL) {
                return;
        }

        if (smb2->fd != -1) {
                close(smb2->fd);
                smb2->fd = -1;
        }

        while (smb2->outqueue) {
                struct smb2_pdu *pdu = smb2->outqueue;

                smb2->outqueue = pdu->next;
                smb2_free_pdu(smb2, pdu);
        }
        while (smb2->waitqueue) {
                struct smb2_pdu *pdu = smb2->waitqueue;

                smb2->waitqueue = pdu->next;
                smb2_free_pdu(smb2, pdu);
        }
        smb2_free_iovector(smb2, &smb2->in);
        if (smb2->pdu) {
                smb2_free_pdu(smb2, smb2->pdu);
                smb2->pdu = NULL;
        }

        free(smb2->server);
        free(smb2->share);
        free(smb2);
}

void smb2_free_iovector(struct smb2_context *smb2, struct smb2_io_vectors *v)
{
        int i;
        
        for (i = 0; i < v->niov; i++) {
                if (v->iov[i].free) {
                        v->iov[i].free(v->iov[i].buf);
                }
        }
        v->niov = 0;
        v->total_size = 0;
        v->num_done = 0;
}

struct smb2_iovec *smb2_add_iovector(struct smb2_context *smb2,
                                     struct smb2_io_vectors *v,
                                     char *buf, int len, void (*free)(void *))
{
        struct smb2_iovec *iov = &v->iov[v->niov];

        v->iov[v->niov].buf = buf;
        v->iov[v->niov].len = len;
        v->iov[v->niov].free = free;
        v->total_size += len;
        v->niov++;

        return iov;
}

void smb2_set_error(struct smb2_context *smb2, const char *error_string, ...)
{
	va_list ap;
	char errstr[MAX_ERROR_SIZE] = {0};

	va_start(ap, error_string);
	if (vsnprintf(errstr, MAX_ERROR_SIZE, error_string, ap) < 0) {
		strncpy(errstr, "could not format error string!",
                        MAX_ERROR_SIZE);
	}
	va_end(ap);
	if (smb2 != NULL) {
		strncpy(smb2->error_string, errstr, MAX_ERROR_SIZE);
	}
}

const char *smb2_get_error(struct smb2_context *smb2)
{
	return smb2 ? smb2->error_string : "";
}
        
const char *smb2_get_client_guid(struct smb2_context *smb2)
{
        return smb2->client_guid;
}

void smb2_set_security_mode(struct smb2_context *smb2, uint16_t security_mode)
{
        smb2->security_mode = security_mode;
}
