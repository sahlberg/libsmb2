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

#ifdef STDC_HEADERS
#include <stddef.h>
#endif

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

static int
smb2_encode_close_request(struct smb2_context *smb2,
                          struct smb2_pdu *pdu,
                          struct smb2_close_request *req)
{
        int len;
        char *buf;

        len = SMB2_CLOSE_REQUEST_SIZE & 0xfffffffe;
        buf = malloc(len);
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate close buffer");
                return -1;
        }
        memset(buf, 0, len);
        
        pdu->out.iov[pdu->out.niov].len = len;
        pdu->out.iov[pdu->out.niov].buf = buf;
        pdu->out.iov[pdu->out.niov].free = free;
        
        smb2_set_uint16(&pdu->out.iov[pdu->out.niov], 0, req->struct_size);
        smb2_set_uint16(&pdu->out.iov[pdu->out.niov], 2, req->flags);
        memcpy(pdu->out.iov[pdu->out.niov].buf + 8, req->file_id,
               SMB2_FD_SIZE);
        pdu->out.niov++;
        
        return 0;
}

static int
smb2_decode_close_reply(struct smb2_context *smb2,
                         struct smb2_pdu *pdu,
                         struct smb2_close_reply *rep)
{
        smb2_get_uint16(&pdu->in.iov[0], 0, &rep->struct_size);
        smb2_get_uint16(&pdu->in.iov[0], 2, &rep->flags);
        smb2_get_uint64(&pdu->in.iov[0], 8, &rep->creation_time);
        smb2_get_uint64(&pdu->in.iov[0], 16, &rep->last_access_time);
        smb2_get_uint64(&pdu->in.iov[0], 24, &rep->last_write_time);
        smb2_get_uint64(&pdu->in.iov[0], 32, &rep->change_time);
        smb2_get_uint64(&pdu->in.iov[0], 40, &rep->allocation_size);
        smb2_get_uint64(&pdu->in.iov[0], 48, &rep->end_of_file);
        smb2_get_uint32(&pdu->in.iov[0], 56, &rep->file_attributes);

        return 0;
}

int smb2_close_async(struct smb2_context *smb2,
                     struct smb2_close_request *req,
                     smb2_command_cb cb, void *cb_data)
{
        struct smb2_pdu *pdu;

        pdu = smb2_allocate_pdu(smb2, SMB2_CLOSE, cb, cb_data);
        if (pdu == NULL) {
                return -1;
        }

        if (smb2_encode_close_request(smb2, pdu, req)) {
                smb2_free_pdu(smb2, pdu);
                return -1;
        }
        
        if (smb2_queue_pdu(smb2, pdu)) {
                smb2_free_pdu(smb2, pdu);
                return -1;
        }

        return 0;
}

int smb2_process_close_reply(struct smb2_context *smb2,
                             struct smb2_pdu *pdu)
{
        struct smb2_close_reply reply;

        smb2_decode_close_reply(smb2, pdu, &reply);

        pdu->cb(smb2, pdu->header.status, &reply, pdu->cb_data);

        return 0;
}
