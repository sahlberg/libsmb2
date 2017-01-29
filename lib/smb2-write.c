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

#include <errno.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

static int
smb2_encode_write_request(struct smb2_context *smb2,
                          struct smb2_pdu *pdu,
                          struct smb2_write_request *req)
{
        int len;
        char *buf;

        len = SMB2_WRITE_REQUEST_SIZE & 0xfffffffe;
        buf = malloc(len);
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate write buffer");
                return -1;
        }
        memset(buf, 0, len);

        pdu->out.iov[pdu->out.niov].len = len;
        pdu->out.iov[pdu->out.niov].buf = buf;
        pdu->out.iov[pdu->out.niov].free = free;

        smb2_set_uint16(&pdu->out.iov[pdu->out.niov], 0,
                        SMB2_WRITE_REQUEST_SIZE);
        smb2_set_uint16(&pdu->out.iov[pdu->out.niov], 2,
                        SMB2_HEADER_SIZE + 48);
        smb2_set_uint32(&pdu->out.iov[pdu->out.niov], 4, req->length);
        smb2_set_uint64(&pdu->out.iov[pdu->out.niov], 8, req->offset);
        memcpy(pdu->out.iov[pdu->out.niov].buf + 16, req->file_id,
               SMB2_FD_SIZE);
        smb2_set_uint32(&pdu->out.iov[pdu->out.niov], 32, req->channel);
        smb2_set_uint32(&pdu->out.iov[pdu->out.niov], 36, req->remaining_bytes);
        smb2_set_uint16(&pdu->out.iov[pdu->out.niov], 42, req->write_channel_info_length);
        smb2_set_uint32(&pdu->out.iov[pdu->out.niov], 44, req->flags);

        pdu->out.niov++;

        if (req->write_channel_info_length > 0 ||
            req->write_channel_info != NULL) {
                smb2_set_error(smb2, "ChannelInfo not yet implemented");
                return -1;
        }

        return 0;
}

static int
smb2_decode_write_reply(struct smb2_context *smb2,
                        struct smb2_pdu *pdu,
                        struct smb2_write_reply *rep)
{
        uint16_t struct_size;

        smb2_get_uint16(&pdu->in.iov[0], 0, &struct_size);
        if (struct_size != SMB2_WRITE_REPLY_SIZE) {
                smb2_set_error(smb2, "Unexpected size of Write reply. "
                               "Expected %d, got %d",
                               SMB2_WRITE_REPLY_SIZE,
                               (int)struct_size);
                return -1;
        }

        smb2_get_uint32(&pdu->in.iov[0], 4, &rep->count);
        smb2_get_uint32(&pdu->in.iov[0], 8, &rep->remaining);

        return 0;
}

int smb2_cmd_write_async(struct smb2_context *smb2,
                         struct smb2_write_request *req,
                         smb2_command_cb cb, void *cb_data)
{
        struct smb2_pdu *pdu;

        pdu = smb2_allocate_pdu(smb2, SMB2_WRITE, cb, cb_data);
        if (pdu == NULL) {
                return -1;
        }

        if (smb2_encode_write_request(smb2, pdu, req)) {
                smb2_free_pdu(smb2, pdu);
                return -1;
        }

        smb2_add_iovector(smb2, &pdu->out, req->buf,
                          req->length, NULL);
        
        if (smb2_queue_pdu(smb2, pdu)) {
                smb2_free_pdu(smb2, pdu);
                return -1;
        }

        return 0;
}

int smb2_process_write_reply(struct smb2_context *smb2,
                            struct smb2_pdu *pdu)
{
        struct smb2_write_reply reply;

        if (smb2_decode_write_reply(smb2, pdu, &reply) < 0) {
                pdu->cb(smb2, -EBADMSG, NULL, pdu->cb_data);
                return -1;
        }

        pdu->cb(smb2, pdu->header.status, &reply, pdu->cb_data);

        return 0;
}
