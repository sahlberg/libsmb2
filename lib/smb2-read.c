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
smb2_encode_read_request(struct smb2_context *smb2,
                         struct smb2_pdu *pdu,
                         struct smb2_read_request *req)
{
        int len;
        char *buf;

        len = SMB2_READ_REQUEST_SIZE & 0xfffffffe;
        buf = malloc(len);
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate read buffer");
                return -1;
        }
        memset(buf, 0, len);
        
        pdu->out.iov[pdu->out.niov].len = len;
        pdu->out.iov[pdu->out.niov].buf = buf;
        pdu->out.iov[pdu->out.niov].free = free;

        smb2_set_uint16(&pdu->out.iov[pdu->out.niov], 0, req->struct_size);
        smb2_set_uint8(&pdu->out.iov[pdu->out.niov], 3, req->flags);
        smb2_set_uint32(&pdu->out.iov[pdu->out.niov], 4, req->length);
        smb2_set_uint64(&pdu->out.iov[pdu->out.niov], 8, req->offset);
        memcpy(pdu->out.iov[pdu->out.niov].buf + 16, req->file_id,
               SMB2_FD_SIZE);
        smb2_set_uint32(&pdu->out.iov[pdu->out.niov], 32, req->minimum_count);
        smb2_set_uint32(&pdu->out.iov[pdu->out.niov], 36, req->channel);
        smb2_set_uint32(&pdu->out.iov[pdu->out.niov], 40, req->remaining_bytes);
        smb2_set_uint16(&pdu->out.iov[pdu->out.niov], 44, req->read_channel_info_offset);

        pdu->out.niov++;

        if (req->read_channel_info != NULL) {
                smb2_set_error(smb2, "ChannelInfo not yet implemented");
                return -1;
        }

        /* The buffer must contain at least one byte, even if we do not
         * have any read channel info.
         */
        if (req->read_channel_info == NULL) {
                static char zero;

                pdu->out.iov[pdu->out.niov].len = 1;
                pdu->out.iov[pdu->out.niov].buf = &zero;
                pdu->out.iov[pdu->out.niov].free = NULL;
                pdu->out.niov++;
        }
        
        return 0;
}

static int
smb2_decode_read_reply(struct smb2_context *smb2,
                         struct smb2_pdu *pdu,
                         struct smb2_read_reply *rep)
{
        smb2_get_uint16(&pdu->in.iov[0], 0, &rep->struct_size);
        smb2_get_uint8(&pdu->in.iov[0], 2, &rep->data_offset);
        smb2_get_uint32(&pdu->in.iov[0], 4, &rep->data_length);
        smb2_get_uint32(&pdu->in.iov[0], 8, &rep->data_remaining);

        return 0;
}

int smb2_cmd_read_async(struct smb2_context *smb2,
                        struct smb2_read_request *req,
                        smb2_command_cb cb, void *cb_data)
{
        struct smb2_pdu *pdu;
        char *buf;

        buf = malloc(SMB2_READ_REPLY_SIZE & 0xfffffffe);
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to malloc read header");
                return -1;
        }

        pdu = smb2_allocate_pdu(smb2, SMB2_READ, cb, cb_data);
        if (pdu == NULL) {
                return -1;
        }

        if (smb2_encode_read_request(smb2, pdu, req)) {
                smb2_free_pdu(smb2, pdu);
                return -1;
        }

        /* Add a vector for the read header as well a vector for
         * the buffer that the application gave us
         */
        smb2_add_iovector(smb2, &pdu->in, buf,
                          SMB2_READ_REPLY_SIZE & 0xfffffffe, free);
        smb2_add_iovector(smb2, &pdu->in, req->buf,
                          req->length, NULL);
        
        if (smb2_queue_pdu(smb2, pdu)) {
                smb2_free_pdu(smb2, pdu);
                return -1;
        }

        return 0;
}

int smb2_process_read_reply(struct smb2_context *smb2,
                            struct smb2_pdu *pdu)
{
        struct smb2_read_reply reply;

        smb2_decode_read_reply(smb2, pdu, &reply);

        pdu->cb(smb2, pdu->header.status, &reply, pdu->cb_data);

        return 0;
}
