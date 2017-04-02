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

#include <endian.h>

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

int
smb2_pad_to_64bit(struct smb2_context *smb2, struct smb2_io_vectors *v)
{
        static char zero_bytes[7];
        int i, len = 0;

        for (i = 0; i < v->niov; i++) {
                len += v->iov[i].len;
        }
        if ((len & 0x07) == 0) {
                return 0;
        }
        if (smb2_add_iovector(smb2, v, &zero_bytes[0], 8 - (len & 0x07), NULL)
            == NULL) {
                return -1;
        }

        return 0;
}

struct smb2_pdu *
smb2_allocate_pdu(struct smb2_context *smb2, enum smb2_command command,
                  smb2_command_cb cb, void *cb_data)
{
	struct smb2_pdu *pdu;
        struct smb2_header *hdr;
        char magic[4] = {0xFE, 'S', 'M', 'B'};
        
        pdu = malloc(sizeof(struct smb2_pdu));
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to allocate pdu");
                return NULL;
        }
        memset(pdu, 0, sizeof(struct smb2_pdu));

        hdr = &pdu->header;
        
        memcpy(hdr->protocol_id, magic, 4);

        hdr->struct_size = SMB2_HEADER_SIZE;
        
        /* We don't have any credits yet during negprot */
        if (command != SMB2_NEGOTIATE) {
                hdr->credit_charge = 1;
                hdr->credit_request_response = 32 - smb2->credits;
        }
        
        hdr->command = command;
        hdr->flags = 0;
        hdr->message_id = smb2->message_id++;

        hdr->sync.process_id = 0xFEFF;
        switch (command) {
        case SMB2_NEGOTIATE:
        case SMB2_SESSION_SETUP:
        case SMB2_LOGOFF:
        case SMB2_ECHO:
        case SMB2_CANCEL:
                break;
        default:
                hdr->sync.tree_id = smb2->tree_id;
        }

        switch (command) {
        case SMB2_NEGOTIATE:
        case SMB2_ECHO:
                break;
        default:
               hdr->session_id = smb2->session_id;
        }

        pdu->cb = cb;
        pdu->cb_data = cb_data;
        pdu->out.niov = 0;

        smb2_add_iovector(smb2, &pdu->out, pdu->hdr, SMB2_HEADER_SIZE, NULL);
        if (smb2_encode_header(smb2, &pdu->out.iov[0],
                               &pdu->header)) {
                smb2_set_error(smb2, "Failed to encode header");
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }
        
        return pdu;
}

void smb2_add_compound_pdu(struct smb2_context *smb2,
                           struct smb2_pdu *pdu, struct smb2_pdu *next_pdu)
{
        int i, offset;

        /* find the last pdu in the chain */
        while (pdu->next_compound) {
                pdu = pdu->next_compound;
        }
        pdu->next_compound = next_pdu;

        /* Fixup the next offset in the header */
        for (i = 0, offset = 0; i < pdu->out.niov; i++) {
                offset += pdu->out.iov[i].len;
        }

        pdu->header.next_command = offset;
        smb2_set_uint32(&pdu->out.iov[0], 20, pdu->header.next_command);

        /* Fixup flags */
        next_pdu->header.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
        smb2_set_uint32(&next_pdu->out.iov[0], 16, next_pdu->header.flags);
}

void
smb2_free_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu)
{
        if (pdu->next_compound) {
                smb2_free_pdu(smb2, pdu->next_compound);
        }

        smb2_free_iovector(smb2, &pdu->out);
        smb2_free_iovector(smb2, &pdu->in);
        
        free(pdu);
}

int
smb2_set_uint8(struct smb2_iovec *iov, int offset, uint8_t value)
{
        if (offset + sizeof(uint8_t) > iov->len) {
                return -1;
        }
        iov->buf[offset] = value;
        return 0;
}

int
smb2_set_uint16(struct smb2_iovec *iov, int offset, uint16_t value)
{
        if (offset + sizeof(uint16_t) > iov->len) {
                return -1;
        }
        *(uint16_t *)(iov->buf + offset) = htole16(value);
        return 0;
}

int
smb2_set_uint32(struct smb2_iovec *iov, int offset, uint32_t value)
{
        if (offset + sizeof(uint32_t) > iov->len) {
                return -1;
        }
        *(uint32_t *)(iov->buf + offset) = htole32(value);
        return 0;
}

int
smb2_set_uint64(struct smb2_iovec *iov, int offset, uint64_t value)
{
        if (offset + sizeof(uint64_t) > iov->len) {
                return -1;
        }
        *(uint64_t *)(iov->buf + offset) = htole64(value);
        return 0;
}

int
smb2_get_uint8(struct smb2_iovec *iov, int offset, uint8_t *value)
{
        if (offset + sizeof(uint8_t) > iov->len) {
                return -1;
        }
        *value = iov->buf[offset];
        return 0;
}

int
smb2_get_uint16(struct smb2_iovec *iov, int offset, uint16_t *value)
{
        uint16_t tmp;
        
        if (offset + sizeof(uint16_t) > iov->len) {
                return -1;
        }
        memcpy(&tmp, iov->buf + offset, sizeof(uint16_t));
        *value = le16toh(tmp);
        return 0;
}

int
smb2_get_uint32(struct smb2_iovec *iov, int offset, uint32_t *value)
{
        uint32_t tmp;
        
        if (offset + sizeof(uint32_t) > iov->len) {
                return -1;
        }
        memcpy(&tmp, iov->buf + offset, sizeof(uint32_t));
        *value = le32toh(tmp);
        return 0;
}

int
smb2_get_uint64(struct smb2_iovec *iov, int offset, uint64_t *value)
{
        uint64_t tmp;
        
        if (offset + sizeof(uint64_t) > iov->len) {
                return -1;
        }
        memcpy(&tmp, iov->buf + offset, sizeof(uint64_t));
        *value = le64toh(tmp);
        return 0;
}

int
smb2_encode_header(struct smb2_context *smb2, struct smb2_iovec *iov,
                   struct smb2_header *hdr)
{
        if (iov->len != SMB2_HEADER_SIZE) {
                smb2_set_error(smb2, "io vector for header is wrong size");
                return -1;
        }
        
        memcpy(iov->buf, hdr->protocol_id, 4);
        smb2_set_uint16(iov, 4, hdr->struct_size);
        smb2_set_uint16(iov, 6, hdr->credit_charge);
        smb2_set_uint32(iov, 8, hdr->status);
        smb2_set_uint16(iov, 12, hdr->command);
        smb2_set_uint16(iov, 14, hdr->credit_request_response);
        smb2_set_uint32(iov, 16, hdr->flags);
        smb2_set_uint32(iov, 20, hdr->next_command);
        smb2_set_uint64(iov, 24, hdr->message_id);

        if (hdr->flags & SMB2_FLAGS_ASYNC_COMMAND) {
                smb2_set_uint64(iov, 32, hdr->async.async_id);
        } else {
                smb2_set_uint32(iov, 32, hdr->sync.process_id);
                smb2_set_uint32(iov, 36, hdr->sync.tree_id);
        }
        
        smb2_set_uint64(iov, 40, hdr->session_id);
        memcpy(iov->buf + 48, hdr->signature, 16);
        
        return 0;
}

int
smb2_decode_header(struct smb2_context *smb2, struct smb2_iovec *iov,
                   struct smb2_header *hdr)
{
        if (iov->len != SMB2_HEADER_SIZE) {
                smb2_set_error(smb2, "io vector for header is wrong size");
                return -1;
        }

        memcpy(&hdr->protocol_id, iov->buf, 4);
        smb2_get_uint16(iov, 4, &hdr->struct_size);
        smb2_get_uint16(iov, 6, &hdr->credit_charge);
        smb2_get_uint32(iov, 8, &hdr->status);
        smb2_get_uint16(iov, 12, &hdr->command);
        smb2_get_uint16(iov, 14, &hdr->credit_request_response);
        smb2_get_uint32(iov, 16, &hdr->flags);
        smb2_get_uint32(iov, 20, &hdr->next_command);
        smb2_get_uint64(iov, 24, &hdr->message_id);

        if (hdr->flags & SMB2_FLAGS_ASYNC_COMMAND) {
                smb2_get_uint64(iov, 32, &hdr->async.async_id);
        } else {
                smb2_get_uint32(iov, 32, &hdr->sync.process_id);
                smb2_get_uint32(iov, 36, &hdr->sync.tree_id);
        }
        
        smb2_get_uint64(iov, 40, &hdr->session_id);
        memcpy(&hdr->signature, iov->buf + 48, 16);

        return 0;
}

static void
smb2_add_to_outqueue(struct smb2_context *smb2, struct smb2_pdu *pdu)
{
        SMB2_LIST_ADD_END(&smb2->outqueue, pdu);
}

int
smb2_queue_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu)
{
        int i;
        uint32_t len = 0;
        
        for (i = 0; i < pdu->out.niov; i++) {
                len += pdu->out.iov[i].len;
        }
        pdu->out.total_size = len;

	smb2_add_to_outqueue(smb2, pdu);

	return 0;
}

struct smb2_pdu *smb2_find_pdu(struct smb2_context *smb2,
                               uint64_t message_id) {
        struct smb2_pdu *pdu;
        
        for (pdu = smb2->waitqueue; pdu; pdu = pdu->next) {
                if (pdu->header.message_id == message_id) {
                        break;
                }
        }
        return pdu;
}

int smb2_process_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu)
{
        smb2->credits += pdu->header.credit_request_response;
        
        switch (pdu->header.command) {
        case SMB2_CLOSE:
                return smb2_process_close_reply(smb2, pdu);
        case SMB2_CREATE:
                return smb2_process_create_reply(smb2, pdu);
        case SMB2_ECHO:
                return smb2_process_echo_reply(smb2, pdu);
        case SMB2_LOGOFF:
                return smb2_process_logoff_reply(smb2, pdu);
        case SMB2_NEGOTIATE:
                return smb2_process_negotiate_reply(smb2, pdu);
        case SMB2_QUERY_INFO:
                return smb2_process_query_info_reply(smb2, pdu);
        case SMB2_QUERY_DIRECTORY:
                return smb2_process_query_directory_reply(smb2, pdu);
        case SMB2_READ:
                return smb2_process_read_reply(smb2, pdu);
        case SMB2_SESSION_SETUP:
                return smb2_process_session_setup_reply(smb2, pdu);
        case SMB2_TREE_CONNECT:
                return smb2_process_tree_connect_reply(smb2, pdu);
        case SMB2_TREE_DISCONNECT:
                return smb2_process_tree_disconnect_reply(smb2, pdu);
        case SMB2_WRITE:
                return smb2_process_write_reply(smb2, pdu);
        default:
                smb2_set_error(smb2, "no decoder for command:%d yet",
                               pdu->header.command);
                return -1;
        }
        return 0;
}

