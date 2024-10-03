/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Brian Dodge <bdodge09g@gmail.com>

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

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

static int
smb2_encode_oplock_break_request(struct smb2_context *smb2,
                          struct smb2_pdu *pdu,
                          struct smb2_oplock_break_request *req)
{
        int len;
        uint8_t *buf;
        struct smb2_iovec *iov;

        len = SMB2_OPLOCK_BREAK_REQUEST_SIZE & 0xfffffffe;
        buf = calloc(len, sizeof(uint8_t));
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate oplock request buffer");
                return -1;
        }

        iov = smb2_add_iovector(smb2, &pdu->out, buf, len, free);

        smb2_set_uint16(iov, 0, SMB2_OPLOCK_BREAK_REQUEST_SIZE);
        smb2_set_uint8(iov, 2, req->oplock_level);
        memcpy(iov->buf + 8, req->file_id, SMB2_FD_SIZE);

        return 0;
}

struct smb2_pdu *
smb2_cmd_oplock_break_async(struct smb2_context *smb2,
                     struct smb2_oplock_break_request *req,
                     smb2_command_cb cb, void *cb_data)
{
        struct smb2_pdu *pdu;

        pdu = smb2_allocate_pdu(smb2, SMB2_OPLOCK_BREAK, cb, cb_data);
        if (pdu == NULL) {
                return NULL;
        }

        if (smb2_encode_oplock_break_request(smb2, pdu, req)) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        if (smb2_pad_to_64bit(smb2, &pdu->out) != 0) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        return pdu;
}

static int
smb2_encode_oplock_break_reply(struct smb2_context *smb2,
                          struct smb2_pdu *pdu,
                          struct smb2_oplock_break_reply *rep)
{
        int len;
        uint8_t *buf;
        struct smb2_iovec *iov;

        len = SMB2_OPLOCK_BREAK_REPLY_SIZE & 0xfffffffe;
        buf = calloc(len, sizeof(uint8_t));
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate oplock reply buffer");
                return -1;
        }

        iov = smb2_add_iovector(smb2, &pdu->out, buf, len, free);

        smb2_set_uint16(iov, 0, SMB2_OPLOCK_BREAK_REPLY_SIZE);
        smb2_set_uint8(iov, 2, rep->oplock_level);
        memcpy(iov->buf + 8, rep->file_id, SMB2_FD_SIZE);

        return 0;
}

struct smb2_pdu *
smb2_cmd_oplock_break_reply_async(struct smb2_context *smb2,
                     struct smb2_oplock_break_reply *rep,
                     smb2_command_cb cb, void *cb_data)
{
        struct smb2_pdu *pdu;

        pdu = smb2_allocate_pdu(smb2, SMB2_OPLOCK_BREAK, cb, cb_data);
        if (pdu == NULL) {
                return NULL;
        }

        if (smb2_encode_oplock_break_reply(smb2, pdu, rep)) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        if (smb2_pad_to_64bit(smb2, &pdu->out) != 0) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        return pdu;
}

int
smb2_process_oplock_break_fixed(struct smb2_context *smb2,
                         struct smb2_pdu *pdu)
{
        struct smb2_oplock_break_reply *rep;
        struct smb2_iovec *iov = &smb2->in.iov[smb2->in.niov - 1];
        uint16_t struct_size;

        rep = malloc(sizeof(*rep));
        if (rep == NULL) {
                smb2_set_error(smb2, "Failed to allocate oplock-break reply");
                return -1;
        }
        pdu->payload = rep;

        smb2_get_uint16(iov, 0, &struct_size);
        if (struct_size != SMB2_OPLOCK_BREAK_REPLY_SIZE ||
            (struct_size & 0xfffe) != iov->len) {
                smb2_set_error(smb2, "Unexpected size of oplock "
                               "break reply. Expected %d, got %d",
                               SMB2_OPLOCK_BREAK_REPLY_SIZE,
                               (int)iov->len);
                return -1;
        }

        smb2_get_uint8(iov, 2, &rep->oplock_level);
        memcpy(rep->file_id, iov->buf + 8, SMB2_FD_SIZE);

        return 0;
}

int
smb2_process_oplock_break_request_fixed(struct smb2_context *smb2,
                         struct smb2_pdu *pdu)
{
        struct smb2_oplock_break_request *req;
        struct smb2_iovec *iov = &smb2->in.iov[smb2->in.niov - 1];
        uint16_t struct_size;

        req = malloc(sizeof(*req));
        if (req == NULL) {
                smb2_set_error(smb2, "Failed to allocate oplock request");
                return -1;
        }
        pdu->payload = req;

        smb2_get_uint16(iov, 0, &struct_size);
        if (struct_size != SMB2_OPLOCK_BREAK_REQUEST_SIZE ||
            (struct_size & 0xfffe) != iov->len) {
                smb2_set_error(smb2, "Unexpected size of oplock "
                               "break request. Expected %d, got %d",
                               SMB2_OPLOCK_BREAK_REQUEST_SIZE,
                               (int)iov->len);
                return -1;
        }

        smb2_get_uint8(iov, 2, &req->oplock_level);
        memcpy(req->file_id, iov->buf + 8, SMB2_FD_SIZE);

        return 0;
}


