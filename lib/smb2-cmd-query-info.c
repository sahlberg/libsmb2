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

int smb2_decode_file_basic_information(
        struct smb2_context *smb2,
        struct smb2_file_basic_information *fs,
        struct smb2_iovec *vec)
{
        uint64_t t;

        smb2_get_uint64(vec, 0, &t);
        win_to_timeval(t, &fs->creation_time);

        smb2_get_uint64(vec, 8, &t);
        win_to_timeval(t, &fs->last_access_time);

        smb2_get_uint64(vec, 16, &t);
        win_to_timeval(t, &fs->last_write_time);

        smb2_get_uint64(vec, 24, &t);
        win_to_timeval(t, &fs->change_time);

        smb2_get_uint32(vec, 32, &fs->file_attributes);

        return 0;
}

int smb2_decode_file_standard_information(
        struct smb2_context *smb2,
        struct smb2_file_standard_information *fs,
        struct smb2_iovec *vec)
{
        smb2_get_uint64(vec, 0, &fs->allocation_size);
        smb2_get_uint64(vec, 8, &fs->end_of_file);
        smb2_get_uint32(vec, 16, &fs->number_of_links);
        smb2_get_uint8(vec, 20, &fs->delete_pending);
        smb2_get_uint8(vec, 20, &fs->directory);

        return 0;
}

int smb2_decode_file_all_information(
        struct smb2_context *smb2,
        struct smb2_file_all_information *fs,
        struct smb2_iovec *vec)
{
        struct smb2_iovec v;

        if (vec->len < 40) {
                return -1;
        }
        
        v.buf = vec->buf;
        v.len = 40;
        smb2_decode_file_basic_information(smb2, &fs->basic, &v);

        if (vec->len < 64) {
                return -1;
        }
        
        v.buf = vec->buf + 40;
        v.len = 24;
        smb2_decode_file_standard_information(smb2, &fs->standard, &v);

        smb2_get_uint64(vec, 64, &fs->index_number);
        smb2_get_uint32(vec, 72, &fs->ea_size);
        smb2_get_uint32(vec, 76, &fs->access_flags);
        smb2_get_uint64(vec, 80, &fs->current_byte_offset);
        smb2_get_uint32(vec, 88, &fs->mode);
        smb2_get_uint32(vec, 92, &fs->alignment_requirement);

        //fs->name = ucs2_to_utf8((uint16_t *)&vec->buf[80], name_len / 2);

        return 0;
}

static int
smb2_encode_query_info_request(struct smb2_context *smb2,
                               struct smb2_pdu *pdu,
                               struct smb2_query_info_request *req)
{
        int len;
        char *buf;
        struct smb2_iovec *iov;

        len = SMB2_QUERY_INFO_REQUEST_SIZE & 0xfffffffe;
        buf = malloc(len);
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate query buffer");
                return -1;
        }
        memset(buf, 0, len);
        
        iov = smb2_add_iovector(smb2, &pdu->out, buf, len, free);

        smb2_set_uint16(iov, 0, SMB2_QUERY_INFO_REQUEST_SIZE);
        smb2_set_uint8(iov, 2, req->info_type);
        smb2_set_uint8(iov, 3, req->file_information_class);
        smb2_set_uint32(iov,4, req->output_buffer_length);
        smb2_set_uint32(iov,12, req->input_buffer_length);
        smb2_set_uint32(iov,16, req->additional_information);
        smb2_set_uint32(iov,20, req->flags);
        memcpy(iov->buf + 24, req->file_id, SMB2_FD_SIZE);

        if (req->input_buffer_length > 0) {
                smb2_set_error(smb2, "No support for input buffers, yet");
                return -1;
        }

        return 0;
}

struct smb2_pdu *
smb2_cmd_query_info_async(struct smb2_context *smb2,
                          struct smb2_query_info_request *req,
                          smb2_command_cb cb, void *cb_data)
{
        struct smb2_pdu *pdu;

        pdu = smb2_allocate_pdu(smb2, SMB2_QUERY_INFO, cb, cb_data);
        if (pdu == NULL) {
                return NULL;
        }

        if (smb2_encode_query_info_request(smb2, pdu, req)) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }
        
        if (smb2_pad_to_64bit(smb2, &pdu->out) != 0) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        return pdu;
}

#define IOV_OFFSET (rep->output_buffer_offset - SMB2_HEADER_SIZE - \
                    (SMB2_QUERY_INFO_REPLY_SIZE & 0xfffe))

int
smb2_process_query_info_fixed(struct smb2_context *smb2,
                              struct smb2_pdu *pdu)
{
        struct smb2_query_info_reply *rep;
        struct smb2_iovec *iov = &smb2->in.iov[smb2->in.niov - 1];
        uint16_t struct_size;

        rep = malloc(sizeof(*rep));
        pdu->payload = rep;

        smb2_get_uint16(iov, 0, &struct_size);
        if (struct_size != SMB2_QUERY_INFO_REPLY_SIZE ||
            (struct_size & 0xfffe) != iov->len) {
                smb2_set_error(smb2, "Unexpected size of Query Info "
                               "reply. Expected %d, got %d",
                               SMB2_QUERY_INFO_REPLY_SIZE,
                               (int)iov->len);
                return -1;
        }

        smb2_get_uint16(iov, 2, &rep->output_buffer_offset);
        smb2_get_uint32(iov, 4, &rep->output_buffer_length);

        if (rep->output_buffer_length == 0) {
                smb2_set_error(smb2, "No output buffer in Query "
                               "Info response");
                return -1;
        }
        if (rep->output_buffer_offset < SMB2_HEADER_SIZE +
            (SMB2_QUERY_INFO_REPLY_SIZE & 0xfffe)) {
                smb2_set_error(smb2, "Output buffer overlaps with "
                               "Query Info reply header");
                return -1;
        }

        /* Return the amount of data that the output buffer will take up.
         * Including any padding before the output buffer itself.
         */
        return IOV_OFFSET + rep->output_buffer_length;
}

int
smb2_process_query_info_variable(struct smb2_context *smb2,
                                 struct smb2_pdu *pdu)
{
        struct smb2_query_info_reply *rep = pdu->payload;
        struct smb2_iovec *iov = &smb2->in.iov[smb2->in.niov - 1];

        rep->output_buffer = &iov->buf[IOV_OFFSET];

        return 0;
}
