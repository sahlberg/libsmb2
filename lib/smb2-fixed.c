/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2025 by André Guilherme <andregui17@outlook.com>

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

#include "compat.h"

#include "portable-endian.h"

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

int
smb2_get_fixed_reply_size(struct smb2_context* smb2, struct smb2_pdu* pdu)
{
    if (smb2_is_error_response(smb2, pdu)) {
        return SMB2_ERROR_REPLY_SIZE & 0xfffe;
    }

    switch (pdu->header.command) {
    case SMB2_NEGOTIATE:
        return SMB2_NEGOTIATE_REPLY_SIZE;
    case SMB2_SESSION_SETUP:
        return SMB2_SESSION_SETUP_REPLY_SIZE;
    case SMB2_LOGOFF:
        return SMB2_LOGOFF_REPLY_SIZE;
    case SMB2_TREE_CONNECT:
        return SMB2_TREE_CONNECT_REPLY_SIZE;
    case SMB2_TREE_DISCONNECT:
        return SMB2_TREE_DISCONNECT_REPLY_SIZE;
    case SMB2_CREATE:
        return SMB2_CREATE_REPLY_SIZE;
    case SMB2_CLOSE:
        return SMB2_CLOSE_REPLY_SIZE;
    case SMB2_FLUSH:
        return SMB2_FLUSH_REPLY_SIZE;
    case SMB2_READ:
        return SMB2_READ_REPLY_SIZE;
    case SMB2_WRITE:
        return SMB2_WRITE_REPLY_SIZE;
    case SMB2_LOCK:
        return SMB2_LOCK_REPLY_SIZE;
    case SMB2_ECHO:
        return SMB2_ECHO_REPLY_SIZE;
    case SMB2_QUERY_DIRECTORY:
        return SMB2_QUERY_DIRECTORY_REPLY_SIZE;
    case SMB2_CHANGE_NOTIFY:
        return SMB2_CHANGE_NOTIFY_REPLY_SIZE;
    case SMB2_QUERY_INFO:
        return SMB2_QUERY_INFO_REPLY_SIZE;
    case SMB2_SET_INFO:
        return SMB2_SET_INFO_REPLY_SIZE;
    case SMB2_IOCTL:
        return SMB2_IOCTL_REPLY_SIZE;
    case SMB2_OPLOCK_BREAK:
        /* need to read the struct size to see what
         * type (oplock or lease) the pdu is */
        return sizeof(uint16_t);
    }
    return -1;
}

int
smb2_get_fixed_request_size(struct smb2_context* smb2, struct smb2_pdu* pdu)
{
    switch (pdu->header.command) {
    case SMB2_NEGOTIATE:
        return SMB2_NEGOTIATE_REQUEST_SIZE;
    case SMB2_SESSION_SETUP:
        return SMB2_SESSION_SETUP_REQUEST_SIZE;
    case SMB2_LOGOFF:
        return SMB2_LOGOFF_REQUEST_SIZE;
    case SMB2_TREE_CONNECT:
        return SMB2_TREE_CONNECT_REQUEST_SIZE;
    case SMB2_TREE_DISCONNECT:
        return SMB2_TREE_DISCONNECT_REQUEST_SIZE;
    case SMB2_CREATE:
        return SMB2_CREATE_REQUEST_SIZE;
    case SMB2_CLOSE:
        return SMB2_CLOSE_REQUEST_SIZE;
    case SMB2_FLUSH:
        return SMB2_FLUSH_REQUEST_SIZE;
    case SMB2_READ:
        return SMB2_READ_REQUEST_SIZE;
    case SMB2_WRITE:
        return SMB2_WRITE_REQUEST_SIZE;
    case SMB2_LOCK:
        return SMB2_LOCK_REQUEST_SIZE;
    case SMB2_CANCEL:
        return SMB2_CANCEL_REQUEST_SIZE;
    case SMB2_ECHO:
        return SMB2_ECHO_REQUEST_SIZE;
    case SMB2_QUERY_DIRECTORY:
        return SMB2_QUERY_DIRECTORY_REQUEST_SIZE;
    case SMB2_CHANGE_NOTIFY:
        return SMB2_CHANGE_NOTIFY_REQUEST_SIZE;
    case SMB2_QUERY_INFO:
        return SMB2_QUERY_INFO_REQUEST_SIZE;
    case SMB2_SET_INFO:
        return SMB2_SET_INFO_REQUEST_SIZE;
    case SMB2_IOCTL:
        return SMB2_IOCTL_REQUEST_SIZE;
    case SMB2_OPLOCK_BREAK:
        /* need to read the struct size to see what
         * type (oplock or lease) the pdu is */
        return sizeof(uint16_t);
    }
    return -1;
}

int
smb2_get_fixed_size(struct smb2_context* smb2, struct smb2_pdu* pdu)
{
    if (smb2_is_server(smb2)) {
        return smb2_get_fixed_request_size(smb2, pdu);
    }
    else {
        return smb2_get_fixed_reply_size(smb2, pdu);
    }
}
