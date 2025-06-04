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

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"
#include "smb2-process.h"

int smb2_process_reply_payload_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)
{
        if (smb2_is_error_response(smb2, pdu)) {
                return smb2_process_error_fixed(smb2, pdu);
        }

        switch (pdu->header.command) {
        case SMB2_NEGOTIATE:
                return smb2_process_negotiate_fixed(smb2, pdu);
        case SMB2_SESSION_SETUP:
                return smb2_process_session_setup_fixed(smb2, pdu);
        case SMB2_LOGOFF:
                return smb2_process_logoff_fixed(smb2, pdu);
        case SMB2_TREE_CONNECT:
                return smb2_process_tree_connect_fixed(smb2, pdu);
        case SMB2_TREE_DISCONNECT:
                return smb2_process_tree_disconnect_fixed(smb2, pdu);
        case SMB2_CREATE:
                return smb2_process_create_fixed(smb2, pdu);
        case SMB2_CLOSE:
                return smb2_process_close_fixed(smb2, pdu);
        case SMB2_FLUSH:
                return smb2_process_flush_fixed(smb2, pdu);
        case SMB2_READ:
                return smb2_process_read_fixed(smb2, pdu);
        case SMB2_WRITE:
                return smb2_process_write_fixed(smb2, pdu);
        case SMB2_ECHO:
                return smb2_process_echo_fixed(smb2, pdu);
        case SMB2_LOCK:
                return smb2_process_lock_fixed(smb2, pdu);
        case SMB2_QUERY_DIRECTORY:
                return smb2_process_query_directory_fixed(smb2, pdu);
        case SMB2_CHANGE_NOTIFY:
                return smb2_process_change_notify_fixed(smb2, pdu);
        case SMB2_QUERY_INFO:
                return smb2_process_query_info_fixed(smb2, pdu);
        case SMB2_SET_INFO:
                return smb2_process_set_info_fixed(smb2, pdu);
        case SMB2_IOCTL:
                return smb2_process_ioctl_fixed(smb2, pdu);
        case SMB2_OPLOCK_BREAK:
                /* notice that op/lease lock breaks can be notification or response here */
                return smb2_process_oplock_break_fixed(smb2, pdu);
        }
        return 0;
}

int smb2_process_reply_payload_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)
{
        if (smb2_is_error_response(smb2, pdu)) {
                return smb2_process_error_variable(smb2, pdu);
        }

        switch (pdu->header.command) {
        case SMB2_NEGOTIATE:
                return smb2_process_negotiate_variable(smb2, pdu);
        case SMB2_SESSION_SETUP:
                return smb2_process_session_setup_variable(smb2, pdu);
        case SMB2_LOGOFF:
                return 0;
        case SMB2_TREE_CONNECT:
                return 0;
        case SMB2_TREE_DISCONNECT:
                return 0;
        case SMB2_CREATE:
                return smb2_process_create_variable(smb2, pdu);
        case SMB2_CLOSE:
                return 0;
        case SMB2_FLUSH:
                return 0;
        case SMB2_READ:
                return smb2_process_read_variable(smb2, pdu);
        case SMB2_WRITE:
                return 0;
        case SMB2_ECHO:
                return 0;
        case SMB2_LOCK:
                return 0;
        case SMB2_CANCEL:
                return 0;
        case SMB2_QUERY_DIRECTORY:
                return smb2_process_query_directory_variable(smb2, pdu);
        case SMB2_CHANGE_NOTIFY:
                return smb2_process_change_notify_variable(smb2, pdu);
        case SMB2_QUERY_INFO:
                return smb2_process_query_info_variable(smb2, pdu);
        case SMB2_SET_INFO:
                return 0;
        case SMB2_IOCTL:
                return smb2_process_ioctl_variable(smb2, pdu);
        case SMB2_OPLOCK_BREAK:
                return smb2_process_oplock_break_variable(smb2, pdu);
        }
        return 0;
}

int smb2_process_request_payload_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)
{
        switch (pdu->header.command) {
        case SMB2_NEGOTIATE:
                return smb2_process_negotiate_request_fixed(smb2, pdu);
        case SMB2_SESSION_SETUP:
                return smb2_process_session_setup_request_fixed(smb2, pdu);
        case SMB2_LOGOFF:
                return smb2_process_logoff_request_fixed(smb2, pdu);
        case SMB2_TREE_CONNECT:
                return smb2_process_tree_connect_request_fixed(smb2, pdu);
        case SMB2_TREE_DISCONNECT:
                return 0;
        case SMB2_CREATE:
                return smb2_process_create_request_fixed(smb2, pdu);
        case SMB2_CLOSE:
                return smb2_process_close_request_fixed(smb2, pdu);
        case SMB2_FLUSH:
                return smb2_process_flush_request_fixed(smb2, pdu);
        case SMB2_READ:
                return smb2_process_read_request_fixed(smb2, pdu);
        case SMB2_WRITE:
                return smb2_process_write_request_fixed(smb2, pdu);
        case SMB2_ECHO:
                return smb2_process_echo_request_fixed(smb2, pdu);
        case SMB2_LOCK:
                return smb2_process_lock_request_fixed(smb2, pdu);
        case SMB2_CANCEL:
                return 0;
        case SMB2_QUERY_DIRECTORY:
                return smb2_process_query_directory_request_fixed(smb2, pdu);
        case SMB2_CHANGE_NOTIFY:
                return smb2_process_change_notify_request_fixed(smb2, pdu);
        case SMB2_QUERY_INFO:
                return smb2_process_query_info_request_fixed(smb2, pdu);
        case SMB2_SET_INFO:
                return smb2_process_set_info_request_fixed(smb2, pdu);
        case SMB2_IOCTL:
                return smb2_process_ioctl_request_fixed(smb2, pdu);
        case SMB2_OPLOCK_BREAK:
                /* note oplock/lease break from a client is an acknowlegement here */
                return smb2_process_oplock_break_request_fixed(smb2, pdu);
        default:
                smb2_set_error(smb2, "No handler for fixed request");
                return -1;
        }
        return 0;
}

int smb2_process_request_payload_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)
{
        switch (pdu->header.command) {
        case SMB2_NEGOTIATE:
                return smb2_process_negotiate_request_variable(smb2, pdu);
        case SMB2_SESSION_SETUP:
                return smb2_process_session_setup_request_variable(smb2, pdu);
        case SMB2_LOGOFF:
                return 0;
        case SMB2_TREE_CONNECT:
                return smb2_process_tree_connect_request_variable(smb2, pdu);
        case SMB2_TREE_DISCONNECT:
                return 0;
        case SMB2_CREATE:
                return smb2_process_create_request_variable(smb2, pdu);
        case SMB2_CLOSE:
                return 0;
        case SMB2_FLUSH:
                return 0;
        case SMB2_READ:
                return smb2_process_read_request_variable(smb2, pdu);
        case SMB2_WRITE:
                return smb2_process_write_request_variable(smb2, pdu);
        case SMB2_LOCK:
                return smb2_process_lock_request_variable(smb2, pdu);
        case SMB2_CANCEL:
                return 0;
        case SMB2_ECHO:
                return 0;
        case SMB2_QUERY_DIRECTORY:
                return smb2_process_query_directory_request_variable(smb2, pdu);
        case SMB2_CHANGE_NOTIFY:
                return 0;
        case SMB2_QUERY_INFO:
                return smb2_process_query_info_request_variable(smb2, pdu);
        case SMB2_SET_INFO:
                return smb2_process_set_info_request_variable(smb2, pdu);
        case SMB2_IOCTL:
                return smb2_process_ioctl_request_variable(smb2, pdu);
        case SMB2_OPLOCK_BREAK:
                return smb2_process_oplock_break_request_variable(smb2, pdu);
        default:
                smb2_set_error(smb2, "No handler for var request");
        }
        return -1;
}

int smb2_process_payload_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu)
{
        if (smb2_is_server(smb2)) {
                return smb2_process_request_payload_fixed(smb2, pdu);
        }
        else {
                return smb2_process_reply_payload_fixed(smb2, pdu);
        }
}

int smb2_process_payload_variable(struct smb2_context *smb2, struct smb2_pdu *pdu)
{
        if (smb2_is_server(smb2)) {
                return smb2_process_request_payload_variable(smb2, pdu);
        }
        else {
                return smb2_process_reply_payload_variable(smb2, pdu);
        }
}