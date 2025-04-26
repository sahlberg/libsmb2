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

#ifdef __cplusplus
extern "C" {
#endif

int smb2_process_reply_payload_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu);

int smb2_process_reply_payload_variable(struct smb2_context *smb2, struct smb2_pdu *pdu);

int smb2_process_request_payload_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu);

int smb2_process_request_payload_variable(struct smb2_context *smb2, struct smb2_pdu *pdu);

int smb2_process_payload_fixed(struct smb2_context *smb2, struct smb2_pdu *pdu);

int smb2_process_payload_variable(struct smb2_context *smb2, struct smb2_pdu *pdu);

#ifdef __cplusplus
}
#endif