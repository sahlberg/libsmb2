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

#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>

#include "smb2.h"

const char *nterror_to_str(uint32_t status) {
        switch (status) {
        case SMB2_STATUS_SUCCESS:
                return "STATUS_SUCCESS";
        case SMB2_STATUS_NO_MORE_FILES:
                return "STATUS_NO_MORE_FILES";
        case SMB2_STATUS_MORE_PROCESSING_REQUIRED:
                return "STATUS_MORE_PROCESSING_REQUIRED";
        case SMB2_STATUS_ACCESS_DENIED:
                return "STATUS_ACCESS_DENIED";
        case SMB2_STATUS_LOGON_FAILURE:
                return "STATUS_LOGON_FAILURE";
        case SMB2_STATUS_BAD_NETWORK_NAME:
                return "STATUS_BAD_NETWORK_NAME";
        case SMB2_STATUS_NOT_A_DIRECTORY:
                return "STATUS_NOT_A_DIRECTORY";
        case SMB2_STATUS_INVALID_PARAMETER:
                return "STATUS_INVALID_PARAMETER";
        case SMB2_STATUS_END_OF_FILE:
                return "STATUS_END_OF_FILE";
        case SMB2_STATUS_FILE_CLOSED:
                return "STATUS_FILE_CLOSED";
        case SMB2_STATUS_OBJECT_NAME_NOT_FOUND:
                return "STATUS_OBJECT_NAME_NOT_FOUND";
        default:
                return "Unknown";
        }
}

int nterror_to_errno(uint32_t status) {
        switch (status) {
        case SMB2_STATUS_SUCCESS:
        case SMB2_STATUS_END_OF_FILE:
                return 0;
        case SMB2_STATUS_BAD_NETWORK_NAME:
        case SMB2_STATUS_OBJECT_NAME_NOT_FOUND:
                return ENOENT;
        case SMB2_STATUS_FILE_CLOSED:
                return EBADF;
        case SMB2_STATUS_MORE_PROCESSING_REQUIRED:
                return EAGAIN;
        case SMB2_STATUS_ACCESS_DENIED:
                return EACCES;
        case SMB2_STATUS_NO_MORE_FILES:
                return ENODATA;
        case SMB2_STATUS_LOGON_FAILURE:
                return ECONNREFUSED;
        case SMB2_STATUS_NOT_A_DIRECTORY:
                return ENOTDIR;
        case SMB2_STATUS_INVALID_PARAMETER:
                return EINVAL;
        default:
                return EIO;
        }
}
