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

/*
 * NTSTATUS fields
 */
#define SMB2_STATUS_SEVERITY_MASK    0xc0000000ul
#define SMB2_STATUS_SEVERITY_SUCCESS 0x00000000ul
#define SMB2_STATUS_SEVERITY_INFO    0x40000000ul
#define SMB2_STATUS_SEVERITY_WARNING 0x80000000ul
#define SMB2_STATUS_SEVERITY_ERROR   0xc0000000ul

#define SMB2_STATUS_CUSTOMER_MASK    0x20000000ul

#define SMB2_STATUS_FACILITY_MASK    0x0fff0000ul

#define SMB2_STATUS_CODE_MASK        0x0000fffful


/* Error codes */
#define SMB2_STATUS_SUCCESS                  0x00000000ul
#define SMB2_STATUS_PENDING                  0x00000103ul
#define SMB2_STATUS_NO_MORE_FILES            0x80000006ul
#define SMB2_STATUS_INVALID_PARAMETER        0xC000000dul
#define SMB2_STATUS_END_OF_FILE              0xC0000011ul
#define SMB2_STATUS_MORE_PROCESSING_REQUIRED 0xC0000016ul
#define SMB2_STATUS_ACCESS_DENIED            0xC0000022ul
#define SMB2_STATUS_OBJECT_NAME_NOT_FOUND    0xC0000034ul
#define SMB2_STATUS_LOGON_FAILURE            0xC000006dul
#define SMB2_STATUS_BAD_NETWORK_NAME         0xC00000CCul
#define SMB2_STATUS_NOT_A_DIRECTORY          0xC0000103ul
#define SMB2_STATUS_FILE_CLOSED              0xC0000128ul
