/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2020 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

/* This configuration file is used to disable featured in libsmb2 to make it
 * smaller footprint.
 */

/* Uncomment to disable building the DCERPC LSA interface */
/* #define DISABLE_DCERPC_LSA */

/* Uncomment to disable building the DCERPC SRVSVC interface */
/* #define DISABLE_DCERPC_SRVSVC */

/* Uncomment to disable building DCERPC and all interfaces */
#define DISABLE_DCERPC

/* Uncomment to disable NT Status error to string mappings */
#define DISABLE_NT_STATUS_STRINGS

/* Uncomment to disable smb2_get_error strings */
#define DISABLE_ERROR_STRINGS
#define smb2_set_error(...) ;

/* Uncomment to disable SMB2/3 Encryption */
#define DISABLE_SEAL

/* Uncomment to disable SMB2/3 Signing */
#define DISABLE_SIGN

/* Uncomment to disable GetInfo: Security Descriptor */
#define DISABLE_SEC_DESC

/* Uncomment to disable Reparse Point support */
#define DISABLE_REPARSE_POINTS

/* Uncomment to disable the IOCTL command. This also disables support for
 * readlink()
 */
#define DISABLE_IOCTL_CMD

/* Uncomment to disable the Logoff command */
#define DISABLE_LOGOFF_CMD

/* Uncomment to disable commands that Write or Modify data or metadata */
#define DISABLE_MUTATE
