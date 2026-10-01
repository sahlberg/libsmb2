/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2018 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#ifndef _LIBSMB2_SHARE_ENUM_H_
#define _LIBSMB2_SHARE_ENUM_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Share enumeration (srvsvc NetrShareEnum) provided by libsmb2 itself.
 * Only levels 0, 1 and 2 are supported. Full srvsvc support is in
 * libdcerpc (dcerpc/dcerpc-srvsvc.h); its srvsvc_* types are separate.
 */

/* smb2_share_info_N.type: the low 2 bits are the share type (STYPE_*) */
#define SMB2_SHARE_TYPE_DISKTREE   0
#define SMB2_SHARE_TYPE_PRINTQ     1
#define SMB2_SHARE_TYPE_DEVICE     2
#define SMB2_SHARE_TYPE_IPC        3
#define SMB2_SHARE_TYPE_TEMPORARY  0x40000000
#define SMB2_SHARE_TYPE_HIDDEN     0x80000000 /* STYPE_SPECIAL */

enum smb2_share_info_level {
        SMB2_SHARE_INFO_0 = 0,
        SMB2_SHARE_INFO_1 = 1,
        SMB2_SHARE_INFO_2 = 2,
};

struct smb2_share_info_0 {
        char *netname;
};

struct smb2_share_info_1 {
        char *netname;
        uint32_t type;
        char *remark;
};

struct smb2_share_info_2 {
        char *netname;
        uint32_t type;
        char *remark;
        uint32_t permissions;
        uint32_t max_users;
        uint32_t current_users;
        char *path;
        char *passwd;
};

/*
 * Result of a share enumeration. share_info holds entries_read entries
 * of the type selected by level; total_entries is the number of shares
 * the server reported in total.
 */
struct smb2_share_enum_reply {
        uint32_t level;
        uint32_t entries_read;
        uint32_t total_entries;
        union {
                struct smb2_share_info_0 *info_0;
                struct smb2_share_info_1 *info_1;
                struct smb2_share_info_2 *info_2;
        } share_info;
};

/*
 * Async share_enum()
 * This function only works when connected to the IPC$ share.
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success. Command_data is struct smb2_share_enum_reply *
 *          This pointer must be freed using smb2_free_data().
 * -errno : An error occurred. Command_data is NULL.
 *  other : The server returned this (positive) WERROR status.
 *          Command_data is a struct smb2_share_enum_reply * that must be
 *          freed using smb2_free_data().
 */
int smb2_share_enum_async(struct smb2_context *smb2,
                          enum smb2_share_info_level level,
                          smb2_command_cb cb, void *cb_data);

/*
 * Sync share_enum()
 * This function only works when connected to the IPC$ share.
 *
 * Returns
 *  NULL  : An error occurred. Use smb2_get_error() for details.
 *  else  : struct smb2_share_enum_reply *, to be freed with
 *          smb2_free_data().
 */
struct smb2_share_enum_reply *
smb2_share_enum_sync(struct smb2_context *smb2,
                     enum smb2_share_info_level level);

#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_SHARE_ENUM_H_ */
