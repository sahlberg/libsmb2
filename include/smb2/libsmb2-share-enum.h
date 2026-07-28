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
 * Minimal share-enum types and high-level API provided by libsmb2.
 * Full DCE/RPC (including SHARE_INFO_502 and other srvsvc ops) lives in
 * libdcerpc — see dcerpc/dcerpc-srvsvc.h.
 */

/* Low 2 bits describe the share type (STYPE_*) */
#define SRVSVC_SHARE_TYPE_DISKTREE   0
#define SRVSVC_SHARE_TYPE_PRINTQ     1
#define SRVSVC_SHARE_TYPE_DEVICE     2
#define SRVSVC_SHARE_TYPE_IPC        3
#define SRVSVC_SHARE_TYPE_TEMPORARY  0x40000000
#define SRVSVC_SHARE_TYPE_HIDDEN     0x80000000 /* STYPE_SPECIAL */

enum SHARE_INFO_enum {
        SHARE_INFO_0 = 0,
        SHARE_INFO_1 = 1,
        SHARE_INFO_2 = 2,
        SHARE_INFO_502 = 502,
};

struct srvsvc_SHARE_INFO_0 {
        char *netname;
};

struct srvsvc_SHARE_INFO_0_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_0 *share_info_0;
};

struct srvsvc_SHARE_INFO_1 {
        char *netname;
        uint32_t type;
        char *remark;
};

struct srvsvc_SHARE_INFO_1_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_1 *share_info_1;
};

struct srvsvc_SHARE_INFO_2 {
        char *netname;
        uint32_t type;
        char *remark;
        uint32_t permissions;
        uint32_t max_users;
        uint32_t current_users;
        char *path;
        char *passwd;
};

struct srvsvc_SHARE_INFO_2_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_2 *share_info_2;
};

/* Incomplete unless dcerpc/dcerpc-srvsvc.h (libdcerpc) is also included. */
struct srvsvc_SHARE_INFO_502;

struct srvsvc_SHARE_INFO_502_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_502 *share_info_502;
};

union srvsvc_SHARE_ENUM_UNION {
        struct srvsvc_SHARE_INFO_0_CONTAINER Level0;
        struct srvsvc_SHARE_INFO_1_CONTAINER Level1;
        struct srvsvc_SHARE_INFO_2_CONTAINER Level2;
        struct srvsvc_SHARE_INFO_502_CONTAINER Level502;
};

struct srvsvc_SHARE_ENUM_STRUCT {
        uint32_t Level;
        union srvsvc_SHARE_ENUM_UNION ShareEnum;
};

struct srvsvc_NetrShareEnum_req {
        char *ServerName;
        struct srvsvc_SHARE_ENUM_STRUCT ses;
        uint32_t PreferedMaximumLength;
        uint32_t ResumeHandle;
};

struct srvsvc_NetrShareEnum_rep {
        struct srvsvc_SHARE_ENUM_STRUCT ses;
        uint32_t total_entries;
        uint32_t resume_handle;

        uint32_t status;
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
 *      0 : Success. Command_data is struct srvsvc_NetrShareEnum_rep *
 *          This pointer must be freed using smb2_free_data().
 * -errno : An error occurred.
 *
 * libsmb2 implements levels 0, 1 and 2. Level 502 requires libdcerpc.
 */
int smb2_share_enum_async(struct smb2_context *smb2, enum SHARE_INFO_enum level,
                          smb2_command_cb cb, void *cb_data);
/*
 * Sync share_enum()
 * This function only works when connected to the IPC$ share.
 *
 * Returns
 * NULL: Failure
 * !NULL: Success. The returned pointer is struct srvsvc_NetrShareEnum_rep *
 *        This pointer must be freed using smb2_free_data().
 */
struct srvsvc_NetrShareEnum_rep *
smb2_share_enum_sync(struct smb2_context *smb2, enum SHARE_INFO_enum level);

#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_SHARE_ENUM_H_ */
