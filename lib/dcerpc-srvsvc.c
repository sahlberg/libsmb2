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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_UNISTD_H
#include <sys/unistd.h>
#endif

#include <errno.h>
#include <stdio.h>

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-dcerpc.h"
#include "libsmb2-dcerpc-srvsvc.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

#define SRVSVC_UUID    0x4b324fc8, 0x1670, 0x01d3, {0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88}

p_syntax_id_t srvsvc_interface = {
        {SRVSVC_UUID}, 3, 0
};

/*
 * SRVSVC BEGIN:  DEFINITIONS FROM SRVSVC.IDL
 * [MS-SRVS].pdf
 */

/*
 * typedef struct _SHARE_INFO_0 {
 *     [string] wchar_t * shi0_netname;
 * } SHARE_INFO_0, *PSHARE_INFO_0, *LPSHARE_INFO_0;
 */
int
srvsvc_SHARE_INFO_0_coder(char *name, struct dcerpc_context *dce,
                           struct dcerpc_pdu *pdu,
                           struct smb2_iovec *iov, int *offset,
                           void *ptr)
{
        struct srvsvc_SHARE_INFO_0 *nsi1 = ptr;

        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset, &nsi1->netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SHARE_INFO_0_STRUCT_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_0_coder);
}

/*
 *       [size_is(EntriesRead)] LPSHARE_INFO_0 Buffer;
 */
static int
srvsvc_SHARE_INFO_0_carray_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        return dcerpc_carray_coder("ShareInfo0", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SHARE_INFO_0),
                                   srvsvc_SHARE_INFO_0_coder);
}

/*
 * typedef struct _SHARE_INFO_0_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPSHARE_INFO_0 Buffer;
 * } SHARE_INFO_0_CONTAINER;
*/
int
srvsvc_SHARE_INFO_0_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        struct srvsvc_SHARE_INFO_0_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }                
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->share_info_0 == NULL) {
                        size_t esize = sizeof(struct srvsvc_SHARE_INFO_0);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->share_info_0 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->share_info_0 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("ShareInfo0", dce, pdu, iov, offset, ctr->share_info_0,
                             PTR_UNIQUE, srvsvc_SHARE_INFO_0_carray_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _SHARE_INFO_1 {
 *       [string] wchar_t *netname;
 *       DWORD shi1_type;
 *       [string] wchar_t *remark;
 * } SHARE_INFO_1, *PSHARE_INFO_1, *LPSHARE_INFO_1;
 */
int
srvsvc_SHARE_INFO_1_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        struct srvsvc_SHARE_INFO_1 *nsi1 = ptr;

        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset, &nsi1->netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Type", dce, pdu, iov, offset, &nsi1->type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Remark", dce, pdu, iov, offset, &nsi1->remark,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SHARE_INFO_1_STRUCT_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_1_coder);
}

/*
 *       [size_is(EntriesRead)] LPSHARE_INFO_1 Buffer;
 */
static int
srvsvc_SHARE_INFO_1_carray_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        return dcerpc_carray_coder("ShareInfo1", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SHARE_INFO_1),
                                   srvsvc_SHARE_INFO_1_STRUCT_coder);
}

/*
 * typedef struct _SHARE_INFO_1_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPSHARE_INFO_1 Buffer;
 * } SHARE_INFO_1_CONTAINER;
*/
int
srvsvc_SHARE_INFO_1_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        struct srvsvc_SHARE_INFO_1_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }                
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->share_info_1 == NULL) {
                        size_t esize = sizeof(struct srvsvc_SHARE_INFO_1);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->share_info_1 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->share_info_1 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("ShareInfo1", dce, pdu, iov, offset, ctr->share_info_1,
                             PTR_UNIQUE, srvsvc_SHARE_INFO_1_carray_coder)) {
                return -1;
        }

        return 0;
}


/*
 * typedef struct _SHARE_INFO_2 {
 *       [string] wchar_t *netname;
 *       DWORD type;
 *       [string] wchar_t *remark;
 *       DWORD permissions;
 *       DWORD max_uses;
 *       DWORD current_users;
 *       [string] wchar_t *path;
 *       [string] wchar_t *passwd;
 * } SHARE_INFO_2, *PSHARE_INFO_2, *LPSHARE_INFO_2;
 */
int
srvsvc_SHARE_INFO_2_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        struct srvsvc_SHARE_INFO_2 *nsi2 = ptr;

        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset, &nsi2->netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Type", dce, pdu, iov, offset, &nsi2->type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Remark", dce, pdu, iov, offset, &nsi2->remark,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Permissions", dce, pdu, iov, offset, &nsi2->permissions)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MaxUsers", dce, pdu, iov, offset, &nsi2->max_users)) {
                return -1;
        }
        if (dcerpc_uint32_coder("CurrentUsers", dce, pdu, iov, offset, &nsi2->current_users)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Path", dce, pdu, iov, offset, &nsi2->path,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Passwd", dce, pdu, iov, offset, &nsi2->passwd,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SHARE_INFO_2_STRUCT_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_2_coder);
}

/*
 *       [size_is(EntriesRead)] LPSHARE_INFO_2 Buffer;
 */
static int
srvsvc_SHARE_INFO_2_carray_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        return dcerpc_carray_coder("ShareInfo2", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SHARE_INFO_2),
                                   srvsvc_SHARE_INFO_2_STRUCT_coder);
}

/*
 * typedef struct _SHARE_INFO_2_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPSHARE_INFO_2 Buffer;
 * } SHARE_INFO_2_CONTAINER;
*/
int
srvsvc_SHARE_INFO_2_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        struct srvsvc_SHARE_INFO_2_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }                
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->share_info_2 == NULL) {
                        size_t esize = sizeof(struct srvsvc_SHARE_INFO_2);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->share_info_2 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->share_info_2 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("ShareInfo2", dce, pdu, iov, offset, ctr->share_info_2,
                             PTR_UNIQUE, srvsvc_SHARE_INFO_2_carray_coder)) {
                return -1;
        }

        return 0;
}


/*
 * typedef [switch_type(DWORD)] union _SHARE_ENUM_UNION {
 * [case(0)] SHARE_INFO_0_CONTAINER* Level0;
 * [case(1)] SHARE_INFO_1_CONTAINER* Level1;
 * [case(2)] SHARE_INFO_2_CONTAINER* Level2;
 * [case(501)] SHARE_INFO_501_CONTAINER* Level501;
 * [case(502)] SHARE_INFO_502_CONTAINER* Level502;
 * [case(503)] SHARE_INFO_503_CONTAINER* Level503;
 * } SHARE_ENUM_UNION;
 */
static int
srvsvc_SHARE_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        union srvsvc_SHARE_ENUM_UNION *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                if (dcerpc_ptr_coder("ShareInfo0Container", dce, pdu, iov, offset, &info->Level0,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_0_CONTAINER_coder)) {
                        return -1;
                }
                break;
        case 1:
                if (dcerpc_ptr_coder("ShareInfo1Container", dce, pdu, iov, offset, &info->Level1,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_1_CONTAINER_coder)) {
                        return -1;
                }
                break;
        case 2:
                if (dcerpc_ptr_coder("ShareInfo2Container", dce, pdu, iov, offset, &info->Level2,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_2_CONTAINER_coder)) {
                        return -1;
                }
                break;
        default:
                return -1;
        };

        return 0;
}

/*
 * typedef struct _SHARE_ENUM_STRUCT {
 *       DWORD Level;
 *       [switch_is(Level)] SHARE_ENUM_UNION ShareInfo;
 * } SHARE_ENUM_STRUCT, *PSHARE_ENUM_STRUCT, *LPSHARE_ENUM_STRUCT;
 */
int
srvsvc_SHARE_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_SHARE_ENUM_STRUCT *ses = ptr;

        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &ses->Level)) {
                return -1;
        }

        if (dcerpc_union_coder("ShareInfo", dce, pdu, iov, offset,
                               &ses->Level, &ses->ShareEnum,
                               srvsvc_SHARE_ENUM_UNION_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_ENUM_STRUCT_struct_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_ENUM_STRUCT_coder);
}


/*
 * typedef [switch_type(unsigned long)] union _SHARE_INFO {
 *   [case(0)] LPSHARE_INFO_0 ShareInfo0;
 *   [case(1)] LPSHARE_INFO_1 ShareInfo1;
 *   [case(2)] LPSHARE_INFO_2 ShareInfo2;
 *   [case(502)] LPSHARE_INFO_502_I ShareInfo502;
 *   [case(1004)] LPSHARE_INFO_1004 ShareInfo1004;
 *   [case(1006)] LPSHARE_INFO_1006 ShareInfo1006;
 *   [case(1501)] LPSHARE_INFO_1501_I ShareInfo1501;
 *   [default];
 *   [case(1005)] LPSHARE_INFO_1005 ShareInfo1005;
 *   [case(501)] LPSHARE_INFO_501 ShareInfo501;
 *   [case(503)] LPSHARE_INFO_503_I ShareInfo503;
 * } SHARE_INFO, *PSHARE_INFO, *LPSHARE_INFO;
 */
static int
srvsvc_SHARE_INFO_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct smb2_iovec *iov, int *offset,
                        void *ptr)
{
        union srvsvc_SHARE_INFO *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                if (dcerpc_ptr_coder("ShareInfo0", dce, pdu, iov, offset, &info->ShareInfo0,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_0_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 1:
                if (dcerpc_ptr_coder("ShareInfo1", dce, pdu, iov, offset, &info->ShareInfo1,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_1_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 2:
                if (dcerpc_ptr_coder("ShareInfo2", dce, pdu, iov, offset, &info->ShareInfo2,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_2_STRUCT_coder)) {
                        return -1;
                }
                break;
        default:
                return -1;
        };

        return 0;
}

static int
srvsvc_SHARE_INFO_STRUCT_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        uint32_t Level = dcerpc_get_switch_is(pdu);

        if (dcerpc_union_coder("InfoStruct", dce, pdu, iov, offset,
                               &Level, ptr,
                               srvsvc_SHARE_INFO_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _SERVER_INFO_100 {
 *   DWORD sv100_platform_id;
 *  [string] wchar_t* sv100_name;
 * } SERVER_INFO_100, *PSERVER_INFO_100, *LPSERVER_INFO_100;
 */
int
srvsvc_SERVER_INFO_100_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SERVER_INFO_100 *si100 = ptr;

        if (dcerpc_uint32_coder("Platform_Id", dce, pdu, iov, offset, &si100->platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Name", dce, pdu, iov, offset, &si100->name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SERVER_INFO_100_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        return  dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                    srvsvc_SERVER_INFO_100_coder);
}


/*
 * typedef struct _SERVER_INFO_101 {
 *   DWORD sv101_platform_id;
 *   [string] wchar_t* sv101_name;
 *   DWORD sv101_version_major;
 *   DWORD sv101_version_minor;
 *   DWORD sv101_type;
 *   [string] wchar_t * sv101_comment;
 * } SERVER_INFO_101, *PSERVER_INFO_101, *LPSERVER_INFO_101;
 */
int
srvsvc_SERVER_INFO_101_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SERVER_INFO_101 *si101 = ptr;

        if (dcerpc_uint32_coder("Platform_Id", dce, pdu, iov, offset, &si101->platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Name", dce, pdu, iov, offset, &si101->name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Major", dce, pdu, iov, offset, &si101->version_major)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Minor", dce, pdu, iov, offset, &si101->version_minor)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Type", dce, pdu, iov, offset, &si101->type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Comment", dce, pdu, iov, offset, &si101->comment,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SERVER_INFO_101_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        return  dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                    srvsvc_SERVER_INFO_101_coder);
}

/*
 * typedef struct _SERVER_INFO_102 {
 *    DWORD sv102_platform_id;
 *    [string] wchar_t * sv102_name;
 *    DWORD sv102_version_major;
 *    DWORD sv102_version_minor;
 *    DWORD sv102_type;
 *    [string] wchar_t * sv102_comment;
 *    DWORD sv102_users;
 *    long sv102_disc;
 *    int sv102_hidden;
 *    DWORD sv102_announce;
 *    DWORD sv102_anndelta;
 *    DWORD sv102_licenses;
 *    [string] wchar_t * sv102_userpath;
 *    } SERVER_INFO_102, *PSERVER_INFO_102, *LPSERVER_INFO_102;
 */
int
srvsvc_SERVER_INFO_102_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SERVER_INFO_102 *si102 = ptr;

        if (dcerpc_uint32_coder("Platform_Id", dce, pdu, iov, offset, &si102->platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Name", dce, pdu, iov, offset, &si102->name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Major", dce, pdu, iov, offset, &si102->version_major)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Minor", dce, pdu, iov, offset, &si102->version_minor)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Type", dce, pdu, iov, offset, &si102->type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Comment", dce, pdu, iov, offset, &si102->comment,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Users", dce, pdu, iov, offset, &si102->users)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Disc", dce, pdu, iov, offset, &si102->disc)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Hidden", dce, pdu, iov, offset, &si102->hidden)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Announce", dce, pdu, iov, offset, &si102->announce)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Anndelta", dce, pdu, iov, offset, &si102->anndelta)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Licenses", dce, pdu, iov, offset, &si102->licenses)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserPath", dce, pdu, iov, offset, &si102->userpath,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SERVER_INFO_102_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        return  dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                    srvsvc_SERVER_INFO_102_coder);
}

/*
 * typedef struct _SERVER_INFO_103 {
 *    DWORD sv103_platform_id;
 *    [string] wchar_t * sv103_name;
 *    DWORD sv103_version_major;
 *    DWORD sv103_version_minor;
 *    DWORD sv103_type;
 *    [string] wchar_t * sv103_comment;
 *    DWORD sv103_users;
 *    long sv103_disc;
 *    int sv103_hidden;
 *    DWORD sv103_announce;
 *    DWORD sv103_anndelta;
 *    DWORD sv103_licenses;
 *    [string] wchar_t * sv103_userpath;
 *    DWORD sv103_capabilities;
 *    } SERVER_INFO_103, *PSERVER_INFO_103, *LPSERVER_INFO_103;
 */
int
srvsvc_SERVER_INFO_103_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SERVER_INFO_103 *si103 = ptr;

        if (dcerpc_uint32_coder("Platform_Id", dce, pdu, iov, offset, &si103->platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Name", dce, pdu, iov, offset, &si103->name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Major", dce, pdu, iov, offset, &si103->version_major)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Minor", dce, pdu, iov, offset, &si103->version_minor)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Type", dce, pdu, iov, offset, &si103->type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Comment", dce, pdu, iov, offset, &si103->comment,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Users", dce, pdu, iov, offset, &si103->users)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Disc", dce, pdu, iov, offset, &si103->disc)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Hidden", dce, pdu, iov, offset, &si103->hidden)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Announce", dce, pdu, iov, offset, &si103->announce)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Anndelta", dce, pdu, iov, offset, &si103->anndelta)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Licenses", dce, pdu, iov, offset, &si103->licenses)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserPath", dce, pdu, iov, offset, &si103->userpath,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Capabilities", dce, pdu, iov, offset, &si103->capabilities)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SERVER_INFO_103_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        return  dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                    srvsvc_SERVER_INFO_103_coder);
}

/*
 * typedef struct _SERVER_INFO_502 {
 *   DWORD sv502_sessopens;
 *   DWORD sv502_sessvcs;
 *   DWORD sv502_opensearch;
 *   DWORD sv502_sizreqbuf;
 *   DWORD sv502_initworkitems;
 *   DWORD sv502_maxworkitems;
 *   DWORD sv502_rawworkitems;
 *   DWORD sv502_irpstacksize;
 *   DWORD sv502_maxrawbuflen;
 *   DWORD sv502_sessusers;
 *   DWORD sv502_sessconns;
 *   DWORD sv502_maxpagedmemoryusage;
 *   DWORD sv502_maxnonpagedmemoryusage;
 *   int sv502_enablesoftcompat;
 *   int sv502_enableforcedlogoff;
 *   int sv502_timesource;
 *   int sv502_acceptdownlevelapis;
 *   int sv502_lmannounce;
 * } SERVER_INFO_502, *PSERVER_INFO_502, *LPSERVER_INFO_502;
 */
int
srvsvc_SERVER_INFO_502_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SERVER_INFO_502 *si502 = ptr;

        if (dcerpc_uint32_coder("sessopens", dce, pdu, iov, offset, &si502->sessopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sessvcs", dce, pdu, iov, offset, &si502->sessvcs)) {
                return -1;
        }
        if (dcerpc_uint32_coder("opensearch", dce, pdu, iov, offset, &si502->opensearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sizreqbuf", dce, pdu, iov, offset, &si502->sizreqbuf)) {
                return -1;
        }
        if (dcerpc_uint32_coder("initworkitems", dce, pdu, iov, offset, &si502->initworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxworkitems", dce, pdu, iov, offset, &si502->maxworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("rawworkitems", dce, pdu, iov, offset, &si502->rawworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("irpstacksize", dce, pdu, iov, offset, &si502->irpstacksize)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxrawbuflen", dce, pdu, iov, offset, &si502->maxrawbuflen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sessusers", dce, pdu, iov, offset, &si502->sessusers)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sessconns", dce, pdu, iov, offset, &si502->sessconns)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxpagedmemoryusage", dce, pdu, iov, offset, &si502->maxpagedmemoryusage)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxnonpagedmemoryusage", dce, pdu, iov, offset, &si502->maxnonpagedmemoryusage)) {
                return -1;
        }
        if (dcerpc_uint32_coder("enablesoftcompat", dce, pdu, iov, offset, &si502->enablesoftcompat)) {
                return -1;
        }
        if (dcerpc_uint32_coder("enableforcedlogoff", dce, pdu, iov, offset, &si502->enableforcedlogoff)) {
                return -1;
        }
        if (dcerpc_uint32_coder("timesource", dce, pdu, iov, offset, &si502->timesource)) {
                return -1;
        }
        if (dcerpc_uint32_coder("acceptdownlevelapis", dce, pdu, iov, offset, &si502->acceptdownlevelapis)) {
                return -1;
        }
        if (dcerpc_uint32_coder("lmannounce", dce, pdu, iov, offset, &si502->lmannounce)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SERVER_INFO_502_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        return  dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                    srvsvc_SERVER_INFO_502_coder);
}

/*
 * typedef struct _SERVER_INFO_503 {
 *   DWORD sv503_sessopens;
 *   DWORD sv503_sessvcs;
 *   DWORD sv503_opensearch;
 *   DWORD sv503_sizreqbuf;
 *   DWORD sv503_initworkitems;
 *   DWORD sv503_maxworkitems;
 *   DWORD sv503_rawworkitems;
 *   DWORD sv503_irpstacksize;
 *   DWORD sv503_maxrawbuflen;
 *   DWORD sv503_sessusers;
 *   DWORD sv503_sessconns;
 *   DWORD sv503_maxpagedmemoryusage;
 *   DWORD sv503_maxnonpagedmemoryusage;
 *   int sv503_enablesoftcompat;
 *   int sv503_enableforcedlogoff;
 *   int sv503_timesource;
 *   int sv503_acceptdownlevelapis;
 *   int sv503_lmannounce;
 *   [string] wchar_t* sv503_domain;
 *   DWORD sv503_maxcopyreadlen;
 *   DWORD sv503_maxcopywritelen;
 *   DWORD sv503_minkeepsearch;
 *   DWORD sv503_maxkeepsearch;
 *   DWORD sv503_minkeepcomplsearch;
 *   DWORD sv503_maxkeepcomplsearch;
 *   DWORD sv503_threadcountadd;
 *   DWORD sv503_numblockthreads;
 *   DWORD sv503_scavtimeout;
 *   DWORD sv503_minrcvqueue;
 *   DWORD sv503_minfreeworkitems;
 *   DWORD sv503_xactmemsize;
 *   DWORD sv503_threadpriority;
 *   DWORD sv503_maxmpxct;
 *   DWORD sv503_oplockbreakwait;
 *   DWORD sv503_oplockbreakresponsewait;
 *   int sv503_enableoplocks;
 *   int sv503_enableoplockforceclose;
 *   int sv503_enablefcbopens;
 *   int sv503_enableraw;
 *   int sv503_enablesharednetdrives;
 *   DWORD sv503_minfreeconnections;
 *   DWORD sv503_maxfreeconnections;
 * } SERVER_INFO_503, *PSERVER_INFO_503, *LPSERVER_INFO_503;
 */
int
srvsvc_SERVER_INFO_503_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SERVER_INFO_503 *si503 = ptr;

        if (dcerpc_uint32_coder("sessopens", dce, pdu, iov, offset, &si503->sessopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sessvcs", dce, pdu, iov, offset, &si503->sessvcs)) {
                return -1;
        }
        if (dcerpc_uint32_coder("opensearch", dce, pdu, iov, offset, &si503->opensearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sizreqbuf", dce, pdu, iov, offset, &si503->sizreqbuf)) {
                return -1;
        }
        if (dcerpc_uint32_coder("initworkitems", dce, pdu, iov, offset, &si503->initworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxworkitems", dce, pdu, iov, offset, &si503->maxworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("rawworkitems", dce, pdu, iov, offset, &si503->rawworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("irpstacksize", dce, pdu, iov, offset, &si503->irpstacksize)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxrawbuflen", dce, pdu, iov, offset, &si503->maxrawbuflen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sessusers", dce, pdu, iov, offset, &si503->sessusers)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sessconns", dce, pdu, iov, offset, &si503->sessconns)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxpagedmemoryusage", dce, pdu, iov, offset, &si503->maxpagedmemoryusage)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxnonpagedmemoryusage", dce, pdu, iov, offset, &si503->maxnonpagedmemoryusage)) {
                return -1;
        }
        if (dcerpc_uint32_coder("enablesoftcompat", dce, pdu, iov, offset, &si503->enablesoftcompat)) {
                return -1;
        }
        if (dcerpc_uint32_coder("enableforcedlogoff", dce, pdu, iov, offset, &si503->enableforcedlogoff)) {
                return -1;
        }
        if (dcerpc_uint32_coder("timesource", dce, pdu, iov, offset, &si503->timesource)) {
                return -1;
        }
        if (dcerpc_uint32_coder("acceptdownlevelapis", dce, pdu, iov, offset, &si503->acceptdownlevelapis)) {
                return -1;
        }
        if (dcerpc_uint32_coder("lmannounce", dce, pdu, iov, offset, &si503->lmannounce)) {
                return -1;
        }
        if (dcerpc_ptr_coder("domain", dce, pdu, iov, offset, &si503->domain,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxcopyreadlen", dce, pdu, iov, offset, &si503->maxcopyreadlen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxcopywritelen", dce, pdu, iov, offset, &si503->maxcopywritelen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("minkeepsearch", dce, pdu, iov, offset, &si503->minkeepsearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxkeepsearch", dce, pdu, iov, offset, &si503->maxkeepsearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("minkeepcomplsearch", dce, pdu, iov, offset, &si503->minkeepcomplsearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxkeepcomplsearch", dce, pdu, iov, offset, &si503->maxkeepcomplsearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("threadcountadd", dce, pdu, iov, offset, &si503->threadcountadd)) {
                return -1;
        }
        if (dcerpc_uint32_coder("numblockthreads", dce, pdu, iov, offset, &si503->numblockthreads)) {
                return -1;
        }
        if (dcerpc_uint32_coder("scavtimeout", dce, pdu, iov, offset, &si503->scavtimeout)) {
                return -1;
        }
        if (dcerpc_uint32_coder("minrcvqueue", dce, pdu, iov, offset, &si503->minrcvqueue)) {
                return -1;
        }
        if (dcerpc_uint32_coder("minfreeworkitems", dce, pdu, iov, offset, &si503->minfreeworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("xactmemsize", dce, pdu, iov, offset, &si503->xactmemsize)) {
                return -1;
        }
        if (dcerpc_uint32_coder("threadpriority", dce, pdu, iov, offset, &si503->threadpriority)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxmpxct", dce, pdu, iov, offset, &si503->maxmpxct)) {
                return -1;
        }
        if (dcerpc_uint32_coder("oplockbreakwait", dce, pdu, iov, offset, &si503->oplockbreakwait)) {
                return -1;
        }
        if (dcerpc_uint32_coder("oplockbreakresponsewait", dce, pdu, iov, offset, &si503->oplockbreakresponsewait)) {
                return -1;
        }
        if (dcerpc_uint32_coder("enableoplocks", dce, pdu, iov, offset, &si503->enableoplocks)) {
                return -1;
        }
        if (dcerpc_uint32_coder("enableoplockforceclose", dce, pdu, iov, offset, &si503->enableoplockforceclose)) {
                return -1;
        }
        if (dcerpc_uint32_coder("enablefcbopens", dce, pdu, iov, offset, &si503->enablefcbopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("enableraw", dce, pdu, iov, offset, &si503->enableraw)) {
                return -1;
        }
        if (dcerpc_uint32_coder("enablesharednetdrives", dce, pdu, iov, offset, &si503->enablesharednetdrives)) {
                return -1;
        }
        if (dcerpc_uint32_coder("minfreeconnections", dce, pdu, iov, offset, &si503->minfreeconnections)) {
                return -1;
        }
        if (dcerpc_uint32_coder("maxfreeconnections", dce, pdu, iov, offset, &si503->maxfreeconnections)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SERVER_INFO_503_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        return  dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                    srvsvc_SERVER_INFO_503_coder);
}

/*
 * typedef [switch_type(unsigned long)] union _SERVER_INFO {
 *   [case(100)]  LPSERVER_INFO_100 ServerInfo100;
 *   [case(101)]  LPSERVER_INFO_101 ServerInfo101;
 *   [case(102)]  LPSERVER_INFO_102 ServerInfo102;
 *   [case(103)]  LPSERVER_INFO_103 ServerInfo103;
 *   [case(502)]  LPSERVER_INFO_502 ServerInfo502;
 *   [case(503)]  LPSERVER_INFO_503 ServerInfo503;
 *   [case(599)]  LPSERVER_INFO_599 ServerInfo599;
 *   [case(1005)] LPSERVER_INFO_1005 ServerInfo1005;
 *   [case(1107)] LPSERVER_INFO_1107 ServerInfo1107;
 *   [case(1010)] LPSERVER_INFO_1010 ServerInfo1010;
 *   [case(1016)] LPSERVER_INFO_1016 ServerInfo1016;
 *   [case(1017)] LPSERVER_INFO_1017 ServerInfo1017;
 *   [case(1018)] LPSERVER_INFO_1018 ServerInfo1018;
 *   [case(1501)] LPSERVER_INFO_1501 ServerInfo1501;
 *   [case(1502)] LPSERVER_INFO_1502 ServerInfo1502;
 *   [case(1503)] LPSERVER_INFO_1503 ServerInfo1503;
 *   [case(1506)] LPSERVER_INFO_1506 ServerInfo1506;
 *   [case(1510)] LPSERVER_INFO_1510 ServerInfo1510;
 *   [case(1511)] LPSERVER_INFO_1511 ServerInfo1511;
 *   [case(1512)] LPSERVER_INFO_1512 ServerInfo1512;
 *   [case(1513)] LPSERVER_INFO_1513 ServerInfo1513;
 *   [case(1514)] LPSERVER_INFO_1514 ServerInfo1514;
 *   [case(1515)] LPSERVER_INFO_1515 ServerInfo1515;
 *   [case(1516)] LPSERVER_INFO_1516 ServerInfo1516;
 *   [case(1518)] LPSERVER_INFO_1518 ServerInfo1518;
 *   [case(1523)] LPSERVER_INFO_1523 ServerInfo1523;
 *   [case(1528)] LPSERVER_INFO_1528 ServerInfo1528;
 *   [case(1529)] LPSERVER_INFO_1529 ServerInfo1529;
 *   [case(1530)] LPSERVER_INFO_1530 ServerInfo1530;
 *   [case(1533)] LPSERVER_INFO_1533 ServerInfo1533;
 *   [case(1534)] LPSERVER_INFO_1534 ServerInfo1534;
 *   [case(1535)] LPSERVER_INFO_1535 ServerInfo1535;
 *   [case(1536)] LPSERVER_INFO_1536 ServerInfo1536;
 *   [case(1538)] LPSERVER_INFO_1538 ServerInfo1538;
 *   [case(1539)] LPSERVER_INFO_1539 ServerInfo1539;
 *   [case(1540)] LPSERVER_INFO_1540 ServerInfo1540;
 *   [case(1541)] LPSERVER_INFO_1541 ServerInfo1541;
 *   [case(1542)] LPSERVER_INFO_1542 ServerInfo1542;
 *   [case(1543)] LPSERVER_INFO_1543 ServerInfo1543;
 *   [case(1544)] LPSERVER_INFO_1544 ServerInfo1544;
 *   [case(1545)] LPSERVER_INFO_1545 ServerInfo1545;
 *   [case(1546)] LPSERVER_INFO_1546 ServerInfo1546;
 *   [case(1547)] LPSERVER_INFO_1547 ServerInfo1547;
 *   [case(1548)] LPSERVER_INFO_1548 ServerInfo1548;
 *   [case(1549)] LPSERVER_INFO_1549 ServerInfo1549;
 *   [case(1550)] LPSERVER_INFO_1550 ServerInfo1550;
 *   [case(1552)] LPSERVER_INFO_1552 ServerInfo1552;
 *   [case(1553)] LPSERVER_INFO_1553 ServerInfo1553;
 *   [case(1554)] LPSERVER_INFO_1554 ServerInfo1554;
 *   [case(1555)] LPSERVER_INFO_1555 ServerInfo1555;
 *   [case(1556)] LPSERVER_INFO_1556 ServerInfo1556;
 * } SERVER_INFO, *PSERVER_INFO, *LPSERVER_INFO;
 */
static int
srvsvc_SERVER_INFO_coder(char *name, struct dcerpc_context *dce,
                         struct dcerpc_pdu *pdu,
                         struct smb2_iovec *iov, int *offset,
                         void *ptr)
{
        union srvsvc_SERVER_INFO *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 100:
                if (dcerpc_ptr_coder("ServerInfo100", dce, pdu, iov, offset, &info->ServerInfo100,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_100_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 101:
                if (dcerpc_ptr_coder("ServerInfo101", dce, pdu, iov, offset, &info->ServerInfo101,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_101_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 102:
                if (dcerpc_ptr_coder("ServerInfo102", dce, pdu, iov, offset, &info->ServerInfo102,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_102_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 103:
                if (dcerpc_ptr_coder("ServerInfo103", dce, pdu, iov, offset, &info->ServerInfo103,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_103_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 502:
                if (dcerpc_ptr_coder("ServerInfo502", dce, pdu, iov, offset, &info->ServerInfo502,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_502_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 503:
                if (dcerpc_ptr_coder("ServerInfo503", dce, pdu, iov, offset, &info->ServerInfo503,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_503_STRUCT_coder)) {
                        return -1;
                }
                break;
        default:
                return -1;
        };

        return 0;
}

static int
srvsvc_SERVER_INFO_STRUCT_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        uint32_t Level = dcerpc_get_switch_is(pdu);

        if (dcerpc_union_coder("InfoStruct", dce, pdu, iov, offset,
                               &Level, ptr,
                               srvsvc_SERVER_INFO_coder)) {
                return -1;
        }
        return 0;
}

/*
 * typedef struct _CONNECTION_INFO_0 {
 *       DWORD coni0_id;
 * } CONNECTION_INFO_0, *PCONNECTION_INFO_0, *LPCONNECTION_INFO_0;
 */
int
srvsvc_CONNECTION_INFO_0_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_CONNECTION_INFO_0 *ci = ptr;

        if (dcerpc_uint32_coder("Id", dce, pdu, iov, offset, &ci->id)) {
                return -1;
        }
        return 0;
}

int
srvsvc_CONNECTION_INFO_0_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_CONNECTION_INFO_0_coder);
}

/*
 *       [size_is(EntriesRead)] LPCONNECTION_INFO_0 Buffer;
 */
static int
srvsvc_CONNECTION_INFO_0_carray_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr)
{
        return dcerpc_carray_coder("ConnectionInfo0", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_CONNECTION_INFO_0),
                                   srvsvc_CONNECTION_INFO_0_coder);
}

/*
 * typedef struct _CONNECT_INFO_0_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPCONNECTION_INFO_0 Buffer;
 * } CONNECT_INFO_0_CONTAINER;
 */
int
srvsvc_CONNECT_INFO_0_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr)
{
        struct srvsvc_CONNECT_INFO_0_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->connection_info_0 == NULL) {
                        size_t esize = sizeof(struct srvsvc_CONNECTION_INFO_0);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->connection_info_0 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->connection_info_0 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("ConnectionInfo0", dce, pdu, iov, offset, ctr->connection_info_0,
                             PTR_UNIQUE, srvsvc_CONNECTION_INFO_0_carray_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _CONNECTION_INFO_1 {
 *       DWORD coni1_id;
 *       DWORD coni1_type;
 *       DWORD coni1_num_opens;
 *       DWORD coni1_num_users;
 *       DWORD coni1_time;
 *       [string] wchar_t *coni1_username;
 *       [string] wchar_t *coni1_netname;
 * } CONNECTION_INFO_1, *PCONNECTION_INFO_1, *LPCONNECTION_INFO_1;
 */
int
srvsvc_CONNECTION_INFO_1_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_CONNECTION_INFO_1 *ci = ptr;

        if (dcerpc_uint32_coder("Id", dce, pdu, iov, offset, &ci->id)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Type", dce, pdu, iov, offset, &ci->type)) {
                return -1;
        }
        if (dcerpc_uint32_coder("NumOpens", dce, pdu, iov, offset, &ci->num_opens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("NumUsers", dce, pdu, iov, offset, &ci->num_users)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Time", dce, pdu, iov, offset, &ci->time)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, &ci->username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset, &ci->netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_CONNECTION_INFO_1_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_CONNECTION_INFO_1_coder);
}

/*
 *       [size_is(EntriesRead)] LPCONNECTION_INFO_1 Buffer;
 */
static int
srvsvc_CONNECTION_INFO_1_carray_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr)
{
        return dcerpc_carray_coder("ConnectionInfo1", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_CONNECTION_INFO_1),
                                   srvsvc_CONNECTION_INFO_1_STRUCT_coder);
}

/*
 * typedef struct _CONNECT_INFO_1_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPCONNECTION_INFO_1 Buffer;
 * } CONNECT_INFO_1_CONTAINER;
 */
int
srvsvc_CONNECT_INFO_1_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr)
{
        struct srvsvc_CONNECT_INFO_1_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->connection_info_1 == NULL) {
                        size_t esize = sizeof(struct srvsvc_CONNECTION_INFO_1);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->connection_info_1 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->connection_info_1 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("ConnectionInfo1", dce, pdu, iov, offset, ctr->connection_info_1,
                             PTR_UNIQUE, srvsvc_CONNECTION_INFO_1_carray_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef [switch_type(DWORD)] union _CONNECT_ENUM_UNION {
 * [case(0)] CONNECT_INFO_0_CONTAINER* Level0;
 * [case(1)] CONNECT_INFO_1_CONTAINER* Level1;
 * } CONNECT_ENUM_UNION;
 */
static int
srvsvc_CONNECT_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        union srvsvc_CONNECT_ENUM_UNION *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                if (dcerpc_ptr_coder("ConnectInfo0Container", dce, pdu, iov, offset, &info->Level0,
                                     PTR_UNIQUE, srvsvc_CONNECT_INFO_0_CONTAINER_coder)) {
                        return -1;
                }
                break;
        case 1:
                if (dcerpc_ptr_coder("ConnectInfo1Container", dce, pdu, iov, offset, &info->Level1,
                                     PTR_UNIQUE, srvsvc_CONNECT_INFO_1_CONTAINER_coder)) {
                        return -1;
                }
                break;
        default:
                return -1;
        };

        return 0;
}

/*
 * typedef struct _CONNECT_ENUM_STRUCT {
 *       DWORD Level;
 *       [switch_is(Level)] CONNECT_ENUM_UNION ConnectInfo;
 * } CONNECT_ENUM_STRUCT, *PCONNECT_ENUM_STRUCT, *LPCONNECT_ENUM_STRUCT;
 */
int
srvsvc_CONNECT_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        struct srvsvc_CONNECT_ENUM_STRUCT *ces = ptr;

        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &ces->Level)) {
                return -1;
        }

        if (dcerpc_union_coder("ConnectInfo", dce, pdu, iov, offset,
                               &ces->Level, &ces->ConnectEnum,
                               srvsvc_CONNECT_ENUM_UNION_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_CONNECT_ENUM_STRUCT_struct_coder(char *name, struct dcerpc_context *dce,
                                        struct dcerpc_pdu *pdu,
                                        struct smb2_iovec *iov, int *offset,
                                        void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_CONNECT_ENUM_STRUCT_coder);
}

/*****************
 * Function: 0x08
 * NET_API_STATUS NetrConnectionEnum (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in,string,unique] WCHAR * Qualifier,
 *   [in,out] LPCONNECT_ENUM_STRUCT InfoStruct,
 *   [in] DWORD PreferedMaximumLength,
 *   [out] DWORD * TotalEntries,
 *   [in,out,unique] DWORD * ResumeHandle
 * );
 */
int
srvsvc_NetrConnectionEnum_req_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        struct srvsvc_NetrConnectionEnum_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Qualifier", dce, pdu, iov, offset, &req->Qualifier,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->ces,
                             PTR_REF, srvsvc_CONNECT_ENUM_STRUCT_struct_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("PreferedMaximumLength", dce, pdu, iov, offset, &req->PreferedMaximumLength,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &req->ResumeHandle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrConnectionEnum_rep_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        struct srvsvc_NetrConnectionEnum_rep *rep = ptr;

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->ces,
                             PTR_REF, srvsvc_CONNECT_ENUM_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TotalEntries", dce, pdu, iov, offset, &rep->total_entries,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &rep->resume_handle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _FILE_INFO_2 {
 *       DWORD fi2_id;
 * } FILE_INFO_2, *PFILE_INFO_2, *LPFILE_INFO_2;
 */
int
srvsvc_FILE_INFO_2_coder(char *name, struct dcerpc_context *dce,
                         struct dcerpc_pdu *pdu,
                         struct smb2_iovec *iov, int *offset,
                         void *ptr)
{
        struct srvsvc_FILE_INFO_2 *fi = ptr;

        if (dcerpc_uint32_coder("Id", dce, pdu, iov, offset, &fi->id)) {
                return -1;
        }
        return 0;
}

int
srvsvc_FILE_INFO_2_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_FILE_INFO_2_coder);
}

/*
 *       [size_is(EntriesRead)] LPFILE_INFO_2 Buffer;
 */
static int
srvsvc_FILE_INFO_2_carray_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        return dcerpc_carray_coder("FileInfo2", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_FILE_INFO_2),
                                   srvsvc_FILE_INFO_2_coder);
}

/*
 * typedef struct _FILE_INFO_2_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPFILE_INFO_2 Buffer;
 * } FILE_INFO_2_CONTAINER;
 */
int
srvsvc_FILE_INFO_2_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        struct srvsvc_FILE_INFO_2_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->file_info_2 == NULL) {
                        size_t esize = sizeof(struct srvsvc_FILE_INFO_2);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->file_info_2 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->file_info_2 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("FileInfo2", dce, pdu, iov, offset, ctr->file_info_2,
                             PTR_UNIQUE, srvsvc_FILE_INFO_2_carray_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _FILE_INFO_3 {
 *       DWORD fi3_id;
 *       DWORD fi3_permissions;
 *       DWORD fi3_num_locks;
 *       [string] wchar_t *fi3_pathname;
 *       [string] wchar_t *fi3_username;
 * } FILE_INFO_3, *PFILE_INFO_3, *LPFILE_INFO_3;
 */
int
srvsvc_FILE_INFO_3_coder(char *name, struct dcerpc_context *dce,
                         struct dcerpc_pdu *pdu,
                         struct smb2_iovec *iov, int *offset,
                         void *ptr)
{
        struct srvsvc_FILE_INFO_3 *fi = ptr;

        if (dcerpc_uint32_coder("Id", dce, pdu, iov, offset, &fi->id)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Permissions", dce, pdu, iov, offset, &fi->permissions)) {
                return -1;
        }
        if (dcerpc_uint32_coder("NumLocks", dce, pdu, iov, offset, &fi->num_locks)) {
                return -1;
        }
        if (dcerpc_ptr_coder("PathName", dce, pdu, iov, offset, &fi->pathname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, &fi->username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_FILE_INFO_3_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_FILE_INFO_3_coder);
}

/*
 *       [size_is(EntriesRead)] LPFILE_INFO_3 Buffer;
 */
static int
srvsvc_FILE_INFO_3_carray_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        return dcerpc_carray_coder("FileInfo3", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_FILE_INFO_3),
                                   srvsvc_FILE_INFO_3_STRUCT_coder);
}

/*
 * typedef struct _FILE_INFO_3_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPFILE_INFO_3 Buffer;
 * } FILE_INFO_3_CONTAINER;
 */
int
srvsvc_FILE_INFO_3_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        struct srvsvc_FILE_INFO_3_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->file_info_3 == NULL) {
                        size_t esize = sizeof(struct srvsvc_FILE_INFO_3);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->file_info_3 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->file_info_3 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("FileInfo3", dce, pdu, iov, offset, ctr->file_info_3,
                             PTR_UNIQUE, srvsvc_FILE_INFO_3_carray_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef [switch_type(DWORD)] union _FILE_ENUM_UNION {
 * [case(2)] FILE_INFO_2_CONTAINER* Level2;
 * [case(3)] FILE_INFO_3_CONTAINER* Level3;
 * } FILE_ENUM_UNION;
 */
static int
srvsvc_FILE_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr)
{
        union srvsvc_FILE_ENUM_UNION *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 2:
                if (dcerpc_ptr_coder("FileInfo2Container", dce, pdu, iov, offset, &info->Level2,
                                     PTR_UNIQUE, srvsvc_FILE_INFO_2_CONTAINER_coder)) {
                        return -1;
                }
                break;
        case 3:
                if (dcerpc_ptr_coder("FileInfo3Container", dce, pdu, iov, offset, &info->Level3,
                                     PTR_UNIQUE, srvsvc_FILE_INFO_3_CONTAINER_coder)) {
                        return -1;
                }
                break;
        default:
                /*
                 * During the NDR conformance pass the discriminant is not
                 * read yet (switch_is stays 0). Levels for this union are
                 * only 2 and 3, so tolerate unknown switch on the CR pass.
                 */
                if (dcerpc_get_cr(pdu)) {
                        return 0;
                }
                return -1;
        };

        return 0;
}

/*
 * typedef struct _FILE_ENUM_STRUCT {
 *       DWORD Level;
 *       [switch_is(Level)] FILE_ENUM_UNION FileInfo;
 * } FILE_ENUM_STRUCT, *PFILE_ENUM_STRUCT, *LPFILE_ENUM_STRUCT;
 */
int
srvsvc_FILE_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        struct srvsvc_FILE_ENUM_STRUCT *fes = ptr;

        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &fes->Level)) {
                return -1;
        }

        if (dcerpc_union_coder("FileInfo", dce, pdu, iov, offset,
                               &fes->Level, &fes->FileInfo,
                               srvsvc_FILE_ENUM_UNION_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_FILE_ENUM_STRUCT_struct_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_FILE_ENUM_STRUCT_coder);
}

/*****************
 * Function: 0x09
 * NET_API_STATUS NetrFileEnum (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in,string,unique] WCHAR * BasePath,
 *   [in,string,unique] WCHAR * UserName,
 *   [in,out] PFILE_ENUM_STRUCT InfoStruct,
 *   [in] DWORD PreferedMaximumLength,
 *   [out] DWORD * TotalEntries,
 *   [in,out,unique] DWORD * ResumeHandle
 * );
 */
int
srvsvc_NetrFileEnum_req_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        struct srvsvc_NetrFileEnum_req *req = ptr;
        void *basepath_ptr = &req->BasePath;
        void *username_ptr = &req->UserName;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        /*
         * BasePath/UserName are [unique]. On encode, a NULL char* must be
         * sent as a null referent (not an empty string). On decode, always
         * pass the address of the char* so a non-null referent can be stored.
         */
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                if (req->BasePath == NULL) {
                        basepath_ptr = NULL;
                }
                if (req->UserName == NULL) {
                        username_ptr = NULL;
                }
        }
        if (dcerpc_ptr_coder("BasePath", dce, pdu, iov, offset, basepath_ptr,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, username_ptr,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->fes,
                             PTR_REF, srvsvc_FILE_ENUM_STRUCT_struct_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("PreferedMaximumLength", dce, pdu, iov, offset, &req->PreferedMaximumLength,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &req->ResumeHandle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrFileEnum_rep_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        struct srvsvc_NetrFileEnum_rep *rep = ptr;

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->fes,
                             PTR_REF, srvsvc_FILE_ENUM_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TotalEntries", dce, pdu, iov, offset, &rep->total_entries,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &rep->resume_handle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*
 * typedef [switch_type(unsigned long)] union _FILE_INFO {
 *   [case(2)] LPFILE_INFO_2 FileInfo2;
 *   [case(3)] LPFILE_INFO_3 FileInfo3;
 * } FILE_INFO, *PFILE_INFO, *LPFILE_INFO;
 */
static int
srvsvc_FILE_INFO_coder(char *name, struct dcerpc_context *dce,
                       struct dcerpc_pdu *pdu,
                       struct smb2_iovec *iov, int *offset,
                       void *ptr)
{
        union srvsvc_FILE_INFO *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 2:
                if (dcerpc_ptr_coder("FileInfo2", dce, pdu, iov, offset, &info->FileInfo2,
                                     PTR_UNIQUE, srvsvc_FILE_INFO_2_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 3:
                if (dcerpc_ptr_coder("FileInfo3", dce, pdu, iov, offset, &info->FileInfo3,
                                     PTR_UNIQUE, srvsvc_FILE_INFO_3_STRUCT_coder)) {
                        return -1;
                }
                break;
        default:
                if (dcerpc_get_cr(pdu)) {
                        return 0;
                }
                return -1;
        };

        return 0;
}

static int
srvsvc_FILE_INFO_STRUCT_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        uint32_t Level = dcerpc_get_switch_is(pdu);

        if (dcerpc_union_coder("InfoStruct", dce, pdu, iov, offset,
                               &Level, ptr,
                               srvsvc_FILE_INFO_coder)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x0a
 * NET_API_STATUS NetrFileGetInfo (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in] DWORD FileId,
 *   [in] DWORD Level,
 *   [out, switch_is(Level)] LPFILE_INFO InfoStruct
 * );
 */
int
srvsvc_NetrFileGetInfo_req_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        struct srvsvc_NetrFileGetInfo_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("FileId", dce, pdu, iov, offset, &req->FileId)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &req->Level)) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);

        return 0;
}

int
srvsvc_NetrFileGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        struct srvsvc_NetrFileGetInfo_rep *rep = ptr;
        /* There is no Level in the reply so we must reference it from the request */
        struct srvsvc_NetrFileGetInfo_req *req = dcerpc_get_request(pdu);

        dcerpc_set_switch_is(pdu, req->Level);

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_REF, srvsvc_FILE_INFO_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x0b
 * NET_API_STATUS NetrFileClose (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in] DWORD FileId
 * );
 */
int
srvsvc_NetrFileClose_req_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_NetrFileClose_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("FileId", dce, pdu, iov, offset, &req->FileId)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrFileClose_rep_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_NetrFileClose_rep *rep = ptr;

        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _SESSION_INFO_0 {
 *       [string] wchar_t *sesi0_cname;
 * } SESSION_INFO_0, *PSESSION_INFO_0, *LPSESSION_INFO_0;
 */
int
srvsvc_SESSION_INFO_0_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr)
{
        struct srvsvc_SESSION_INFO_0 *si = ptr;

        if (dcerpc_ptr_coder("CName", dce, pdu, iov, offset, &si->cname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SESSION_INFO_0_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_0_coder);
}

/*
 *       [size_is(EntriesRead)] LPSESSION_INFO_0 Buffer;
 */
static int
srvsvc_SESSION_INFO_0_carray_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        return dcerpc_carray_coder("SessionInfo0", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SESSION_INFO_0),
                                   srvsvc_SESSION_INFO_0_STRUCT_coder);
}

/*
 * typedef struct _SESSION_INFO_0_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPSESSION_INFO_0 Buffer;
 * } SESSION_INFO_0_CONTAINER;
 */
int
srvsvc_SESSION_INFO_0_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr)
{
        struct srvsvc_SESSION_INFO_0_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->session_info_0 == NULL) {
                        size_t esize = sizeof(struct srvsvc_SESSION_INFO_0);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->session_info_0 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->session_info_0 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("SessionInfo0", dce, pdu, iov, offset, ctr->session_info_0,
                             PTR_UNIQUE, srvsvc_SESSION_INFO_0_carray_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _SESSION_INFO_1 {
 *       [string] wchar_t *sesi1_cname;
 *       [string] wchar_t *sesi1_username;
 *       DWORD sesi1_num_opens;
 *       DWORD sesi1_time;
 *       DWORD sesi1_idle_time;
 *       DWORD sesi1_user_flags;
 * } SESSION_INFO_1, *PSESSION_INFO_1, *LPSESSION_INFO_1;
 */
int
srvsvc_SESSION_INFO_1_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr)
{
        struct srvsvc_SESSION_INFO_1 *si = ptr;

        if (dcerpc_ptr_coder("CName", dce, pdu, iov, offset, &si->cname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, &si->username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("NumOpens", dce, pdu, iov, offset, &si->num_opens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Time", dce, pdu, iov, offset, &si->time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("IdleTime", dce, pdu, iov, offset, &si->idle_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UserFlags", dce, pdu, iov, offset, &si->user_flags)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SESSION_INFO_1_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_1_coder);
}

/*
 *       [size_is(EntriesRead)] LPSESSION_INFO_1 Buffer;
 */
static int
srvsvc_SESSION_INFO_1_carray_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        return dcerpc_carray_coder("SessionInfo1", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SESSION_INFO_1),
                                   srvsvc_SESSION_INFO_1_STRUCT_coder);
}

/*
 * typedef struct _SESSION_INFO_1_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPSESSION_INFO_1 Buffer;
 * } SESSION_INFO_1_CONTAINER;
 */
int
srvsvc_SESSION_INFO_1_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr)
{
        struct srvsvc_SESSION_INFO_1_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->session_info_1 == NULL) {
                        size_t esize = sizeof(struct srvsvc_SESSION_INFO_1);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->session_info_1 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->session_info_1 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("SessionInfo1", dce, pdu, iov, offset, ctr->session_info_1,
                             PTR_UNIQUE, srvsvc_SESSION_INFO_1_carray_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _SESSION_INFO_2 {
 *       [string] wchar_t *sesi2_cname;
 *       [string] wchar_t *sesi2_username;
 *       DWORD sesi2_num_opens;
 *       DWORD sesi2_time;
 *       DWORD sesi2_idle_time;
 *       DWORD sesi2_user_flags;
 *       [string] wchar_t *sesi2_cltype_name;
 * } SESSION_INFO_2, *PSESSION_INFO_2, *LPSESSION_INFO_2;
 */
int
srvsvc_SESSION_INFO_2_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr)
{
        struct srvsvc_SESSION_INFO_2 *si = ptr;

        if (dcerpc_ptr_coder("CName", dce, pdu, iov, offset, &si->cname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, &si->username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("NumOpens", dce, pdu, iov, offset, &si->num_opens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Time", dce, pdu, iov, offset, &si->time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("IdleTime", dce, pdu, iov, offset, &si->idle_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UserFlags", dce, pdu, iov, offset, &si->user_flags)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ClTypeName", dce, pdu, iov, offset, &si->cltype_name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SESSION_INFO_2_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_2_coder);
}

/*
 *       [size_is(EntriesRead)] LPSESSION_INFO_2 Buffer;
 */
static int
srvsvc_SESSION_INFO_2_carray_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        return dcerpc_carray_coder("SessionInfo2", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SESSION_INFO_2),
                                   srvsvc_SESSION_INFO_2_STRUCT_coder);
}

/*
 * typedef struct _SESSION_INFO_2_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPSESSION_INFO_2 Buffer;
 * } SESSION_INFO_2_CONTAINER;
 */
int
srvsvc_SESSION_INFO_2_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr)
{
        struct srvsvc_SESSION_INFO_2_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->session_info_2 == NULL) {
                        size_t esize = sizeof(struct srvsvc_SESSION_INFO_2);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->session_info_2 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->session_info_2 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("SessionInfo2", dce, pdu, iov, offset, ctr->session_info_2,
                             PTR_UNIQUE, srvsvc_SESSION_INFO_2_carray_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _SESSION_INFO_10 {
 *       [string] wchar_t *sesi10_cname;
 *       [string] wchar_t *sesi10_username;
 *       DWORD sesi10_time;
 *       DWORD sesi10_idle_time;
 * } SESSION_INFO_10, *PSESSION_INFO_10, *LPSESSION_INFO_10;
 */
int
srvsvc_SESSION_INFO_10_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SESSION_INFO_10 *si = ptr;

        if (dcerpc_ptr_coder("CName", dce, pdu, iov, offset, &si->cname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, &si->username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Time", dce, pdu, iov, offset, &si->time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("IdleTime", dce, pdu, iov, offset, &si->idle_time)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SESSION_INFO_10_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_10_coder);
}

/*
 *       [size_is(EntriesRead)] LPSESSION_INFO_10 Buffer;
 */
static int
srvsvc_SESSION_INFO_10_carray_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        return dcerpc_carray_coder("SessionInfo10", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SESSION_INFO_10),
                                   srvsvc_SESSION_INFO_10_STRUCT_coder);
}

/*
 * typedef struct _SESSION_INFO_10_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPSESSION_INFO_10 Buffer;
 * } SESSION_INFO_10_CONTAINER;
 */
int
srvsvc_SESSION_INFO_10_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                       struct dcerpc_pdu *pdu,
                                       struct smb2_iovec *iov, int *offset,
                                       void *ptr)
{
        struct srvsvc_SESSION_INFO_10_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->session_info_10 == NULL) {
                        size_t esize = sizeof(struct srvsvc_SESSION_INFO_10);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->session_info_10 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->session_info_10 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("SessionInfo10", dce, pdu, iov, offset, ctr->session_info_10,
                             PTR_UNIQUE, srvsvc_SESSION_INFO_10_carray_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _SESSION_INFO_502 {
 *       [string] wchar_t *sesi502_cname;
 *       [string] wchar_t *sesi502_username;
 *       DWORD sesi502_num_opens;
 *       DWORD sesi502_time;
 *       DWORD sesi502_idle_time;
 *       DWORD sesi502_user_flags;
 *       [string] wchar_t *sesi502_cltype_name;
 *       [string] wchar_t *sesi502_transport;
 * } SESSION_INFO_502, *PSESSION_INFO_502, *LPSESSION_INFO_502;
 */
int
srvsvc_SESSION_INFO_502_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        struct srvsvc_SESSION_INFO_502 *si = ptr;

        if (dcerpc_ptr_coder("CName", dce, pdu, iov, offset, &si->cname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, &si->username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("NumOpens", dce, pdu, iov, offset, &si->num_opens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Time", dce, pdu, iov, offset, &si->time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("IdleTime", dce, pdu, iov, offset, &si->idle_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UserFlags", dce, pdu, iov, offset, &si->user_flags)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ClTypeName", dce, pdu, iov, offset, &si->cltype_name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Transport", dce, pdu, iov, offset, &si->transport,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SESSION_INFO_502_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_502_coder);
}

/*
 *       [size_is(EntriesRead)] LPSESSION_INFO_502 Buffer;
 */
static int
srvsvc_SESSION_INFO_502_carray_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr)
{
        return dcerpc_carray_coder("SessionInfo502", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SESSION_INFO_502),
                                   srvsvc_SESSION_INFO_502_STRUCT_coder);
}

/*
 * typedef struct _SESSION_INFO_502_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPSESSION_INFO_502 Buffer;
 * } SESSION_INFO_502_CONTAINER;
 */
int
srvsvc_SESSION_INFO_502_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                        struct dcerpc_pdu *pdu,
                                        struct smb2_iovec *iov, int *offset,
                                        void *ptr)
{
        struct srvsvc_SESSION_INFO_502_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->session_info_502 == NULL) {
                        size_t esize = sizeof(struct srvsvc_SESSION_INFO_502);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->session_info_502 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->session_info_502 == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("SessionInfo502", dce, pdu, iov, offset, ctr->session_info_502,
                             PTR_UNIQUE, srvsvc_SESSION_INFO_502_carray_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef [switch_type(DWORD)] union _SESSION_ENUM_UNION {
 * [case(0)] SESSION_INFO_0_CONTAINER* Level0;
 * [case(1)] SESSION_INFO_1_CONTAINER* Level1;
 * [case(2)] SESSION_INFO_2_CONTAINER* Level2;
 * [case(10)] SESSION_INFO_10_CONTAINER* Level10;
 * [case(502)] SESSION_INFO_502_CONTAINER* Level502;
 * } SESSION_ENUM_UNION;
 */
static int
srvsvc_SESSION_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        union srvsvc_SESSION_ENUM_UNION *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                if (dcerpc_ptr_coder("SessionInfo0Container", dce, pdu, iov, offset, &info->Level0,
                                     PTR_UNIQUE, srvsvc_SESSION_INFO_0_CONTAINER_coder)) {
                        return -1;
                }
                break;
        case 1:
                if (dcerpc_ptr_coder("SessionInfo1Container", dce, pdu, iov, offset, &info->Level1,
                                     PTR_UNIQUE, srvsvc_SESSION_INFO_1_CONTAINER_coder)) {
                        return -1;
                }
                break;
        case 2:
                if (dcerpc_ptr_coder("SessionInfo2Container", dce, pdu, iov, offset, &info->Level2,
                                     PTR_UNIQUE, srvsvc_SESSION_INFO_2_CONTAINER_coder)) {
                        return -1;
                }
                break;
        case 10:
                if (dcerpc_ptr_coder("SessionInfo10Container", dce, pdu, iov, offset, &info->Level10,
                                     PTR_UNIQUE, srvsvc_SESSION_INFO_10_CONTAINER_coder)) {
                        return -1;
                }
                break;
        case 502:
                if (dcerpc_ptr_coder("SessionInfo502Container", dce, pdu, iov, offset, &info->Level502,
                                     PTR_UNIQUE, srvsvc_SESSION_INFO_502_CONTAINER_coder)) {
                        return -1;
                }
                break;
        default:
                /*
                 * During the NDR conformance pass the discriminant is not
                 * read yet (switch_is stays 0). Levels include non-zero
                 * values (10, 502), so tolerate unknown switch on the CR pass.
                 */
                if (dcerpc_get_cr(pdu)) {
                        return 0;
                }
                return -1;
        };

        return 0;
}

/*
 * typedef struct _SESSION_ENUM_STRUCT {
 *       DWORD Level;
 *       [switch_is(Level)] SESSION_ENUM_UNION SessionInfo;
 * } SESSION_ENUM_STRUCT, *PSESSION_ENUM_STRUCT, *LPSESSION_ENUM_STRUCT;
 */
int
srvsvc_SESSION_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        struct srvsvc_SESSION_ENUM_STRUCT *ses = ptr;

        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &ses->Level)) {
                return -1;
        }

        if (dcerpc_union_coder("SessionInfo", dce, pdu, iov, offset,
                               &ses->Level, &ses->SessionInfo,
                               srvsvc_SESSION_ENUM_UNION_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_ENUM_STRUCT_struct_coder(char *name, struct dcerpc_context *dce,
                                        struct dcerpc_pdu *pdu,
                                        struct smb2_iovec *iov, int *offset,
                                        void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_ENUM_STRUCT_coder);
}

/*****************
 * Function: 0x0c
 * NET_API_STATUS NetrSessionEnum (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in,string,unique] WCHAR * ClientName,
 *   [in,string,unique] WCHAR * UserName,
 *   [in,out] PSESSION_ENUM_STRUCT InfoStruct,
 *   [in] DWORD PreferedMaximumLength,
 *   [out] DWORD * TotalEntries,
 *   [in,out,unique] DWORD * ResumeHandle
 * );
 */
int
srvsvc_NetrSessionEnum_req_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        struct srvsvc_NetrSessionEnum_req *req = ptr;
        void *clientname_ptr = &req->ClientName;
        void *username_ptr = &req->UserName;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        /*
         * ClientName/UserName are [unique]. On encode, a NULL char* must be
         * sent as a null referent (not an empty string). On decode, always
         * pass the address of the char* so a non-null referent can be stored.
         */
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                if (req->ClientName == NULL) {
                        clientname_ptr = NULL;
                }
                if (req->UserName == NULL) {
                        username_ptr = NULL;
                }
        }
        if (dcerpc_ptr_coder("ClientName", dce, pdu, iov, offset, clientname_ptr,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, username_ptr,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->ses,
                             PTR_REF, srvsvc_SESSION_ENUM_STRUCT_struct_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("PreferedMaximumLength", dce, pdu, iov, offset, &req->PreferedMaximumLength,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &req->ResumeHandle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrSessionEnum_rep_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        struct srvsvc_NetrSessionEnum_rep *rep = ptr;

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->ses,
                             PTR_REF, srvsvc_SESSION_ENUM_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TotalEntries", dce, pdu, iov, offset, &rep->total_entries,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &rep->resume_handle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x0d
 * NET_API_STATUS NetrSessionDel (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in,string,unique] WCHAR * ClientName,
 *   [in,string,unique] WCHAR * UserName
 * );
 */
int
srvsvc_NetrSessionDel_req_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        struct srvsvc_NetrSessionDel_req *req = ptr;
        void *clientname_ptr = &req->ClientName;
        void *username_ptr = &req->UserName;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        /*
         * ClientName/UserName are [unique]. On encode, a NULL char* must be
         * sent as a null referent (not an empty string). On decode, always
         * pass the address of the char* so a non-null referent can be stored.
         */
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                if (req->ClientName == NULL) {
                        clientname_ptr = NULL;
                }
                if (req->UserName == NULL) {
                        username_ptr = NULL;
                }
        }
        if (dcerpc_ptr_coder("ClientName", dce, pdu, iov, offset, clientname_ptr,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, username_ptr,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrSessionDel_rep_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        struct srvsvc_NetrSessionDel_rep *rep = ptr;

        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x0e
 * NET_API_STATUS NetrShareAdd (
 * [in,string,unique] SRVSVC_HANDLE ServerName,
 * [in] DWORD Level,
 * [in, switch_is(Level)] LPSHARE_INFO InfoStruct,
 * [in,out,unique] DWORD * ParmErr
 *);
 */
int
srvsvc_NetrShareAdd_req_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        struct srvsvc_NetrShareAdd_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &req->Level)) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->InfoStruct,
                             PTR_REF, srvsvc_SHARE_INFO_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ParmErr", dce, pdu, iov, offset, &req->ParmErr,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrShareAdd_rep_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        struct srvsvc_NetrShareAdd_rep *rep = ptr;

        if (dcerpc_ptr_coder("ParmErr", dce, pdu, iov, offset, &rep->ParmErr,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x0f
 * NET_API_STATUS NetrShareEnum (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in,out] LPSHARE_ENUM_STRUCT InfoStruct,
 *   [in] DWORD PreferedMaximumLength,
 *   [out] DWORD * TotalEntries,
 *   [in,out,unique] DWORD * ResumeHandle
 * );
 */
int
srvsvc_NetrShareEnum_req_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_NetrShareEnum_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->ses,
                             PTR_REF, srvsvc_SHARE_ENUM_STRUCT_struct_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("PreferedMaximumLength", dce, pdu, iov, offset, &req->PreferedMaximumLength,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &req->ResumeHandle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrShareEnum_rep_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_NetrShareEnum_rep *rep = ptr;

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->ses,
                             PTR_REF, srvsvc_SHARE_ENUM_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TotalEntries", dce, pdu, iov, offset, &rep->total_entries,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &rep->resume_handle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/******************
 * Function: 0x10
 * NET_API_STATUS NetrShareGetInfo (
 *    [in,string,unique] SRVSVC_HANDLE ServerName,
 *    [in,string] WCHAR * NetName,
 *    [in] DWORD Level,
 *    [out, switch_is(Level)] LPSHARE_INFO InfoStruct
*/
int
srvsvc_NetrShareGetInfo_req_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        struct srvsvc_NetrShareGetInfo_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset,
                             discard_const(&req->NetName),
                             PTR_REF, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &req->Level)) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);

        return 0;
}

int
srvsvc_NetrShareGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        struct srvsvc_NetrShareGetInfo_rep *rep = ptr;
        /* There is no Level in the reply so we must reference it from the request */
        struct srvsvc_NetrShareGetInfo_req *req = dcerpc_get_request(pdu);

        dcerpc_set_switch_is(pdu, req->Level);

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_REF, srvsvc_SHARE_INFO_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/******************
 * Function: 0x11
 * NET_API_STATUS NetrShareSetInfo (
 * [in,string,unique] SRVSVC_HANDLE ServerName,
 * [in,string] WCHAR * NetName,
 * [in] DWORD Level,
 * [in, switch_is(Level)] LPSHARE_INFO ShareInfo,
 * [in,out,unique] DWORD * ParmErr
 * );
*/
int
srvsvc_NetrShareSetInfo_req_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        struct srvsvc_NetrShareSetInfo_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset,
                             discard_const(&req->NetName),
                             PTR_REF, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &req->Level)) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->InfoStruct,
                             PTR_REF, srvsvc_SHARE_INFO_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ParmErr", dce, pdu, iov, offset, &req->ParmErr,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrShareSetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        struct srvsvc_NetrShareSetInfo_rep *rep = ptr;

        if (dcerpc_ptr_coder("ParmErr", dce, pdu, iov, offset, &rep->ParmErr,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/******************
 * Function: 0x12
 * NET_API_STATUS NetrShareDel (
 * [in,string,unique] SRVSVC_HANDLE ServerName,
 * [in,string] WCHAR *NetName,
 * [in] DWORD reserved
 * );
 */
int
srvsvc_NetrShareDel_req_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        struct srvsvc_NetrShareDel_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset,
                             discard_const(&req->NetName),
                             PTR_REF, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Reserved", dce, pdu, iov, offset, &req->Reserved)) {
                return -1;
        }
        return 0;
}

int
srvsvc_NetrShareDel_rep_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        struct srvsvc_NetrShareDel_rep *rep = ptr;

        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/******************
 * Function: 0x13
 * NET_API_STATUS NetrShareCheck (
 * [in,string,unique] SRVSVC_HANDLE ServerName,
 * [in,string] WCHAR *Device,
 * [out] DWORD Type
 * );
 */
int
srvsvc_NetrShareCheck_req_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        struct srvsvc_NetrShareCheck_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Device", dce, pdu, iov, offset,
                             discard_const(&req->Device),
                             PTR_REF, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_NetrShareCheck_rep_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        struct srvsvc_NetrShareCheck_rep *rep = ptr;

        if (dcerpc_ptr_coder("Type", dce, pdu, iov, offset, &rep->Type,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }

        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/***********
 * NetrServerGetInfo (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in] DWORD Level,
 *   [out, switch_is(Level)] LPSERVER_INFO InfoStruct
 *);
*/
int srvsvc_NetrServerGetInfo_req_coder(char *name, struct dcerpc_context *dce,
                                       struct dcerpc_pdu *pdu,
                                       struct smb2_iovec *iov, int *offset,
                                       void *ptr)
{
        struct srvsvc_NetrServerGetInfo_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &req->Level)) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);

        return 0;
}
        
int srvsvc_NetrServerGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                       struct dcerpc_pdu *pdu,
                                       struct smb2_iovec *iov, int *offset,
                                       void *ptr)
{
        struct srvsvc_NetrServerGetInfo_rep *rep = ptr;
        /* There is no Level in the reply so we must reference it from the request */
        struct srvsvc_NetrServerGetInfo_req *req = dcerpc_get_request(pdu);

        dcerpc_set_switch_is(pdu, req->Level);

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_REF, srvsvc_SERVER_INFO_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x16
 * NET_API_STATUS NetrServerSetInfo (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in] DWORD Level,
 *   [in, switch_is(Level)] LPSERVER_INFO ServerInfo,
 *   [in,out,unique] DWORD * ParmError
 * );
 */
int
srvsvc_NetrServerSetInfo_req_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        struct srvsvc_NetrServerSetInfo_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &req->Level)) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->InfoStruct,
                             PTR_REF, srvsvc_SERVER_INFO_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ParmErr", dce, pdu, iov, offset, &req->ParmErr,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrServerSetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        struct srvsvc_NetrServerSetInfo_rep *rep = ptr;

        if (dcerpc_ptr_coder("ParmErr", dce, pdu, iov, offset, &rep->ParmErr,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*
 * [string] WCHAR Disk[3] is encoded by MIDL as a varying UTF-16 string:
 *   offset, actual_count, data[actual_count]
 * (no max_count on the wire; the IDL bound of 3 is not transmitted).
 *
 * Encode/decode the full varying string during the data pass only so that
 * an array of DISK_INFO keeps each entry self-contained
 * (offset/actual/data before the next entry).
 */
static int
srvsvc_DISK_varying_string_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        char **str = ptr;
        uint32_t off = 0;
        uint32_t actual;
        uint32_t i;
        struct smb2_utf16 *utf16;
        const char *tmp;
        char *out;
        uint16_t zero = 0;
        uint16_t ch;

        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                /* YAML/JSON: plain string field */
                return dcerpc_utf16z_coder(name, dce, pdu, iov, offset, str);
        }

        /* NDR: nothing during the conformance run */
        if (dcerpc_get_cr(pdu)) {
                return 0;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                if (*str) {
                        utf16 = smb2_utf8_to_utf16(*str);
                } else {
                        utf16 = smb2_utf8_to_utf16("");
                }
                if (utf16 == NULL) {
                        return -1;
                }
                actual = (uint32_t)utf16->len + 1; /* include NUL */
                if (dcerpc_uint32_coder("Offset", dce, pdu, iov, offset, &off)) {
                        free(utf16);
                        return -1;
                }
                if (dcerpc_uint32_coder("ActualCount", dce, pdu, iov, offset, &actual)) {
                        free(utf16);
                        return -1;
                }
                for (i = 0; i < utf16->len; i++) {
                        ch = utf16->val[i];
                        if (dcerpc_uint16_coder("Disk", dce, pdu, iov, offset, &ch)) {
                                free(utf16);
                                return -1;
                        }
                }
                if (dcerpc_uint16_coder("Nult", dce, pdu, iov, offset, &zero)) {
                        free(utf16);
                        return -1;
                }
                free(utf16);
                return 0;
        }

        /* DECODE */
        if (dcerpc_uint32_coder("Offset", dce, pdu, iov, offset, &off)) {
                return -1;
        }
        if (dcerpc_uint32_coder("ActualCount", dce, pdu, iov, offset, &actual)) {
                return -1;
        }
        if (actual == 0) {
                *str = NULL;
                return 0;
        }
        if (*offset < 0 ||
            (uint64_t)*offset + (uint64_t)actual * 2u > iov->len) {
                return -1;
        }
        tmp = smb2_utf16_to_utf8((uint16_t *)(void *)(&iov->buf[*offset]),
                                 (size_t)actual);
        if (tmp == NULL) {
                return -1;
        }
        *offset += (int)actual * 2;
        out = smb2_alloc_data(dcerpc_get_smb2_context(dce),
                              dcerpc_get_pdu_payload(pdu),
                              strlen(tmp) + 1);
        if (out == NULL) {
                free(discard_const(tmp));
                return -1;
        }
        memcpy(out, tmp, strlen(tmp) + 1);
        free(discard_const(tmp));
        *str = out;
        return 0;
}

/*
 * typedef struct _DISK_INFO {
 *       [string] WCHAR Disk[3];
 * } DISK_INFO, *PDISK_INFO, *LPDISK_INFO;
 */
int
srvsvc_DISK_INFO_coder(char *name, struct dcerpc_context *dce,
                       struct dcerpc_pdu *pdu,
                       struct smb2_iovec *iov, int *offset,
                       void *ptr)
{
        struct srvsvc_DISK_INFO *di = ptr;

        if (srvsvc_DISK_varying_string_coder("Disk", dce, pdu, iov, offset,
                                             &di->disk)) {
                return -1;
        }
        return 0;
}

int
srvsvc_DISK_INFO_STRUCT_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_DISK_INFO_coder);
}

/*
 * Buffer is [size_is(EntriesRead), length_is(EntriesRead)] LPDISK_INFO
 * i.e. a conformant-varying array: max_count, offset, actual_count, then
 * EntriesRead elements. Write the full headers during the data pass so
 * each DISK_INFO can keep its varying string self-contained.
 */
static int
srvsvc_DISK_INFO_carray_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        uint32_t num = dcerpc_get_size_is(pdu);
        uint32_t max_count = num;
        uint32_t arr_offset = 0;
        uint32_t actual = num;
        uint32_t i;
        uint8_t *data = ptr;

        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                return dcerpc_carray_coder("DiskInfo", dce, pdu, iov, offset,
                                           num, ptr,
                                           sizeof(struct srvsvc_DISK_INFO),
                                           srvsvc_DISK_INFO_STRUCT_coder);
        }

        if (dcerpc_get_cr(pdu)) {
                return 0;
        }

        if (dcerpc_uint32_coder("MaxCount", dce, pdu, iov, offset, &max_count)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Offset", dce, pdu, iov, offset, &arr_offset)) {
                return -1;
        }
        if (dcerpc_uint32_coder("ActualCount", dce, pdu, iov, offset, &actual)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                if (actual > max_count || actual > num) {
                        return -1;
                }
                /* Prefer the wire actual_count (size_is came from EntriesRead). */
                num = actual;
        }
        for (i = 0; i < num; i++) {
                if (srvsvc_DISK_INFO_STRUCT_coder("DiskInfo", dce, pdu, iov,
                                                  offset,
                                                  &data[i * sizeof(struct srvsvc_DISK_INFO)])) {
                        return -1;
                }
        }
        return 0;
}

/*
 * typedef struct _DISK_ENUM_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead), length_is(EntriesRead)] LPDISK_INFO Buffer;
 * } DISK_ENUM_CONTAINER;
 */
int
srvsvc_DISK_ENUM_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        struct srvsvc_DISK_ENUM_CONTAINER *ctr = ptr;

        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead) {
                if (ctr->disk_info == NULL) {
                        size_t esize = sizeof(struct srvsvc_DISK_INFO);

                        if (ctr->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        ctr->disk_info = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                (size_t)ctr->EntriesRead * esize);
                        if (ctr->disk_info == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("DiskInfo", dce, pdu, iov, offset, ctr->disk_info,
                             PTR_UNIQUE, srvsvc_DISK_INFO_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_DISK_ENUM_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                                        struct dcerpc_pdu *pdu,
                                        struct smb2_iovec *iov, int *offset,
                                        void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_DISK_ENUM_CONTAINER_coder);
}

/*****************
 * Function: 0x17
 * NET_API_STATUS NetrServerDiskEnum (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in] DWORD Level,
 *   [in,out] DISK_ENUM_CONTAINER * DiskInfoStruct,
 *   [in] DWORD PreferedMaximumLength,
 *   [out] DWORD * TotalEntries,
 *   [in,out,unique] DWORD * ResumeHandle
 * );
 */
int
srvsvc_NetrServerDiskEnum_req_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        struct srvsvc_NetrServerDiskEnum_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &req->Level)) {
                return -1;
        }
        if (dcerpc_ptr_coder("DiskInfoStruct", dce, pdu, iov, offset, &req->DiskInfoStruct,
                             PTR_REF, srvsvc_DISK_ENUM_CONTAINER_struct_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("PreferedMaximumLength", dce, pdu, iov, offset, &req->PreferedMaximumLength,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &req->ResumeHandle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrServerDiskEnum_rep_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        struct srvsvc_NetrServerDiskEnum_rep *rep = ptr;

        if (dcerpc_ptr_coder("DiskInfoStruct", dce, pdu, iov, offset, &rep->DiskInfoStruct,
                             PTR_REF, srvsvc_DISK_ENUM_CONTAINER_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TotalEntries", dce, pdu, iov, offset, &rep->total_entries,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &rep->resume_handle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _STAT_SERVER_0 {
 *   DWORD sts0_start;
 *   DWORD sts0_fopens;
 *   DWORD sts0_devopens;
 *   DWORD sts0_jobsqueued;
 *   DWORD sts0_sopens;
 *   DWORD sts0_stimedout;
 *   DWORD sts0_serrorout;
 *   DWORD sts0_pwerrors;
 *   DWORD sts0_permerrors;
 *   DWORD sts0_syserrors;
 *   DWORD sts0_bytessent_low;
 *   DWORD sts0_bytessent_high;
 *   DWORD sts0_bytesrcvd_low;
 *   DWORD sts0_bytesrcvd_high;
 *   DWORD sts0_avresponse;
 *   DWORD sts0_reqbufneed;
 *   DWORD sts0_bigbufneed;
 * } STAT_SERVER_0, *PSTAT_SERVER_0, *LPSTAT_SERVER_0;
 */
int
srvsvc_STAT_SERVER_0_coder(char *name, struct dcerpc_context *dce,
                           struct dcerpc_pdu *pdu,
                           struct smb2_iovec *iov, int *offset,
                           void *ptr)
{
        struct srvsvc_STAT_SERVER_0 *st = ptr;

        if (dcerpc_uint32_coder("Start", dce, pdu, iov, offset, &st->start)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Fopens", dce, pdu, iov, offset, &st->fopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Devopens", dce, pdu, iov, offset, &st->devopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Jobsqueued", dce, pdu, iov, offset, &st->jobsqueued)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Sopens", dce, pdu, iov, offset, &st->sopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Stimedout", dce, pdu, iov, offset, &st->stimedout)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Serrorout", dce, pdu, iov, offset, &st->serrorout)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Pwerrors", dce, pdu, iov, offset, &st->pwerrors)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Permerrors", dce, pdu, iov, offset, &st->permerrors)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Syserrors", dce, pdu, iov, offset, &st->syserrors)) {
                return -1;
        }
        if (dcerpc_uint32_coder("BytessentLow", dce, pdu, iov, offset, &st->bytessent_low)) {
                return -1;
        }
        if (dcerpc_uint32_coder("BytessentHigh", dce, pdu, iov, offset, &st->bytessent_high)) {
                return -1;
        }
        if (dcerpc_uint32_coder("BytesrcvdLow", dce, pdu, iov, offset, &st->bytesrcvd_low)) {
                return -1;
        }
        if (dcerpc_uint32_coder("BytesrcvdHigh", dce, pdu, iov, offset, &st->bytesrcvd_high)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Avresponse", dce, pdu, iov, offset, &st->avresponse)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Reqbufneed", dce, pdu, iov, offset, &st->reqbufneed)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Bigbufneed", dce, pdu, iov, offset, &st->bigbufneed)) {
                return -1;
        }
        return 0;
}

int
srvsvc_STAT_SERVER_0_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_STAT_SERVER_0_coder);
}

/*****************
 * Function: 0x18
 * NET_API_STATUS NetrServerStatisticsGet (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in,string,unique] WCHAR * Service,
 *   [in] DWORD Level,
 *   [in] DWORD Options,
 *   [out] LPSTAT_SERVER_0 * InfoStruct
 * );
 */
int
srvsvc_NetrServerStatisticsGet_req_coder(char *name, struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         struct smb2_iovec *iov, int *offset,
                                         void *ptr)
{
        struct srvsvc_NetrServerStatisticsGet_req *req = ptr;
        void *service_ptr = &req->Service;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        /*
         * Service is [unique]. On encode, a NULL char* must be sent as a
         * null referent. On decode, always pass the address of the char*.
         */
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                if (req->Service == NULL) {
                        service_ptr = NULL;
                }
        }
        if (dcerpc_ptr_coder("Service", dce, pdu, iov, offset, service_ptr,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &req->Level)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Options", dce, pdu, iov, offset, &req->Options)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrServerStatisticsGet_rep_coder(char *name, struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         struct smb2_iovec *iov, int *offset,
                                         void *ptr)
{
        struct srvsvc_NetrServerStatisticsGet_rep *rep = ptr;

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_UNIQUE, srvsvc_STAT_SERVER_0_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}


struct dcerpc_procedure srvsvc_procs[] = {
        {SRVSVC_NETRCONNECTIONENUM, "NetrConnectionEnum",
         srvsvc_NetrConnectionEnum_req_coder, sizeof(struct srvsvc_NetrConnectionEnum_req),
         srvsvc_NetrConnectionEnum_rep_coder, sizeof(struct srvsvc_NetrConnectionEnum_rep),
        },
        {SRVSVC_NETRFILEENUM, "NetrFileEnum",
         srvsvc_NetrFileEnum_req_coder, sizeof(struct srvsvc_NetrFileEnum_req),
         srvsvc_NetrFileEnum_rep_coder, sizeof(struct srvsvc_NetrFileEnum_rep),
        },
        {SRVSVC_NETRFILEGETINFO, "NetrFileGetInfo",
         srvsvc_NetrFileGetInfo_req_coder, sizeof(struct srvsvc_NetrFileGetInfo_req),
         srvsvc_NetrFileGetInfo_rep_coder, sizeof(struct srvsvc_NetrFileGetInfo_rep),
        },
        {SRVSVC_NETRFILECLOSE, "NetrFileClose",
         srvsvc_NetrFileClose_req_coder, sizeof(struct srvsvc_NetrFileClose_req),
         srvsvc_NetrFileClose_rep_coder, sizeof(struct srvsvc_NetrFileClose_rep),
        },
        {SRVSVC_NETRSESSIONENUM, "NetrSessionEnum",
         srvsvc_NetrSessionEnum_req_coder, sizeof(struct srvsvc_NetrSessionEnum_req),
         srvsvc_NetrSessionEnum_rep_coder, sizeof(struct srvsvc_NetrSessionEnum_rep),
        },
        {SRVSVC_NETRSESSIONDEL, "NetrSessionDel",
         srvsvc_NetrSessionDel_req_coder, sizeof(struct srvsvc_NetrSessionDel_req),
         srvsvc_NetrSessionDel_rep_coder, sizeof(struct srvsvc_NetrSessionDel_rep),
        },
        {SRVSVC_NETRSHAREADD, "NetrShareAdd",
         srvsvc_NetrShareAdd_req_coder, sizeof(struct srvsvc_NetrShareAdd_req),
         srvsvc_NetrShareAdd_rep_coder, sizeof(struct srvsvc_NetrShareAdd_rep),
        },
        {SRVSVC_NETRSHAREENUM, "NetrShareEnum",
         srvsvc_NetrShareEnum_req_coder, sizeof(struct srvsvc_NetrShareEnum_req),
         srvsvc_NetrShareEnum_rep_coder, sizeof(struct srvsvc_NetrShareEnum_rep),
        },
        {SRVSVC_NETRSHAREGETINFO, "NetrShareGetInfo",
         srvsvc_NetrShareGetInfo_req_coder, sizeof(struct srvsvc_NetrShareGetInfo_req),
         srvsvc_NetrShareGetInfo_rep_coder, sizeof(struct srvsvc_NetrShareGetInfo_rep),
        },
        {SRVSVC_NETRSHARESETINFO, "NetrShareSetInfo",
         srvsvc_NetrShareSetInfo_req_coder, sizeof(struct srvsvc_NetrShareSetInfo_req),
         srvsvc_NetrShareSetInfo_rep_coder, sizeof(struct srvsvc_NetrShareSetInfo_rep),
        },
        {SRVSVC_NETRSHAREDEL, "NetrShareDel",
         srvsvc_NetrShareDel_req_coder, sizeof(struct srvsvc_NetrShareDel_req),
         srvsvc_NetrShareDel_rep_coder, sizeof(struct srvsvc_NetrShareDel_rep),
        },
        {SRVSVC_NETRSHAREDELSTICKY, "NetrShareDelSticky",
         srvsvc_NetrShareDel_req_coder, sizeof(struct srvsvc_NetrShareDel_req),
         srvsvc_NetrShareDel_rep_coder, sizeof(struct srvsvc_NetrShareDel_rep),
        },
        {SRVSVC_NETRSHARECHECK, "NetrShareCheck",
         srvsvc_NetrShareCheck_req_coder, sizeof(struct srvsvc_NetrShareCheck_req),
         srvsvc_NetrShareCheck_rep_coder, sizeof(struct srvsvc_NetrShareCheck_rep),
        },
        {SRVSVC_NETRSERVERGETINFO, "NetrServerGetInfo",
         srvsvc_NetrServerGetInfo_req_coder, sizeof(struct srvsvc_NetrServerGetInfo_req),
         srvsvc_NetrServerGetInfo_rep_coder, sizeof(struct srvsvc_NetrServerGetInfo_rep),
        },
        {SRVSVC_NETRSERVERSETINFO, "NetrServerSetInfo",
         srvsvc_NetrServerSetInfo_req_coder, sizeof(struct srvsvc_NetrServerSetInfo_req),
         srvsvc_NetrServerSetInfo_rep_coder, sizeof(struct srvsvc_NetrServerSetInfo_rep),
        },
        {SRVSVC_NETRSERVERDISKENUM, "NetrServerDiskEnum",
         srvsvc_NetrServerDiskEnum_req_coder, sizeof(struct srvsvc_NetrServerDiskEnum_req),
         srvsvc_NetrServerDiskEnum_rep_coder, sizeof(struct srvsvc_NetrServerDiskEnum_rep),
        },
        {SRVSVC_NETRSERVERSTATISTICSGET, "NetrServerStatisticsGet",
         srvsvc_NetrServerStatisticsGet_req_coder, sizeof(struct srvsvc_NetrServerStatisticsGet_req),
         srvsvc_NetrServerStatisticsGet_rep_coder, sizeof(struct srvsvc_NetrServerStatisticsGet_rep),
        },
        {-1, NULL, NULL, 0, NULL, 0}
};

