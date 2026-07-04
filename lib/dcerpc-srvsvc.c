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
srvsvc_SHARE_INFO_0_coder(char *name, struct dcerpc_context *ctx,
                           struct dcerpc_pdu *pdu,
                           struct smb2_iovec *iov, int *offset,
                           void *ptr)
{
        struct srvsvc_SHARE_INFO_0 *nsi1 = ptr;

        if (dcerpc_ptr_coder("NetName", ctx, pdu, iov, offset, &nsi1->netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SHARE_INFO_0_STRUCT_coder(char *name, struct dcerpc_context *ctx,
                          struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        return dcerpc_struct_coder(name, ctx, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_0_coder);
}

/*
 *       [size_is(EntriesRead)] LPSHARE_INFO_0 Buffer;
 */
static int
srvsvc_SHARE_INFO_0_carray_coder(char *name, struct dcerpc_context *ctx,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        return dcerpc_carray_coder("ShareInfo0", ctx, pdu, iov, offset,
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
                        ctr->share_info_0 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                ctr->EntriesRead * sizeof(struct srvsvc_SHARE_INFO_0));
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
srvsvc_SHARE_INFO_1_coder(char *name, struct dcerpc_context *ctx,
                          struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        struct srvsvc_SHARE_INFO_1 *nsi1 = ptr;

        if (dcerpc_ptr_coder("NetName", ctx, pdu, iov, offset, &nsi1->netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Type", ctx, pdu, iov, offset, &nsi1->type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Remark", ctx, pdu, iov, offset, &nsi1->remark,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SHARE_INFO_1_STRUCT_coder(char *name, struct dcerpc_context *ctx,
                          struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        return dcerpc_struct_coder(name, ctx, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_1_coder);
}

/*
 *       [size_is(EntriesRead)] LPSHARE_INFO_1 Buffer;
 */
static int
srvsvc_SHARE_INFO_1_carray_coder(char *name, struct dcerpc_context *ctx,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        return dcerpc_carray_coder("ShareInfo1", ctx, pdu, iov, offset,
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
                        ctr->share_info_1 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                ctr->EntriesRead * sizeof(struct srvsvc_SHARE_INFO_1));
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
srvsvc_SHARE_INFO_2_coder(char *name, struct dcerpc_context *ctx,
                          struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        struct srvsvc_SHARE_INFO_2 *nsi2 = ptr;

        if (dcerpc_ptr_coder("NetName", ctx, pdu, iov, offset, &nsi2->netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Type", ctx, pdu, iov, offset, &nsi2->type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Remark", ctx, pdu, iov, offset, &nsi2->remark,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Permissions", ctx, pdu, iov, offset, &nsi2->permissions)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MaxUsers", ctx, pdu, iov, offset, &nsi2->max_users)) {
                return -1;
        }
        if (dcerpc_uint32_coder("CurrentUsers", ctx, pdu, iov, offset, &nsi2->current_users)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Path", ctx, pdu, iov, offset, &nsi2->path,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Passwd", ctx, pdu, iov, offset, &nsi2->passwd,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SHARE_INFO_2_STRUCT_coder(char *name, struct dcerpc_context *ctx,
                          struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        return dcerpc_struct_coder(name, ctx, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_2_coder);
}

/*
 *       [size_is(EntriesRead)] LPSHARE_INFO_2 Buffer;
 */
static int
srvsvc_SHARE_INFO_2_carray_coder(char *name, struct dcerpc_context *ctx,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        return dcerpc_carray_coder("ShareInfo2", ctx, pdu, iov, offset,
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
                        ctr->share_info_2 = smb2_alloc_data(
                                dcerpc_get_smb2_context(dce),
                                dcerpc_get_pdu_payload(pdu),
                                ctr->EntriesRead * sizeof(struct srvsvc_SHARE_INFO_2));
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
srvsvc_SHARE_ENUM_UNION_coder(char *name, struct dcerpc_context *ctx,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr)
{
        union srvsvc_SHARE_ENUM_UNION *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                if (dcerpc_ptr_coder("ShareInfo0Container", ctx, pdu, iov, offset, &info->Level0,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_0_CONTAINER_coder)) {
                        return -1;
                }
                break;
        case 1:
                if (dcerpc_ptr_coder("ShareInfo1Container", ctx, pdu, iov, offset, &info->Level1,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_1_CONTAINER_coder)) {
                        return -1;
                }
                break;
        case 2:
                if (dcerpc_ptr_coder("ShareInfo2Container", ctx, pdu, iov, offset, &info->Level2,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_2_CONTAINER_coder)) {
                        return -1;
                }
                break;
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
srvsvc_SHARE_ENUM_STRUCT_coder(char *name, struct dcerpc_context *ctx,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_SHARE_ENUM_STRUCT *ses = ptr;

        if (dcerpc_uint32_coder("Level", ctx, pdu, iov, offset, &ses->Level)) {
                return -1;
        }

        if (dcerpc_union_coder("ShareInfo", ctx, pdu, iov, offset,
                               &ses->Level, &ses->ShareEnum,
                               srvsvc_SHARE_ENUM_UNION_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_ENUM_STRUCT_struct_coder(char *name, struct dcerpc_context *ctx,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        return dcerpc_struct_coder(name, ctx, pdu, iov, offset, ptr,
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
srvsvc_SHARE_INFO_coder(char *name, struct dcerpc_context *ctx,
                        struct dcerpc_pdu *pdu,
                        struct smb2_iovec *iov, int *offset,
                        void *ptr)
{
        union srvsvc_SHARE_INFO *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                if (dcerpc_ptr_coder("ShareInfo0", ctx, pdu, iov, offset, &info->ShareInfo0,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_0_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 1:
                if (dcerpc_ptr_coder("ShareInfo1", ctx, pdu, iov, offset, &info->ShareInfo1,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_1_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 2:
                if (dcerpc_ptr_coder("ShareInfo2", ctx, pdu, iov, offset, &info->ShareInfo2,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_2_STRUCT_coder)) {
                        return -1;
                }
                break;
        };

        return 0;
}

static int
srvsvc_SHARE_INFO_STRUCT_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        uint32_t Level = dcerpc_get_switch_is(pdu);

        if (dcerpc_union_coder("InfoStruct", ctx, pdu, iov, offset,
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

        if (dcerpc_uint32_coder("SV100_Platform_Id", dce, pdu, iov, offset, &si100->sv100_platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("SV100_Name", dce, pdu, iov, offset, &si100->sv100_name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SERVER_INFO_100_STRUCT_coder(char *name, struct dcerpc_context *ctx,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr)
{
        return  dcerpc_struct_coder(name, ctx, pdu, iov, offset, ptr,
                                    srvsvc_SERVER_INFO_100_coder);
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
srvsvc_SERVER_INFO_coder(char *name, struct dcerpc_context *ctx,
                         struct dcerpc_pdu *pdu,
                         struct smb2_iovec *iov, int *offset,
                         void *ptr)
{
        union srvsvc_SERVER_INFO *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 100:
                if (dcerpc_ptr_coder("ServerInfo100", ctx, pdu, iov, offset, &info->ServerInfo100,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_100_STRUCT_coder)) {
                        return -1;
                }
                break;
        };

        return 0;
}

static int
srvsvc_SERVER_INFO_STRUCT_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr)
{
        uint32_t Level = dcerpc_get_switch_is(pdu);

        if (dcerpc_union_coder("InfoStruct", ctx, pdu, iov, offset,
                               &Level, ptr,
                               srvsvc_SERVER_INFO_coder)) {
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


struct dcerpc_procedure srvsvc_procs[] = {
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
        {-1, NULL, NULL, 0, NULL, 0}
};

