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
 * typedef struct _SHARE_INFO_1 {
 *       [string] wchar_t *netname;
 *       DWORD shi1_type;
 *       [string] wchar_t *remark;
 * } SHARE_INFO_1, *PSHARE_INFO_1, *LPSHARE_INFO_1;
 */
int
srvsvc_SHARE_INFO_1_coder(struct dcerpc_context *ctx,
                           struct dcerpc_pdu *pdu,
                           struct smb2_iovec *iov, int *offset,
                           void *ptr)
{
        struct srvsvc_SHARE_INFO_1 *nsi1 = ptr;

        if (dcerpc_ptr_coder(ctx, pdu, iov, offset, &nsi1->netname,
                              PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder(ctx, pdu, iov, offset, &nsi1->type)) {
                return -1;
        }
        if (dcerpc_ptr_coder(ctx, pdu, iov, offset, &nsi1->remark,
                              PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

/*
 *       [size_is(EntriesRead)] LPSHARE_INFO_1 Buffer;
 */
static int
srvsvc_SHARE_INFO_1_array_coder(struct dcerpc_context *ctx,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr)
{
        struct srvsvc_SHARE_INFO_1_carray *array = ptr;
        int i;
        uint64_t p;

        /* Conformance */
        p = array->max_count;
        if (dcerpc_uint3264_coder(ctx, pdu, iov, offset, &p)) {
                return -1;
        }
        if (p != array->max_count) {
                return -1;
        }

        /* Data */
        for (i = 0; i < p; i++) {
                if (srvsvc_SHARE_INFO_1_coder(ctx, pdu, iov, offset,
                                              &array->share_info_1[i])) {
                        return -1;
                }
        }

        return 0;
}

/*
 * typedef struct _SHARE_INFO_1_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPSHARE_INFO_1 Buffer;
 * } SHARE_INFO_1_CONTAINER;
*/
static int
srvsvc_SHARE_INFO_1_CONTAINER_coder(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                          struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        struct srvsvc_SHARE_INFO_1_CONTAINER *ctr1 = ptr;

        if (dcerpc_uint32_coder(dce, pdu, iov, offset, &ctr1->EntriesRead)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                /* Need to allocate the buffer for the array */
                ctr1->Buffer = smb2_alloc_data(dcerpc_get_smb2_context(dce),
                                               dcerpc_get_pdu_payload(pdu),
                                               sizeof(struct srvsvc_SHARE_INFO_1_carray) + ctr1->EntriesRead * sizeof(struct srvsvc_SHARE_INFO_1));
                if (ctr1->Buffer == NULL) {
                        return -1;
                }
                /* Need to set the max_count. When decoding we compare this
                 * with the maximum_count read from the pdu
                 */
                ctr1->Buffer->max_count = ctr1->EntriesRead;
        }

        if (dcerpc_ptr_coder(dce, pdu, iov, offset,
                             ctr1->Buffer,
                             PTR_UNIQUE,
                             srvsvc_SHARE_INFO_1_array_coder)) {
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
srvsvc_SHARE_ENUM_UNION_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                         struct smb2_iovec *iov, int *offset,
                         void *ptr)
{
        struct srvsvc_SHARE_ENUM_UNION *ctr = ptr;
        uint64_t p;

        p = ctr->level;
        if (dcerpc_uint3264_coder(ctx, pdu, iov, offset, &p)) {
                return -1;
        }
        ctr->level = (uint32_t)p;

        switch (ctr->level) {
        case 1:
                if (dcerpc_ptr_coder(ctx, pdu, iov, offset, &ctr->Level1,
                                      PTR_UNIQUE,
                                      srvsvc_SHARE_INFO_1_CONTAINER_coder)) {
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
/*
  000000 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00
         ----------- ----------- ----------- -----------
           pad to 64     Level    pad to 64       UNION-
  000010 00 00 00 00 55 70 74 72 72 74 70 55 00 00 00 00
         ----------- -----------------------
         -CHOICE         *Level1
  000020 00 00 00 00 00 00 00 00 00 00 00 00
  00002c
*/
int
srvsvc_SHARE_ENUM_STRUCT_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                         struct smb2_iovec *iov, int *offset,
                         void *ptr)
{
        struct srvsvc_SHARE_ENUM_STRUCT *ses = ptr;

        /* QQQ temp padding to 64 bits because of alignment of ShareInfo */
        /* need to split the coder run into two.
           first a conformance run that also tracks alignment
           and second a run to code the actual data
        */
        *offset = dcerpc_align_3264(ctx, *offset);

        if (dcerpc_uint32_coder(ctx, pdu, iov, offset, &ses->Level)) {
                return -1;
        }
        ses->ShareInfo.level = ses->Level;
        if (srvsvc_SHARE_ENUM_UNION_coder(ctx, pdu, iov, offset, &ses->ShareInfo)) {
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
srvsvc_NetrShareEnum_req_coder(struct dcerpc_context *ctx,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_NetShareEnum_req *req = ptr;

        if (dcerpc_ptr_coder(ctx, pdu, iov, offset, &req->ServerName,
                              PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder(ctx, pdu, iov, offset, &req->ses,
                              PTR_REF, srvsvc_SHARE_ENUM_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder(ctx, pdu, iov, offset, &req->PreferedMaximumLength,
                              PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder(ctx, pdu, iov, offset, &req->ResumeHandle,
                              PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrShareEnum_rep_coder(struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_NetShareEnum_rep *rep = ptr;
        struct srvsvc_SHARE_ENUM_UNION *ctr;

        if (dcerpc_ptr_coder(dce, pdu, iov, offset, &rep->level,
                              PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                ctr = smb2_alloc_data(dcerpc_get_smb2_context(dce),
                                      dcerpc_get_pdu_payload(pdu),
                                      sizeof(struct srvsvc_SHARE_ENUM_UNION));
                if (ctr == NULL) {
                        return -1;
                }
                rep->ctr = ctr;
        }
        if (dcerpc_ptr_coder(dce, pdu, iov, offset, rep->ctr,
                              PTR_REF, srvsvc_SHARE_ENUM_UNION_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder(dce, pdu, iov, offset, &rep->total_entries,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder(dce, pdu, iov, offset, &rep->resume_handle,
                              PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder(dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*
 *	typedef union {
 *		[case(0)] srvsvc_NetShareInfo0 *info0;
 *		[case(1)] srvsvc_SHARE_INFO_1 *Level1;
 *		[case(2)] srvsvc_NetShareInfo2 *info2;
 *		[case(501)] srvsvc_NetShareInfo501 *info501;
 *		[case(502)] srvsvc_NetShareInfo502 *info502;
 *		[case(1004)] srvsvc_NetShareInfo1004 *info1004;
 *		[case(1005)] srvsvc_NetShareInfo1005 *info1005;
 *		[case(1006)] srvsvc_NetShareInfo1006 *info1006;
 *		[case(1007)] srvsvc_NetShareInfo1007 *info1007;
 *		[case(1501)] sec_desc_buf *info1501;
 *		[default] ;
 *	} srvsvc_NetShareInfo;
 */
static int
srvsvc_NetShareInfo_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                           struct smb2_iovec *iov, int *offset,
                          void *ptr)
{
        struct srvsvc_netshareinfo *info = ptr;
        uint64_t p;

        p = info->level;
        if (dcerpc_uint3264_coder(ctx, pdu, iov, offset, &p)) {
                return -1;
        }
        info->level = (uint32_t)p;

        switch (info->level) {
        case 1:
                if (dcerpc_ptr_coder(ctx, pdu, iov, offset, &info->ShareInfo1,
                                      PTR_UNIQUE,
                                      srvsvc_SHARE_INFO_1_coder)) {
                        return -1;
                }
                break;
        };

        return 0     ;
}

/******************
 * Function: 0x10
 *	WERROR srvsvc_NetShareGetInfo(
 *		[in]   [string,charset(UTF16)] uint16 *server_unc,
 *		[in]   [string,charset(UTF16)] uint16 share_name[],
 *		[in]   uint32 level,
 *		[out,switch_is(level),ref] srvsvc_NetShareInfo *info
 *		);
 ******************/
int
srvsvc_NetrShareGetInfo_req_coder(struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        struct srvsvc_netrsharegetinfo_req *req = ptr;

        if (dcerpc_ptr_coder(dce, pdu, iov, offset, &req->ServerName,
                              PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder(dce, pdu, iov, offset,
                              discard_const(&req->NetName),
                              PTR_REF, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder(dce, pdu, iov, offset, &req->Level)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrShareGetInfo_rep_coder(struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        struct srvsvc_netrsharegetinfo_rep *rep = ptr;

        if (dcerpc_ptr_coder(dce, pdu, iov, offset, &rep->info,
                              PTR_REF, srvsvc_NetShareInfo_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder(dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}
