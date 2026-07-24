/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
#include "libsmb2-dcerpc-wkssvc.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

/* MS-WKST: uuid(6bffd098-a112-3610-9833-46c3f87e345a), version(1.0) */
#define WKSSVC_UUID    0x6bffd098, 0xa112, 0x3610, {0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a}

p_syntax_id_t wkssvc_interface = {
        {WKSSVC_UUID}, 1, 0
};

/*
 * WKSSVC BEGIN: DEFINITIONS FROM MS-WKST
 */

/*
 * typedef struct _WKSTA_INFO_100 {
 *   unsigned long wki100_platform_id;
 *   [string] wchar_t *wki100_computername;
 *   [string] wchar_t *wki100_langroup;
 *   unsigned long wki100_ver_major;
 *   unsigned long wki100_ver_minor;
 * } WKSTA_INFO_100;
 */
int
wkssvc_WKSTA_INFO_100_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr)
{
        struct wkssvc_WKSTA_INFO_100 *wi = ptr;

        if (dcerpc_uint32_coder("Platform_Id", dce, pdu, iov, offset, &wi->platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ComputerName", dce, pdu, iov, offset, &wi->computername,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("LanGroup", dce, pdu, iov, offset, &wi->langroup,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Major", dce, pdu, iov, offset, &wi->ver_major)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Minor", dce, pdu, iov, offset, &wi->ver_minor)) {
                return -1;
        }
        return 0;
}

int
wkssvc_WKSTA_INFO_100_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   wkssvc_WKSTA_INFO_100_coder);
}

/*
 * typedef struct _WKSTA_INFO_101 {
 *   unsigned long wki101_platform_id;
 *   [string] wchar_t *wki101_computername;
 *   [string] wchar_t *wki101_langroup;
 *   unsigned long wki101_ver_major;
 *   unsigned long wki101_ver_minor;
 *   [string] wchar_t *wki101_lanroot;
 * } WKSTA_INFO_101;
 */
int
wkssvc_WKSTA_INFO_101_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr)
{
        struct wkssvc_WKSTA_INFO_101 *wi = ptr;

        if (dcerpc_uint32_coder("Platform_Id", dce, pdu, iov, offset, &wi->platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ComputerName", dce, pdu, iov, offset, &wi->computername,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("LanGroup", dce, pdu, iov, offset, &wi->langroup,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Major", dce, pdu, iov, offset, &wi->ver_major)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Minor", dce, pdu, iov, offset, &wi->ver_minor)) {
                return -1;
        }
        if (dcerpc_ptr_coder("LanRoot", dce, pdu, iov, offset, &wi->lanroot,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        return 0;
}

int
wkssvc_WKSTA_INFO_101_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   wkssvc_WKSTA_INFO_101_coder);
}

/*
 * typedef struct _WKSTA_INFO_102 {
 *   unsigned long wki102_platform_id;
 *   [string] wchar_t *wki102_computername;
 *   [string] wchar_t *wki102_langroup;
 *   unsigned long wki102_ver_major;
 *   unsigned long wki102_ver_minor;
 *   [string] wchar_t *wki102_lanroot;
 *   unsigned long wki102_logged_on_users;
 * } WKSTA_INFO_102;
 */
int
wkssvc_WKSTA_INFO_102_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr)
{
        struct wkssvc_WKSTA_INFO_102 *wi = ptr;

        if (dcerpc_uint32_coder("Platform_Id", dce, pdu, iov, offset, &wi->platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ComputerName", dce, pdu, iov, offset, &wi->computername,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("LanGroup", dce, pdu, iov, offset, &wi->langroup,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Major", dce, pdu, iov, offset, &wi->ver_major)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Version_Minor", dce, pdu, iov, offset, &wi->ver_minor)) {
                return -1;
        }
        if (dcerpc_ptr_coder("LanRoot", dce, pdu, iov, offset, &wi->lanroot,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("LoggedOnUsers", dce, pdu, iov, offset, &wi->logged_on_users)) {
                return -1;
        }
        return 0;
}

int
wkssvc_WKSTA_INFO_102_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   wkssvc_WKSTA_INFO_102_coder);
}

/*
 * typedef struct _WKSTA_INFO_502 {
 *   unsigned long wki502_char_wait;
 *   unsigned long wki502_collection_time;
 *   unsigned long wki502_maximum_collection_count;
 *   unsigned long wki502_keep_conn;
 *   unsigned long wki502_max_cmds;
 *   unsigned long wki502_sess_timeout;
 *   unsigned long wki502_siz_char_buf;
 *   unsigned long wki502_max_threads;
 *   unsigned long wki502_lock_quota;
 *   unsigned long wki502_lock_increment;
 *   unsigned long wki502_lock_maximum;
 *   unsigned long wki502_pipe_increment;
 *   unsigned long wki502_pipe_maximum;
 *   unsigned long wki502_cache_file_timeout;
 *   unsigned long wki502_dormant_file_limit;
 *   unsigned long wki502_read_ahead_throughput;
 *   unsigned long wki502_num_mailslot_buffers;
 *   unsigned long wki502_num_srv_announce_buffers;
 *   unsigned long wki502_max_illegal_datagram_events;
 *   unsigned long wki502_illegal_datagram_event_reset_frequency;
 *   int wki502_log_election_packets;
 *   int wki502_use_opportunistic_locking;
 *   int wki502_use_unlock_behind;
 *   int wki502_use_close_behind;
 *   int wki502_buf_named_pipes;
 *   int wki502_use_lock_read_unlock;
 *   int wki502_utilize_nt_caching;
 *   int wki502_use_raw_read;
 *   int wki502_use_raw_write;
 *   int wki502_use_write_raw_data;
 *   int wki502_use_encryption;
 *   int wki502_buf_files_deny_write;
 *   int wki502_buf_read_only_files;
 *   int wki502_force_core_create_mode;
 *   int wki502_use_512_byte_max_transfer;
 * } WKSTA_INFO_502;
 */
int
wkssvc_WKSTA_INFO_502_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr)
{
        struct wkssvc_WKSTA_INFO_502 *wi = ptr;

        if (dcerpc_uint32_coder("CharWait", dce, pdu, iov, offset, &wi->char_wait)) {
                return -1;
        }
        if (dcerpc_uint32_coder("CollectionTime", dce, pdu, iov, offset, &wi->collection_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MaximumCollectionCount", dce, pdu, iov, offset, &wi->maximum_collection_count)) {
                return -1;
        }
        if (dcerpc_uint32_coder("KeepConn", dce, pdu, iov, offset, &wi->keep_conn)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MaxCmds", dce, pdu, iov, offset, &wi->max_cmds)) {
                return -1;
        }
        if (dcerpc_uint32_coder("SessTimeout", dce, pdu, iov, offset, &wi->sess_timeout)) {
                return -1;
        }
        if (dcerpc_uint32_coder("SizCharBuf", dce, pdu, iov, offset, &wi->siz_char_buf)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MaxThreads", dce, pdu, iov, offset, &wi->max_threads)) {
                return -1;
        }
        if (dcerpc_uint32_coder("LockQuota", dce, pdu, iov, offset, &wi->lock_quota)) {
                return -1;
        }
        if (dcerpc_uint32_coder("LockIncrement", dce, pdu, iov, offset, &wi->lock_increment)) {
                return -1;
        }
        if (dcerpc_uint32_coder("LockMaximum", dce, pdu, iov, offset, &wi->lock_maximum)) {
                return -1;
        }
        if (dcerpc_uint32_coder("PipeIncrement", dce, pdu, iov, offset, &wi->pipe_increment)) {
                return -1;
        }
        if (dcerpc_uint32_coder("PipeMaximum", dce, pdu, iov, offset, &wi->pipe_maximum)) {
                return -1;
        }
        if (dcerpc_uint32_coder("CacheFileTimeout", dce, pdu, iov, offset, &wi->cache_file_timeout)) {
                return -1;
        }
        if (dcerpc_uint32_coder("DormantFileLimit", dce, pdu, iov, offset, &wi->dormant_file_limit)) {
                return -1;
        }
        if (dcerpc_uint32_coder("ReadAheadThroughput", dce, pdu, iov, offset, &wi->read_ahead_throughput)) {
                return -1;
        }
        if (dcerpc_uint32_coder("NumMailslotBuffers", dce, pdu, iov, offset, &wi->num_mailslot_buffers)) {
                return -1;
        }
        if (dcerpc_uint32_coder("NumSrvAnnounceBuffers", dce, pdu, iov, offset, &wi->num_srv_announce_buffers)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MaxIllegalDatagramEvents", dce, pdu, iov, offset, &wi->max_illegal_datagram_events)) {
                return -1;
        }
        if (dcerpc_uint32_coder("IllegalDatagramEventResetFrequency", dce, pdu, iov, offset, &wi->illegal_datagram_event_reset_frequency)) {
                return -1;
        }
        if (dcerpc_uint32_coder("LogElectionPackets", dce, pdu, iov, offset, &wi->log_election_packets)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UseOpportunisticLocking", dce, pdu, iov, offset, &wi->use_opportunistic_locking)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UseUnlockBehind", dce, pdu, iov, offset, &wi->use_unlock_behind)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UseCloseBehind", dce, pdu, iov, offset, &wi->use_close_behind)) {
                return -1;
        }
        if (dcerpc_uint32_coder("BufNamedPipes", dce, pdu, iov, offset, &wi->buf_named_pipes)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UseLockReadUnlock", dce, pdu, iov, offset, &wi->use_lock_read_unlock)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UtilizeNtCaching", dce, pdu, iov, offset, &wi->utilize_nt_caching)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UseRawRead", dce, pdu, iov, offset, &wi->use_raw_read)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UseRawWrite", dce, pdu, iov, offset, &wi->use_raw_write)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UseWriteRawData", dce, pdu, iov, offset, &wi->use_write_raw_data)) {
                return -1;
        }
        if (dcerpc_uint32_coder("UseEncryption", dce, pdu, iov, offset, &wi->use_encryption)) {
                return -1;
        }
        if (dcerpc_uint32_coder("BufFilesDenyWrite", dce, pdu, iov, offset, &wi->buf_files_deny_write)) {
                return -1;
        }
        if (dcerpc_uint32_coder("BufReadOnlyFiles", dce, pdu, iov, offset, &wi->buf_read_only_files)) {
                return -1;
        }
        if (dcerpc_uint32_coder("ForceCoreCreateMode", dce, pdu, iov, offset, &wi->force_core_create_mode)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Use512ByteMaxTransfer", dce, pdu, iov, offset, &wi->use_512_byte_max_transfer)) {
                return -1;
        }
        return 0;
}

int
wkssvc_WKSTA_INFO_502_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   wkssvc_WKSTA_INFO_502_coder);
}

/*
 * typedef [switch_type(unsigned long)] union _WKSTA_INFO {
 *   [case(100)] LPWKSTA_INFO_100 WkstaInfo100;
 *   [case(101)] LPWKSTA_INFO_101 WkstaInfo101;
 *   [case(102)] LPWKSTA_INFO_102 WkstaInfo102;
 *   [case(502)] LPWKSTA_INFO_502 WkstaInfo502;
 * } WKSTA_INFO;
 */
static int
wkssvc_WKSTA_INFO_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct smb2_iovec *iov, int *offset,
                        void *ptr)
{
        union wkssvc_WKSTA_INFO *info = ptr;

        switch (dcerpc_get_switch_is(pdu)) {
        case 100:
                if (dcerpc_ptr_coder("WkstaInfo100", dce, pdu, iov, offset, &info->WkstaInfo100,
                                     PTR_UNIQUE, wkssvc_WKSTA_INFO_100_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 101:
                if (dcerpc_ptr_coder("WkstaInfo101", dce, pdu, iov, offset, &info->WkstaInfo101,
                                     PTR_UNIQUE, wkssvc_WKSTA_INFO_101_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 102:
                if (dcerpc_ptr_coder("WkstaInfo102", dce, pdu, iov, offset, &info->WkstaInfo102,
                                     PTR_UNIQUE, wkssvc_WKSTA_INFO_102_STRUCT_coder)) {
                        return -1;
                }
                break;
        case 502:
                if (dcerpc_ptr_coder("WkstaInfo502", dce, pdu, iov, offset, &info->WkstaInfo502,
                                     PTR_UNIQUE, wkssvc_WKSTA_INFO_502_STRUCT_coder)) {
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
wkssvc_WKSTA_INFO_STRUCT_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr)
{
        uint32_t Level = dcerpc_get_switch_is(pdu);

        if (dcerpc_union_coder("WkstaInfo", dce, pdu, iov, offset,
                               &Level, ptr,
                               wkssvc_WKSTA_INFO_coder)) {
                return -1;
        }
        return 0;
}

/*****************
 * Function: 0x00
 * unsigned long NetrWkstaGetInfo (
 *   [in, string, unique] WKSSVC_IDENTIFY_HANDLE ServerName,
 *   [in] unsigned long Level,
 *   [out, switch_is(Level)] LPWKSTA_INFO WkstaInfo
 * );
 */
int
wkssvc_NetrWkstaGetInfo_req_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        struct wkssvc_NetrWkstaGetInfo_req *req = ptr;

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

int
wkssvc_NetrWkstaGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr)
{
        struct wkssvc_NetrWkstaGetInfo_rep *rep = ptr;
        /* There is no Level in the reply so we must reference it from the request */
        struct wkssvc_NetrWkstaGetInfo_req *req = dcerpc_get_request(pdu);

        dcerpc_set_switch_is(pdu, req->Level);

        if (dcerpc_ptr_coder("WkstaInfo", dce, pdu, iov, offset, &rep->WkstaInfo,
                             PTR_REF, wkssvc_WKSTA_INFO_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

struct dcerpc_procedure wkssvc_procs[] = {
        {WKSSVC_NETRWKSTAGETINFO, "NetrWkstaGetInfo",
         wkssvc_NetrWkstaGetInfo_req_coder, sizeof(struct wkssvc_NetrWkstaGetInfo_req),
         wkssvc_NetrWkstaGetInfo_rep_coder, sizeof(struct wkssvc_NetrWkstaGetInfo_rep),
        },
        {-1, NULL, NULL, 0, NULL, 0}
};
