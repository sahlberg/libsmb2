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

#ifndef _LIBSMB2_DCERPC_WKSSVC_H_
#define _LIBSMB2_DCERPC_WKSSVC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <smb2/libsmb2-dcerpc.h>

/* MS-WKST opnums */
#define WKSSVC_NETRWKSTAGETINFO 0x00

struct dcerpc_context;
struct dcerpc_pdu;

/*
 * WKSTA_INFO levels used by NetrWkstaGetInfo
 */
enum WKSTA_INFO_enum {
        WKSTA_INFO_100 = 100,
        WKSTA_INFO_101 = 101,
        WKSTA_INFO_102 = 102,
        WKSTA_INFO_502 = 502,
};

/*
 * typedef struct _WKSTA_INFO_100 {
 *   unsigned long wki100_platform_id;
 *   [string] wchar_t *wki100_computername;
 *   [string] wchar_t *wki100_langroup;
 *   unsigned long wki100_ver_major;
 *   unsigned long wki100_ver_minor;
 * } WKSTA_INFO_100;
 */
struct wkssvc_WKSTA_INFO_100 {
        uint32_t platform_id;
        char *computername;
        char *langroup;
        uint32_t ver_major;
        uint32_t ver_minor;
};
int wkssvc_WKSTA_INFO_100_coder(char *name, struct dcerpc_context *ctx,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr);

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
struct wkssvc_WKSTA_INFO_101 {
        uint32_t platform_id;
        char *computername;
        char *langroup;
        uint32_t ver_major;
        uint32_t ver_minor;
        char *lanroot;
};
int wkssvc_WKSTA_INFO_101_coder(char *name, struct dcerpc_context *ctx,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr);

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
struct wkssvc_WKSTA_INFO_102 {
        uint32_t platform_id;
        char *computername;
        char *langroup;
        uint32_t ver_major;
        uint32_t ver_minor;
        char *lanroot;
        uint32_t logged_on_users;
};
int wkssvc_WKSTA_INFO_102_coder(char *name, struct dcerpc_context *ctx,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr);

/*
 * typedef struct _WKSTA_INFO_502 {
 *   unsigned long wki502_char_wait;
 *   ... (see MS-WKST 2.2.5.4)
 * } WKSTA_INFO_502;
 */
struct wkssvc_WKSTA_INFO_502 {
        uint32_t char_wait;
        uint32_t collection_time;
        uint32_t maximum_collection_count;
        uint32_t keep_conn;
        uint32_t max_cmds;
        uint32_t sess_timeout;
        uint32_t siz_char_buf;
        uint32_t max_threads;
        uint32_t lock_quota;
        uint32_t lock_increment;
        uint32_t lock_maximum;
        uint32_t pipe_increment;
        uint32_t pipe_maximum;
        uint32_t cache_file_timeout;
        uint32_t dormant_file_limit;
        uint32_t read_ahead_throughput;
        uint32_t num_mailslot_buffers;
        uint32_t num_srv_announce_buffers;
        uint32_t max_illegal_datagram_events;
        uint32_t illegal_datagram_event_reset_frequency;
        uint32_t log_election_packets;
        uint32_t use_opportunistic_locking;
        uint32_t use_unlock_behind;
        uint32_t use_close_behind;
        uint32_t buf_named_pipes;
        uint32_t use_lock_read_unlock;
        uint32_t utilize_nt_caching;
        uint32_t use_raw_read;
        uint32_t use_raw_write;
        uint32_t use_write_raw_data;
        uint32_t use_encryption;
        uint32_t buf_files_deny_write;
        uint32_t buf_read_only_files;
        uint32_t force_core_create_mode;
        uint32_t use_512_byte_max_transfer;
};
int wkssvc_WKSTA_INFO_502_coder(char *name, struct dcerpc_context *ctx,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr);

/*
 * typedef [switch_type(unsigned long)] union _WKSTA_INFO {
 *   [case(100)] LPWKSTA_INFO_100 WkstaInfo100;
 *   [case(101)] LPWKSTA_INFO_101 WkstaInfo101;
 *   [case(102)] LPWKSTA_INFO_102 WkstaInfo102;
 *   [case(502)] LPWKSTA_INFO_502 WkstaInfo502;
 * } WKSTA_INFO, *PWKSTA_INFO, *LPWKSTA_INFO;
 */
union wkssvc_WKSTA_INFO {
        struct wkssvc_WKSTA_INFO_100 WkstaInfo100;
        struct wkssvc_WKSTA_INFO_101 WkstaInfo101;
        struct wkssvc_WKSTA_INFO_102 WkstaInfo102;
        struct wkssvc_WKSTA_INFO_502 WkstaInfo502;
};

/*
 * unsigned long NetrWkstaGetInfo(
 *   [in, string, unique] WKSSVC_IDENTIFY_HANDLE ServerName,
 *   [in] unsigned long Level,
 *   [out, switch_is(Level)] LPWKSTA_INFO WkstaInfo
 * );
 */
struct wkssvc_NetrWkstaGetInfo_req {
        char *ServerName;
        uint32_t Level;
};

struct wkssvc_NetrWkstaGetInfo_rep {
        union wkssvc_WKSTA_INFO WkstaInfo;

        uint32_t status;
};

int wkssvc_NetrWkstaGetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int wkssvc_NetrWkstaGetInfo_rep_coder(char *name, struct dcerpc_context *ctx,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);

extern struct dcerpc_procedure wkssvc_procs[];

#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_DCERPC_WKSSVC_H_ */
