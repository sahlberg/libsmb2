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
#define WKSSVC_NETRWKSTAGETINFO              0x00
#define WKSSVC_NETRWKSTASETINFO              0x01
#define WKSSVC_NETRWKSTAUSERENUM             0x02
#define WKSSVC_NETRUSEENUM                   0x0b
#define WKSSVC_NETRWORKSTATIONSTATISTICSGET  0x0d

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

/*
 * unsigned long NetrWkstaSetInfo(
 *   [in, string, unique] WKSSVC_IDENTIFY_HANDLE ServerName,
 *   [in] unsigned long Level,
 *   [in, switch_is(Level)] LPWKSTA_INFO WkstaInfo,
 *   [in, out, unique] unsigned long *ErrorParameter
 * );
 */
struct wkssvc_NetrWkstaSetInfo_req {
        char *ServerName;
        uint32_t Level;
        union wkssvc_WKSTA_INFO WkstaInfo;
        uint32_t ErrorParameter;
};

struct wkssvc_NetrWkstaSetInfo_rep {
        uint32_t ErrorParameter;

        uint32_t status;
};

/*
 * WKSTA_USER_INFO / WKSTA_USER_ENUM (NetrWkstaUserEnum)
 */
enum WKSTA_USER_INFO_enum {
        WKSTA_USER_INFO_0 = 0,
        WKSTA_USER_INFO_1 = 1,
};

struct wkssvc_WKSTA_USER_INFO_0 {
        char *username;
};
int wkssvc_WKSTA_USER_INFO_0_coder(char *name, struct dcerpc_context *ctx,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr);

struct wkssvc_WKSTA_USER_INFO_0_CONTAINER {
        uint32_t EntriesRead;
        struct wkssvc_WKSTA_USER_INFO_0 *Buffer;
};

struct wkssvc_WKSTA_USER_INFO_1 {
        char *username;
        char *logon_domain;
        char *oth_domains;
        char *logon_server;
};
int wkssvc_WKSTA_USER_INFO_1_coder(char *name, struct dcerpc_context *ctx,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr);

struct wkssvc_WKSTA_USER_INFO_1_CONTAINER {
        uint32_t EntriesRead;
        struct wkssvc_WKSTA_USER_INFO_1 *Buffer;
};

union wkssvc_WKSTA_USER_ENUM_UNION {
        struct wkssvc_WKSTA_USER_INFO_0_CONTAINER Level0;
        struct wkssvc_WKSTA_USER_INFO_1_CONTAINER Level1;
};

struct wkssvc_WKSTA_USER_ENUM_STRUCT {
        uint32_t Level;
        union wkssvc_WKSTA_USER_ENUM_UNION WkstaUserInfo;
};

/*
 * unsigned long NetrWkstaUserEnum(
 *   [in, string, unique] WKSSVC_IDENTIFY_HANDLE ServerName,
 *   [in, out] LPWKSTA_USER_ENUM_STRUCT UserInfo,
 *   [in] unsigned long PreferredMaximumLength,
 *   [out] unsigned long *TotalEntries,
 *   [in, out, unique] unsigned long *ResumeHandle
 * );
 */
struct wkssvc_NetrWkstaUserEnum_req {
        char *ServerName;
        struct wkssvc_WKSTA_USER_ENUM_STRUCT UserInfo;
        uint32_t PreferredMaximumLength;
        uint32_t ResumeHandle;
};

struct wkssvc_NetrWkstaUserEnum_rep {
        struct wkssvc_WKSTA_USER_ENUM_STRUCT UserInfo;
        uint32_t total_entries;
        uint32_t resume_handle;

        uint32_t status;
};

/*
 * USE_INFO / USE_ENUM (NetrUseEnum)
 */
enum USE_INFO_enum {
        USE_INFO_0 = 0,
        USE_INFO_1 = 1,
        USE_INFO_2 = 2,
};

/*
 * typedef struct _USE_INFO_0 {
 *   [string] wchar_t *ui0_local;
 *   [string] wchar_t *ui0_remote;
 * } USE_INFO_0;
 */
struct wkssvc_USE_INFO_0 {
        char *local;
        char *remote;
};
int wkssvc_USE_INFO_0_coder(char *name, struct dcerpc_context *ctx,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr);

struct wkssvc_USE_INFO_0_CONTAINER {
        uint32_t EntriesRead;
        struct wkssvc_USE_INFO_0 *Buffer;
};

/*
 * typedef struct _USE_INFO_1 {
 *   [string] wchar_t *ui1_local;
 *   [string] wchar_t *ui1_remote;
 *   [string] wchar_t *ui1_password;
 *   unsigned long ui1_status;
 *   unsigned long ui1_asg_type;
 *   unsigned long ui1_refcount;
 *   unsigned long ui1_usecount;
 * } USE_INFO_1;
 */
struct wkssvc_USE_INFO_1 {
        char *local;
        char *remote;
        char *password;
        uint32_t status;
        uint32_t asg_type;
        uint32_t refcount;
        uint32_t usecount;
};
int wkssvc_USE_INFO_1_coder(char *name, struct dcerpc_context *ctx,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr);

struct wkssvc_USE_INFO_1_CONTAINER {
        uint32_t EntriesRead;
        struct wkssvc_USE_INFO_1 *Buffer;
};

/*
 * typedef struct _USE_INFO_2 {
 *   [string] wchar_t *ui2_local;
 *   [string] wchar_t *ui2_remote;
 *   [string] wchar_t *ui2_password;
 *   unsigned long ui2_status;
 *   unsigned long ui2_asg_type;
 *   unsigned long ui2_refcount;
 *   unsigned long ui2_usecount;
 *   [string] wchar_t *ui2_username;
 *   [string] wchar_t *ui2_domainname;
 * } USE_INFO_2;
 */
struct wkssvc_USE_INFO_2 {
        char *local;
        char *remote;
        char *password;
        uint32_t status;
        uint32_t asg_type;
        uint32_t refcount;
        uint32_t usecount;
        char *username;
        char *domainname;
};
int wkssvc_USE_INFO_2_coder(char *name, struct dcerpc_context *ctx,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr);

struct wkssvc_USE_INFO_2_CONTAINER {
        uint32_t EntriesRead;
        struct wkssvc_USE_INFO_2 *Buffer;
};

/*
 * typedef [switch_type(unsigned long)] union _USE_ENUM_UNION {
 *   [case(0)] LPUSE_INFO_0_CONTAINER Level0;
 *   [case(1)] LPUSE_INFO_1_CONTAINER Level1;
 *   [case(2)] LPUSE_INFO_2_CONTAINER Level2;
 * } USE_ENUM_UNION;
 */
union wkssvc_USE_ENUM_UNION {
        struct wkssvc_USE_INFO_0_CONTAINER Level0;
        struct wkssvc_USE_INFO_1_CONTAINER Level1;
        struct wkssvc_USE_INFO_2_CONTAINER Level2;
};

/*
 * typedef struct _USE_ENUM_STRUCT {
 *   unsigned long Level;
 *   [switch_is(Level)] USE_ENUM_UNION UseInfo;
 * } USE_ENUM_STRUCT;
 */
struct wkssvc_USE_ENUM_STRUCT {
        uint32_t Level;
        union wkssvc_USE_ENUM_UNION UseInfo;
};

/*
 * unsigned long NetrUseEnum(
 *   [in, string, unique] WKSSVC_IMPERSONATE_HANDLE ServerName,
 *   [in, out] LPUSE_ENUM_STRUCT InfoStruct,
 *   [in] unsigned long PreferedMaximumLength,
 *   [out] unsigned long *TotalEntries,
 *   [in, out, unique] unsigned long *ResumeHandle
 * );
 */
struct wkssvc_NetrUseEnum_req {
        char *ServerName;
        struct wkssvc_USE_ENUM_STRUCT InfoStruct;
        uint32_t PreferedMaximumLength;
        uint32_t ResumeHandle;
};

struct wkssvc_NetrUseEnum_rep {
        struct wkssvc_USE_ENUM_STRUCT InfoStruct;
        uint32_t total_entries;
        uint32_t resume_handle;

        uint32_t status;
};

/*
 * typedef struct _STAT_WORKSTATION_0 {
 *   LARGE_INTEGER StatisticsStartTime;
 *   LARGE_INTEGER BytesReceived;
 *   ... (see MS-WKST 2.2.5.11)
 * } STAT_WORKSTATION_0;
 */
struct wkssvc_STAT_WORKSTATION_0 {
        uint64_t StatisticsStartTime;
        uint64_t BytesReceived;
        uint64_t SmbsReceived;
        uint64_t PagingReadBytesRequested;
        uint64_t NonPagingReadBytesRequested;
        uint64_t CacheReadBytesRequested;
        uint64_t NetworkReadBytesRequested;
        uint64_t BytesTransmitted;
        uint64_t SmbsTransmitted;
        uint64_t PagingWriteBytesRequested;
        uint64_t NonPagingWriteBytesRequested;
        uint64_t CacheWriteBytesRequested;
        uint64_t NetworkWriteBytesRequested;
        uint32_t InitiallyFailedOperations;
        uint32_t FailedCompletionOperations;
        uint32_t ReadOperations;
        uint32_t RandomReadOperations;
        uint32_t ReadSmbs;
        uint32_t LargeReadSmbs;
        uint32_t SmallReadSmbs;
        uint32_t WriteOperations;
        uint32_t RandomWriteOperations;
        uint32_t WriteSmbs;
        uint32_t LargeWriteSmbs;
        uint32_t SmallWriteSmbs;
        uint32_t RawReadsDenied;
        uint32_t RawWritesDenied;
        uint32_t NetworkErrors;
        uint32_t Sessions;
        uint32_t FailedSessions;
        uint32_t Reconnects;
        uint32_t CoreConnects;
        uint32_t Lanman20Connects;
        uint32_t Lanman21Connects;
        uint32_t LanmanNtConnects;
        uint32_t ServerDisconnects;
        uint32_t HungSessions;
        uint32_t UseCount;
        uint32_t FailedUseCount;
        uint32_t CurrentCommands;
};
int wkssvc_STAT_WORKSTATION_0_coder(char *name, struct dcerpc_context *ctx,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr);

/*
 * unsigned long NetrWorkstationStatisticsGet(
 *   [in, string, unique] WKSSVC_IDENTIFY_HANDLE ServerName,
 *   [in, string, unique] wchar_t *ServiceName,
 *   [in] unsigned long Level,
 *   [in] unsigned long Options,
 *   [out] LPSTAT_WORKSTATION_0 *Buffer
 * );
 */
struct wkssvc_NetrWorkstationStatisticsGet_req {
        char *ServerName;
        char *ServiceName;
        uint32_t Level;
        uint32_t Options;
};

struct wkssvc_NetrWorkstationStatisticsGet_rep {
        struct wkssvc_STAT_WORKSTATION_0 Buffer;

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
int wkssvc_NetrWkstaSetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int wkssvc_NetrWkstaSetInfo_rep_coder(char *name, struct dcerpc_context *ctx,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int wkssvc_NetrWkstaUserEnum_req_coder(char *name, struct dcerpc_context *ctx,
                                       struct dcerpc_pdu *pdu,
                                       struct smb2_iovec *iov, int *offset,
                                       void *ptr);
int wkssvc_NetrWkstaUserEnum_rep_coder(char *name, struct dcerpc_context *ctx,
                                       struct dcerpc_pdu *pdu,
                                       struct smb2_iovec *iov, int *offset,
                                       void *ptr);
int wkssvc_NetrUseEnum_req_coder(char *name, struct dcerpc_context *ctx,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr);
int wkssvc_NetrUseEnum_rep_coder(char *name, struct dcerpc_context *ctx,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr);
int wkssvc_NetrWorkstationStatisticsGet_req_coder(char *name, struct dcerpc_context *ctx,
                                                   struct dcerpc_pdu *pdu,
                                                   struct smb2_iovec *iov, int *offset,
                                                   void *ptr);
int wkssvc_NetrWorkstationStatisticsGet_rep_coder(char *name, struct dcerpc_context *ctx,
                                                   struct dcerpc_pdu *pdu,
                                                   struct smb2_iovec *iov, int *offset,
                                                   void *ptr);

extern struct dcerpc_procedure wkssvc_procs[];

#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_DCERPC_WKSSVC_H_ */
