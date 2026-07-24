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

#ifndef _LIBSMB2_DCERPC_SRVSVC_H_
#define _LIBSMB2_DCERPC_SRVSVC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <smb2/libsmb2-dcerpc.h>

#define SRVSVC_NETRCONNECTIONENUM 0x08
#define SRVSVC_NETRFILEENUM       0x09
#define SRVSVC_NETRFILEGETINFO    0x0a
#define SRVSVC_NETRFILECLOSE      0x0b
#define SRVSVC_NETRSESSIONENUM    0x0c
#define SRVSVC_NETRSESSIONDEL     0x0d
#define SRVSVC_NETRSHAREADD       0x0e
#define SRVSVC_NETRSHAREENUM      0x0f
#define SRVSVC_NETRSHAREGETINFO   0x10
#define SRVSVC_NETRSHARESETINFO   0x11
#define SRVSVC_NETRSHAREDEL       0x12
#define SRVSVC_NETRSHAREDELSTICKY 0x13
#define SRVSVC_NETRSHARECHECK     0x14
#define SRVSVC_NETRSERVERGETINFO  0x15
#define SRVSVC_NETRSERVERSETINFO  0x16
#define SRVSVC_NETRSERVERDISKENUM     0x17
#define SRVSVC_NETRSERVERSTATISTICSGET 0x18
#define SRVSVC_NETRREMOTETOD           0x1c

struct dcerpc_context;
struct dcerpc_pdu;


/* Low 2 bits desctibe the type */
#define SHARE_TYPE_DISKTREE  0
#define SHARE_TYPE_PRINTQ    1
#define SHARE_TYPE_DEVICE    2
#define SHARE_TYPE_IPC       3

#define SHARE_TYPE_TEMPORARY 0x40000000
#define SHARE_TYPE_HIDDEN    0x80000000

enum SHARE_INFO_enum {
        SHARE_INFO_0 = 0,
        SHARE_INFO_1 = 1,
        SHARE_INFO_2 = 2,
};

struct srvsvc_SHARE_INFO_0 {
        char *netname;
};
int srvsvc_SHARE_INFO_0_coder(char *name, struct dcerpc_context *ctx,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr);

struct srvsvc_SHARE_INFO_0_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_0 *share_info_0;
};

struct srvsvc_SHARE_INFO_1 {
        char *netname;
        uint32_t type;
        char *remark;
};
int srvsvc_SHARE_INFO_1_coder(char *name, struct dcerpc_context *ctx,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr);

struct srvsvc_SHARE_INFO_1_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_1 *share_info_1;
};
        
int srvsvc_SHARE_INFO_1_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                        struct dcerpc_pdu *pdu,
                                        struct smb2_iovec *iov, int *offset,
                                        void *ptr);

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
int srvsvc_SHARE_INFO_2_coder(char *name, struct dcerpc_context *ctx,
                              struct dcerpc_pdu *pdu,
                              struct smb2_iovec *iov, int *offset,
                              void *ptr);

struct srvsvc_SHARE_INFO_2_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_2 *share_info_2;
};
        
int srvsvc_SHARE_INFO_2_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                                        struct dcerpc_pdu *pdu,
                                        struct smb2_iovec *iov, int *offset,
                                        void *ptr);

union srvsvc_SHARE_ENUM_UNION {
        struct srvsvc_SHARE_INFO_0_CONTAINER Level0;
        struct srvsvc_SHARE_INFO_1_CONTAINER Level1;
        struct srvsvc_SHARE_INFO_2_CONTAINER Level2;
};

struct srvsvc_SHARE_ENUM_STRUCT {
        uint32_t Level;
        union srvsvc_SHARE_ENUM_UNION ShareEnum;
};

union srvsvc_SHARE_INFO {
        struct srvsvc_SHARE_INFO_0 ShareInfo0;
        struct srvsvc_SHARE_INFO_1 ShareInfo1;
        struct srvsvc_SHARE_INFO_2 ShareInfo2;
};

struct srvsvc_SERVER_INFO_100 {
        uint32_t platform_id;
        char *name;
};

struct srvsvc_SERVER_INFO_101 {
        uint32_t platform_id;
        char *name;
        uint32_t version_major;
        uint32_t version_minor;
        uint32_t type;
        char *comment;
};
        
struct srvsvc_SERVER_INFO_102 {
        uint32_t platform_id;
        char *name;
        uint32_t version_major;
        uint32_t version_minor;
        uint32_t type;
        char *comment;
        uint32_t users;
        uint32_t disc;
        uint32_t hidden;
        uint32_t announce;
        uint32_t anndelta;
        uint32_t licenses;
        char *userpath;
};
        
struct srvsvc_SERVER_INFO_103 {
        uint32_t platform_id;
        char *name;
        uint32_t version_major;
        uint32_t version_minor;
        uint32_t type;
        char *comment;
        uint32_t users;
        uint32_t disc;
        uint32_t hidden;
        uint32_t announce;
        uint32_t anndelta;
        uint32_t licenses;
        char *userpath;
        uint32_t capabilities;
};

struct srvsvc_SERVER_INFO_502 {
        uint32_t sessopens;
        uint32_t sessvcs;
        uint32_t opensearch;
        uint32_t sizreqbuf;
        uint32_t initworkitems;
        uint32_t maxworkitems;
        uint32_t rawworkitems;
        uint32_t irpstacksize;
        uint32_t maxrawbuflen;
        uint32_t sessusers;
        uint32_t sessconns;
        uint32_t maxpagedmemoryusage;
        uint32_t maxnonpagedmemoryusage;
        uint32_t enablesoftcompat;
        uint32_t enableforcedlogoff;
        uint32_t timesource;
        uint32_t acceptdownlevelapis;
        uint32_t lmannounce;
};

struct srvsvc_SERVER_INFO_503 {
        uint32_t sessopens;
        uint32_t sessvcs;
        uint32_t opensearch;
        uint32_t sizreqbuf;
        uint32_t initworkitems;
        uint32_t maxworkitems;
        uint32_t rawworkitems;
        uint32_t irpstacksize;
        uint32_t maxrawbuflen;
        uint32_t sessusers;
        uint32_t sessconns;
        uint32_t maxpagedmemoryusage;
        uint32_t maxnonpagedmemoryusage;
        uint32_t enablesoftcompat;
        uint32_t enableforcedlogoff;
        uint32_t timesource;
        uint32_t acceptdownlevelapis;
        uint32_t lmannounce;
        char *domain;
        uint32_t maxcopyreadlen;
        uint32_t maxcopywritelen;
        uint32_t minkeepsearch;
        uint32_t maxkeepsearch;
        uint32_t minkeepcomplsearch;
        uint32_t maxkeepcomplsearch;
        uint32_t threadcountadd;
        uint32_t numblockthreads;
        uint32_t scavtimeout;
        uint32_t minrcvqueue;
        uint32_t minfreeworkitems;
        uint32_t xactmemsize;
        uint32_t threadpriority;
        uint32_t maxmpxct;
        uint32_t oplockbreakwait;
        uint32_t oplockbreakresponsewait;
        uint32_t enableoplocks;
        uint32_t enableoplockforceclose;
        uint32_t enablefcbopens;
        uint32_t enableraw;
        uint32_t enablesharednetdrives;
        uint32_t minfreeconnections;
        uint32_t maxfreeconnections;
};
        
union srvsvc_SERVER_INFO {
        struct srvsvc_SERVER_INFO_100 ServerInfo100;
        struct srvsvc_SERVER_INFO_101 ServerInfo101;
        struct srvsvc_SERVER_INFO_102 ServerInfo102;
        struct srvsvc_SERVER_INFO_103 ServerInfo103;
        struct srvsvc_SERVER_INFO_502 ServerInfo502;
        struct srvsvc_SERVER_INFO_503 ServerInfo503;
};
        
/*
 * CONNECTION_INFO / CONNECT_ENUM (NetrConnectionEnum)
 */
enum CONNECTION_INFO_enum {
        CONNECTION_INFO_0 = 0,
        CONNECTION_INFO_1 = 1,
};

struct srvsvc_CONNECTION_INFO_0 {
        uint32_t id;
};
int srvsvc_CONNECTION_INFO_0_coder(char *name, struct dcerpc_context *ctx,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr);

struct srvsvc_CONNECT_INFO_0_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_CONNECTION_INFO_0 *connection_info_0;
};

struct srvsvc_CONNECTION_INFO_1 {
        uint32_t id;
        uint32_t type;
        uint32_t num_opens;
        uint32_t num_users;
        uint32_t time;
        char *username;
        char *netname;
};
int srvsvc_CONNECTION_INFO_1_coder(char *name, struct dcerpc_context *ctx,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr);

struct srvsvc_CONNECT_INFO_1_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_CONNECTION_INFO_1 *connection_info_1;
};

union srvsvc_CONNECT_ENUM_UNION {
        struct srvsvc_CONNECT_INFO_0_CONTAINER Level0;
        struct srvsvc_CONNECT_INFO_1_CONTAINER Level1;
};

struct srvsvc_CONNECT_ENUM_STRUCT {
        uint32_t Level;
        union srvsvc_CONNECT_ENUM_UNION ConnectEnum;
};

struct srvsvc_NetrConnectionEnum_req {
        char *ServerName;
        char *Qualifier;
        struct srvsvc_CONNECT_ENUM_STRUCT ces;
        uint32_t PreferedMaximumLength;
        uint32_t ResumeHandle;
};

struct srvsvc_NetrConnectionEnum_rep {
        struct srvsvc_CONNECT_ENUM_STRUCT ces;
        uint32_t total_entries;
        uint32_t resume_handle;

        uint32_t status;
};

/*
 * FILE_INFO / FILE_ENUM (NetrFileEnum)
 */
enum FILE_INFO_enum {
        FILE_INFO_2 = 2,
        FILE_INFO_3 = 3,
};

struct srvsvc_FILE_INFO_2 {
        uint32_t id;
};
int srvsvc_FILE_INFO_2_coder(char *name, struct dcerpc_context *ctx,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr);

struct srvsvc_FILE_INFO_2_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_FILE_INFO_2 *file_info_2;
};

struct srvsvc_FILE_INFO_3 {
        uint32_t id;
        uint32_t permissions;
        uint32_t num_locks;
        char *pathname;
        char *username;
};
int srvsvc_FILE_INFO_3_coder(char *name, struct dcerpc_context *ctx,
                             struct dcerpc_pdu *pdu,
                             struct smb2_iovec *iov, int *offset,
                             void *ptr);

struct srvsvc_FILE_INFO_3_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_FILE_INFO_3 *file_info_3;
};

union srvsvc_FILE_ENUM_UNION {
        struct srvsvc_FILE_INFO_2_CONTAINER Level2;
        struct srvsvc_FILE_INFO_3_CONTAINER Level3;
};

struct srvsvc_FILE_ENUM_STRUCT {
        uint32_t Level;
        union srvsvc_FILE_ENUM_UNION FileInfo;
};

struct srvsvc_NetrFileEnum_req {
        char *ServerName;
        char *BasePath;
        char *UserName;
        struct srvsvc_FILE_ENUM_STRUCT fes;
        uint32_t PreferedMaximumLength;
        uint32_t ResumeHandle;
};

struct srvsvc_NetrFileEnum_rep {
        struct srvsvc_FILE_ENUM_STRUCT fes;
        uint32_t total_entries;
        uint32_t resume_handle;

        uint32_t status;
};

/*
 * FILE_INFO union used by NetrFileGetInfo
 * typedef [switch_type(unsigned long)] union _FILE_INFO {
 *   [case(2)] LPFILE_INFO_2 FileInfo2;
 *   [case(3)] LPFILE_INFO_3 FileInfo3;
 * } FILE_INFO, *PFILE_INFO, *LPFILE_INFO;
 */
union srvsvc_FILE_INFO {
        struct srvsvc_FILE_INFO_2 FileInfo2;
        struct srvsvc_FILE_INFO_3 FileInfo3;
};

struct srvsvc_NetrFileGetInfo_req {
        char *ServerName;
        uint32_t FileId;
        uint32_t Level;
};

struct srvsvc_NetrFileGetInfo_rep {
        union srvsvc_FILE_INFO InfoStruct;

        uint32_t status;
};

struct srvsvc_NetrFileClose_req {
        char *ServerName;
        uint32_t FileId;
};

struct srvsvc_NetrFileClose_rep {
        uint32_t status;
};

/*
 * SESSION_INFO / SESSION_ENUM (NetrSessionEnum)
 */
enum SESSION_INFO_enum {
        SESSION_INFO_0 = 0,
        SESSION_INFO_1 = 1,
        SESSION_INFO_2 = 2,
        SESSION_INFO_10 = 10,
        SESSION_INFO_502 = 502,
};

struct srvsvc_SESSION_INFO_0 {
        char *cname;
};
int srvsvc_SESSION_INFO_0_coder(char *name, struct dcerpc_context *ctx,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr);

struct srvsvc_SESSION_INFO_0_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SESSION_INFO_0 *session_info_0;
};

struct srvsvc_SESSION_INFO_1 {
        char *cname;
        char *username;
        uint32_t num_opens;
        uint32_t time;
        uint32_t idle_time;
        uint32_t user_flags;
};
int srvsvc_SESSION_INFO_1_coder(char *name, struct dcerpc_context *ctx,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr);

struct srvsvc_SESSION_INFO_1_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SESSION_INFO_1 *session_info_1;
};

struct srvsvc_SESSION_INFO_2 {
        char *cname;
        char *username;
        uint32_t num_opens;
        uint32_t time;
        uint32_t idle_time;
        uint32_t user_flags;
        char *cltype_name;
};
int srvsvc_SESSION_INFO_2_coder(char *name, struct dcerpc_context *ctx,
                                struct dcerpc_pdu *pdu,
                                struct smb2_iovec *iov, int *offset,
                                void *ptr);

struct srvsvc_SESSION_INFO_2_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SESSION_INFO_2 *session_info_2;
};

struct srvsvc_SESSION_INFO_10 {
        char *cname;
        char *username;
        uint32_t time;
        uint32_t idle_time;
};
int srvsvc_SESSION_INFO_10_coder(char *name, struct dcerpc_context *ctx,
                                 struct dcerpc_pdu *pdu,
                                 struct smb2_iovec *iov, int *offset,
                                 void *ptr);

struct srvsvc_SESSION_INFO_10_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SESSION_INFO_10 *session_info_10;
};

struct srvsvc_SESSION_INFO_502 {
        char *cname;
        char *username;
        uint32_t num_opens;
        uint32_t time;
        uint32_t idle_time;
        uint32_t user_flags;
        char *cltype_name;
        char *transport;
};
int srvsvc_SESSION_INFO_502_coder(char *name, struct dcerpc_context *ctx,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr);

struct srvsvc_SESSION_INFO_502_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SESSION_INFO_502 *session_info_502;
};

union srvsvc_SESSION_ENUM_UNION {
        struct srvsvc_SESSION_INFO_0_CONTAINER Level0;
        struct srvsvc_SESSION_INFO_1_CONTAINER Level1;
        struct srvsvc_SESSION_INFO_2_CONTAINER Level2;
        struct srvsvc_SESSION_INFO_10_CONTAINER Level10;
        struct srvsvc_SESSION_INFO_502_CONTAINER Level502;
};

struct srvsvc_SESSION_ENUM_STRUCT {
        uint32_t Level;
        union srvsvc_SESSION_ENUM_UNION SessionInfo;
};

struct srvsvc_NetrSessionEnum_req {
        char *ServerName;
        char *ClientName;
        char *UserName;
        struct srvsvc_SESSION_ENUM_STRUCT ses;
        uint32_t PreferedMaximumLength;
        uint32_t ResumeHandle;
};

struct srvsvc_NetrSessionEnum_rep {
        struct srvsvc_SESSION_ENUM_STRUCT ses;
        uint32_t total_entries;
        uint32_t resume_handle;

        uint32_t status;
};

struct srvsvc_NetrSessionDel_req {
        char *ServerName;
        char *ClientName;
        char *UserName;
};

struct srvsvc_NetrSessionDel_rep {
        uint32_t status;
};

struct srvsvc_NetrShareAdd_req {
        char *ServerName;
        uint32_t Level;
        union srvsvc_SHARE_INFO InfoStruct;
        uint32_t ParmErr;
};

struct srvsvc_NetrShareAdd_rep {
        uint32_t ParmErr;

        uint32_t status;
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

struct srvsvc_NetrShareGetInfo_req {
        char *ServerName;
        char *NetName;
        uint32_t Level;
};

struct srvsvc_NetrShareGetInfo_rep {
        union srvsvc_SHARE_INFO InfoStruct;

        uint32_t status;
};

struct srvsvc_NetrShareSetInfo_req {
        char *ServerName;
        char *NetName;
        uint32_t Level;
        union srvsvc_SHARE_INFO InfoStruct;
        uint32_t ParmErr;
};

struct srvsvc_NetrShareSetInfo_rep {
        uint32_t ParmErr;

        uint32_t status;
};

struct srvsvc_NetrShareDel_req {
        char *ServerName;
        char *NetName;
        uint32_t Reserved;
};

struct srvsvc_NetrShareDel_rep {

        uint32_t status;
};

struct srvsvc_NetrShareCheck_req {
        char *ServerName;
        char *Device;
};

struct srvsvc_NetrShareCheck_rep {
        uint32_t Type;

        uint32_t status;
};

struct srvsvc_NetrServerGetInfo_req {
        char *ServerName;
        uint32_t Level;
};

struct srvsvc_NetrServerGetInfo_rep {
        union srvsvc_SERVER_INFO InfoStruct;

        uint32_t status;
};

struct srvsvc_NetrServerSetInfo_req {
        char *ServerName;
        uint32_t Level;
        union srvsvc_SERVER_INFO InfoStruct;
        uint32_t ParmErr;
};

struct srvsvc_NetrServerSetInfo_rep {
        uint32_t ParmErr;

        uint32_t status;
};

/*
 * DISK_INFO / DISK_ENUM (NetrServerDiskEnum)
 *
 * typedef struct _DISK_INFO {
 *   [string] WCHAR Disk[3];
 * } DISK_INFO;
 *
 * MIDL encodes Disk as a varying UTF-16 string (offset + actual_count +
 * data), not a conformant-varying string.
 */
struct srvsvc_DISK_INFO {
        char *disk;
};
int srvsvc_DISK_INFO_coder(char *name, struct dcerpc_context *ctx,
                           struct dcerpc_pdu *pdu,
                           struct smb2_iovec *iov, int *offset,
                           void *ptr);

struct srvsvc_DISK_ENUM_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_DISK_INFO *disk_info;
};

struct srvsvc_NetrServerDiskEnum_req {
        char *ServerName;
        uint32_t Level;
        struct srvsvc_DISK_ENUM_CONTAINER DiskInfoStruct;
        uint32_t PreferedMaximumLength;
        uint32_t ResumeHandle;
};

struct srvsvc_NetrServerDiskEnum_rep {
        struct srvsvc_DISK_ENUM_CONTAINER DiskInfoStruct;
        uint32_t total_entries;
        uint32_t resume_handle;

        uint32_t status;
};

/*
 * STAT_SERVER_0 / NetrServerStatisticsGet
 */
struct srvsvc_STAT_SERVER_0 {
        uint32_t start;
        uint32_t fopens;
        uint32_t devopens;
        uint32_t jobsqueued;
        uint32_t sopens;
        uint32_t stimedout;
        uint32_t serrorout;
        uint32_t pwerrors;
        uint32_t permerrors;
        uint32_t syserrors;
        uint32_t bytessent_low;
        uint32_t bytessent_high;
        uint32_t bytesrcvd_low;
        uint32_t bytesrcvd_high;
        uint32_t avresponse;
        uint32_t reqbufneed;
        uint32_t bigbufneed;
};
int srvsvc_STAT_SERVER_0_coder(char *name, struct dcerpc_context *ctx,
                               struct dcerpc_pdu *pdu,
                               struct smb2_iovec *iov, int *offset,
                               void *ptr);

struct srvsvc_NetrServerStatisticsGet_req {
        char *ServerName;
        char *Service;
        uint32_t Level;
        uint32_t Options;
};

struct srvsvc_NetrServerStatisticsGet_rep {
        struct srvsvc_STAT_SERVER_0 InfoStruct;

        uint32_t status;
};

/*
 * TIME_OF_DAY_INFO / NetrRemoteTOD
 */
struct srvsvc_TIME_OF_DAY_INFO {
        uint32_t elapsedt;
        uint32_t msecs;
        uint32_t hours;
        uint32_t mins;
        uint32_t secs;
        uint32_t hunds;
        int32_t timezone;       /* minutes from UTC (signed) */
        uint32_t tinterval;
        uint32_t day;
        uint32_t month;
        uint32_t year;
        uint32_t weekday;
};
int srvsvc_TIME_OF_DAY_INFO_coder(char *name, struct dcerpc_context *ctx,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr);

struct srvsvc_NetrRemoteTOD_req {
        char *ServerName;
};

struct srvsvc_NetrRemoteTOD_rep {
        struct srvsvc_TIME_OF_DAY_INFO BufferPtr;

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


int srvsvc_NetrConnectionEnum_rep_coder(char *name, struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         struct smb2_iovec *iov, int *offset,
                                         void *ptr);
int srvsvc_NetrConnectionEnum_req_coder(char *name, struct dcerpc_context *ctx,
                                         struct dcerpc_pdu *pdu,
                                         struct smb2_iovec *iov, int *offset,
                                         void *ptr);
int srvsvc_NetrFileEnum_rep_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr);
int srvsvc_NetrFileEnum_req_coder(char *name, struct dcerpc_context *ctx,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr);
int srvsvc_NetrFileGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrFileGetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrFileClose_rep_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr);
int srvsvc_NetrFileClose_req_coder(char *name, struct dcerpc_context *ctx,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr);
int srvsvc_NetrSessionEnum_rep_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrSessionEnum_req_coder(char *name, struct dcerpc_context *ctx,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrSessionDel_rep_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr);
int srvsvc_NetrSessionDel_req_coder(char *name, struct dcerpc_context *ctx,
                                     struct dcerpc_pdu *pdu,
                                     struct smb2_iovec *iov, int *offset,
                                     void *ptr);
int srvsvc_NetrShareEnum_rep_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr);
int srvsvc_NetrShareEnum_req_coder(char *name, struct dcerpc_context *ctx,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr);
int srvsvc_NetrShareGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrShareGetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrShareSetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrShareSetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                      struct dcerpc_pdu *pdu,
                                      struct smb2_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrShareDel_req_coder(char *name, struct dcerpc_context *ctx,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr);
int srvsvc_NetrShareDel_rep_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct smb2_iovec *iov, int *offset,
                                  void *ptr);
int srvsvc_NetrServerGetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                       struct dcerpc_pdu *pdu,
                                       struct smb2_iovec *iov, int *offset,
                                       void *ptr);
int srvsvc_NetrServerGetInfo_rep_coder(char *name, struct dcerpc_context *ctx,
                                       struct dcerpc_pdu *pdu,
                                       struct smb2_iovec *iov, int *offset,
                                       void *ptr);
int srvsvc_NetrServerSetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                        struct dcerpc_pdu *pdu,
                                        struct smb2_iovec *iov, int *offset,
                                        void *ptr);
int srvsvc_NetrServerSetInfo_rep_coder(char *name, struct dcerpc_context *ctx,
                                        struct dcerpc_pdu *pdu,
                                        struct smb2_iovec *iov, int *offset,
                                        void *ptr);
int srvsvc_NetrServerDiskEnum_req_coder(char *name, struct dcerpc_context *ctx,
                                         struct dcerpc_pdu *pdu,
                                         struct smb2_iovec *iov, int *offset,
                                         void *ptr);
int srvsvc_NetrServerDiskEnum_rep_coder(char *name, struct dcerpc_context *ctx,
                                         struct dcerpc_pdu *pdu,
                                         struct smb2_iovec *iov, int *offset,
                                         void *ptr);
int srvsvc_NetrServerStatisticsGet_req_coder(char *name, struct dcerpc_context *ctx,
                                              struct dcerpc_pdu *pdu,
                                              struct smb2_iovec *iov, int *offset,
                                              void *ptr);
int srvsvc_NetrServerStatisticsGet_rep_coder(char *name, struct dcerpc_context *ctx,
                                              struct dcerpc_pdu *pdu,
                                              struct smb2_iovec *iov, int *offset,
                                              void *ptr);
int srvsvc_NetrRemoteTOD_req_coder(char *name, struct dcerpc_context *ctx,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr);
int srvsvc_NetrRemoteTOD_rep_coder(char *name, struct dcerpc_context *ctx,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr);

extern struct dcerpc_procedure srvsvc_procs[];
        
#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_DCERPC_SRVSVC_H_ */
