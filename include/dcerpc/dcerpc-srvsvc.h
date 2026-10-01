/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2018 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _DCERPC_SRVSVC_H_
#define _DCERPC_SRVSVC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>

/* Low 2 bits describe the share type (STYPE_*) */
#define SRVSVC_SHARE_TYPE_DISKTREE   0
#define SRVSVC_SHARE_TYPE_PRINTQ     1
#define SRVSVC_SHARE_TYPE_DEVICE     2
#define SRVSVC_SHARE_TYPE_IPC        3
#define SRVSVC_SHARE_TYPE_TEMPORARY  0x40000000
#define SRVSVC_SHARE_TYPE_HIDDEN     0x80000000 /* STYPE_SPECIAL */

/*
 * NetrShareEnum and NetrShareGetInfo: SHARE_INFO levels 0, 1, 2, 501, 502,
 * 503, 1004, 1005, 1006 and 1501, SHARE_ENUM_STRUCT and the SHARE_INFO
 * union, generated from the [MS-SRVS] IDL. Field names follow the IDL.
 */
struct srvsvc_SHARE_INFO_0 {
        char * shi0_netname;
};

struct srvsvc_SHARE_INFO_0_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_0 * Buffer;
};

struct srvsvc_SHARE_INFO_1 {
        char * shi1_netname;
        uint32_t shi1_type;
        char * shi1_remark;
};

struct srvsvc_SHARE_INFO_1_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_1 * Buffer;
};

struct srvsvc_SHARE_INFO_2 {
        char * shi2_netname;
        uint32_t shi2_type;
        char * shi2_remark;
        uint32_t shi2_permissions;
        uint32_t shi2_max_uses;
        uint32_t shi2_current_uses;
        char * shi2_path;
        char * shi2_passwd;
};

struct srvsvc_SHARE_INFO_2_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_2 * Buffer;
};

struct srvsvc_SHARE_INFO_501 {
        char * shi501_netname;
        uint32_t shi501_type;
        char * shi501_remark;
        uint32_t shi501_flags;
};

struct srvsvc_SHARE_INFO_501_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_501 * Buffer;
};

struct srvsvc_SHARE_INFO_502_I {
        char * shi502_netname;
        uint32_t shi502_type;
        char * shi502_remark;
        uint32_t shi502_permissions;
        uint32_t shi502_max_uses;
        uint32_t shi502_current_uses;
        char * shi502_path;
        char * shi502_passwd;
        uint32_t shi502_reserved;
        SECURITY_DESCRIPTOR * shi502_security_descriptor;
};

struct srvsvc_SHARE_INFO_502_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_502_I * Buffer;
};

struct srvsvc_SHARE_INFO_503_I {
        char * shi503_netname;
        uint32_t shi503_type;
        char * shi503_remark;
        uint32_t shi503_permissions;
        uint32_t shi503_max_uses;
        uint32_t shi503_current_uses;
        char * shi503_path;
        char * shi503_passwd;
        char * shi503_servername;
        uint32_t shi503_reserved;
        SECURITY_DESCRIPTOR * shi503_security_descriptor;
};

struct srvsvc_SHARE_INFO_503_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SHARE_INFO_503_I * Buffer;
};

struct srvsvc_SHARE_INFO_1004 {
        char * shi1004_remark;
};

struct srvsvc_SHARE_INFO_1005 {
        uint32_t shi1005_flags;
};

struct srvsvc_SHARE_INFO_1006 {
        uint32_t shi1006_max_uses;
};

struct srvsvc_SHARE_INFO_1501_I {
        uint32_t shi1501_reserved;
        SECURITY_DESCRIPTOR * shi1501_security_descriptor;
};

union srvsvc_SHARE_ENUM_UNION {
        struct srvsvc_SHARE_INFO_0_CONTAINER Level0;
        struct srvsvc_SHARE_INFO_1_CONTAINER Level1;
        struct srvsvc_SHARE_INFO_2_CONTAINER Level2;
        struct srvsvc_SHARE_INFO_501_CONTAINER Level501;
        struct srvsvc_SHARE_INFO_502_CONTAINER Level502;
        struct srvsvc_SHARE_INFO_503_CONTAINER Level503;
};

struct srvsvc_SHARE_ENUM_STRUCT {
        uint32_t Level;
        union srvsvc_SHARE_ENUM_UNION ShareInfo;
};

union srvsvc_SHARE_INFO {
        struct srvsvc_SHARE_INFO_0 ShareInfo0;
        struct srvsvc_SHARE_INFO_1 ShareInfo1;
        struct srvsvc_SHARE_INFO_2 ShareInfo2;
        struct srvsvc_SHARE_INFO_502_I ShareInfo502;
        struct srvsvc_SHARE_INFO_1004 ShareInfo1004;
        struct srvsvc_SHARE_INFO_1006 ShareInfo1006;
        struct srvsvc_SHARE_INFO_1501_I ShareInfo1501;
        struct srvsvc_SHARE_INFO_1005 ShareInfo1005;
        struct srvsvc_SHARE_INFO_501 ShareInfo501;
        struct srvsvc_SHARE_INFO_503_I ShareInfo503;
};

struct srvsvc_NetrShareEnum_req {
        char * ServerName;
        struct srvsvc_SHARE_ENUM_STRUCT InfoStruct;
        uint32_t PreferedMaximumLength;
        uint32_t ResumeHandle;
};

struct srvsvc_NetrShareEnum_rep {
        struct srvsvc_SHARE_ENUM_STRUCT InfoStruct;
        uint32_t TotalEntries;
        uint32_t ResumeHandle;
        uint32_t status;
};

struct srvsvc_NetrShareGetInfo_req {
        char * ServerName;
        char * NetName;
        uint32_t Level;
};

struct srvsvc_NetrShareGetInfo_rep {
        union srvsvc_SHARE_INFO InfoStruct;
        uint32_t status;
};

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
#define SRVSVC_NETRSERVERSTATISTICSGET 0x18
#define SRVSVC_NETRREMOTETOD           0x1c

struct dcerpc_context;
struct dcerpc_pdu;

/* PLATFORM_ID_* — SERVER_INFO / WKSTA_INFO platform_id */
#define SRVSVC_PLATFORM_ID_DOS  300
#define SRVSVC_PLATFORM_ID_OS2  400
#define SRVSVC_PLATFORM_ID_NT   500
#define SRVSVC_PLATFORM_ID_OSF  600
#define SRVSVC_PLATFORM_ID_VMS  700

/* Legacy share access bits (SHARE_INFO_2.permissions / ACCESS_*) */
#define SRVSVC_ACCESS_READ    0x00000001
#define SRVSVC_ACCESS_WRITE   0x00000002
#define SRVSVC_ACCESS_CREATE  0x00000004
#define SRVSVC_ACCESS_EXEC    0x00000008
#define SRVSVC_ACCESS_DELETE  0x00000010
#define SRVSVC_ACCESS_ATRIB   0x00000020
#define SRVSVC_ACCESS_PERM    0x00000040
#define SRVSVC_ACCESS_ALL     0x0000007f

/* Open file permissions (FILE_INFO_3.permissions / PERM_FILE_*) */
#define SRVSVC_PERM_FILE_READ    0x00000001
#define SRVSVC_PERM_FILE_WRITE   0x00000002
#define SRVSVC_PERM_FILE_CREATE  0x00000004

/* Session user flags (SESSION_INFO_*.user_flags) */
#define SRVSVC_SESS_GUEST         0x00000001
#define SRVSVC_SESS_NOENCRYPTION  0x00000002

/* Software type flags (SERVER_INFO_*.type / SV_TYPE_*) */
#define SRVSVC_SV_TYPE_WORKSTATION        0x00000001
#define SRVSVC_SV_TYPE_SERVER             0x00000002
#define SRVSVC_SV_TYPE_SQLSERVER          0x00000004
#define SRVSVC_SV_TYPE_DOMAIN_CTRL        0x00000008
#define SRVSVC_SV_TYPE_DOMAIN_BAKCTRL     0x00000010
#define SRVSVC_SV_TYPE_TIME_SOURCE        0x00000020
#define SRVSVC_SV_TYPE_AFP                0x00000040
#define SRVSVC_SV_TYPE_NOVELL             0x00000080
#define SRVSVC_SV_TYPE_DOMAIN_MEMBER      0x00000100
#define SRVSVC_SV_TYPE_PRINTQ_SERVER      0x00000200
#define SRVSVC_SV_TYPE_DIALIN_SERVER      0x00000400
#define SRVSVC_SV_TYPE_XENIX_SERVER       0x00000800
#define SRVSVC_SV_TYPE_NT                 0x00001000
#define SRVSVC_SV_TYPE_WFW                0x00002000
#define SRVSVC_SV_TYPE_SERVER_MFPN        0x00004000
#define SRVSVC_SV_TYPE_SERVER_NT          0x00008000
#define SRVSVC_SV_TYPE_POTENTIAL_BROWSER  0x00010000
#define SRVSVC_SV_TYPE_BACKUP_BROWSER     0x00020000
#define SRVSVC_SV_TYPE_MASTER_BROWSER     0x00040000
#define SRVSVC_SV_TYPE_DOMAIN_MASTER      0x00080000
#define SRVSVC_SV_TYPE_WINDOWS            0x00400000
#define SRVSVC_SV_TYPE_DFS                0x00800000
#define SRVSVC_SV_TYPE_CLUSTER_NT         0x01000000
#define SRVSVC_SV_TYPE_TERMINALSERVER     0x02000000
#define SRVSVC_SV_TYPE_CLUSTER_VS_NT      0x04000000
#define SRVSVC_SV_TYPE_DCE                0x10000000
#define SRVSVC_SV_TYPE_ALTERNATE_XPORT    0x20000000
#define SRVSVC_SV_TYPE_LOCAL_LIST_ONLY    0x40000000
#define SRVSVC_SV_TYPE_DOMAIN_ENUM        0x80000000

int srvsvc_SHARE_INFO_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_0_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_0_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_0_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_1_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_1_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_1_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_1_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_2_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_2_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_2_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_2_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_501_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_501_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_501_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_501_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_502_I_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_502_I_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_502_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_502_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_503_I_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_503_I_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_503_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_503_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_1004_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_1004_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_1005_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_1005_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_1006_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_1006_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_1501_I_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_1501_I_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_ENUM_STRUCT_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SHARE_INFO_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_switch_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

struct srvsvc_SERVER_INFO_100 {
        uint32_t sv100_platform_id;
        char * sv100_name;
};

struct srvsvc_SERVER_INFO_101 {
        uint32_t sv101_platform_id;
        char * sv101_name;
        uint32_t sv101_version_major;
        uint32_t sv101_version_minor;
        uint32_t sv101_type;
        char * sv101_comment;
};

struct srvsvc_SERVER_INFO_102 {
        uint32_t sv102_platform_id;
        char * sv102_name;
        uint32_t sv102_version_major;
        uint32_t sv102_version_minor;
        uint32_t sv102_type;
        char * sv102_comment;
        uint32_t sv102_users;
        int32_t sv102_disc;
        int32_t sv102_hidden;
        uint32_t sv102_announce;
        uint32_t sv102_anndelta;
        uint32_t sv102_licenses;
        char * sv102_userpath;
};

struct srvsvc_SERVER_INFO_103 {
        uint32_t sv103_platform_id;
        char * sv103_name;
        uint32_t sv103_version_major;
        uint32_t sv103_version_minor;
        uint32_t sv103_type;
        char * sv103_comment;
        uint32_t sv103_users;
        int32_t sv103_disc;
        int32_t sv103_hidden;
        uint32_t sv103_announce;
        uint32_t sv103_anndelta;
        uint32_t sv103_licenses;
        char * sv103_userpath;
        uint32_t sv103_capabilities;
};

struct srvsvc_SERVER_INFO_502 {
        uint32_t sv502_sessopens;
        uint32_t sv502_sessvcs;
        uint32_t sv502_opensearch;
        uint32_t sv502_sizreqbuf;
        uint32_t sv502_initworkitems;
        uint32_t sv502_maxworkitems;
        uint32_t sv502_rawworkitems;
        uint32_t sv502_irpstacksize;
        uint32_t sv502_maxrawbuflen;
        uint32_t sv502_sessusers;
        uint32_t sv502_sessconns;
        uint32_t sv502_maxpagedmemoryusage;
        uint32_t sv502_maxnonpagedmemoryusage;
        int32_t sv502_enablesoftcompat;
        int32_t sv502_enableforcedlogoff;
        int32_t sv502_timesource;
        int32_t sv502_acceptdownlevelapis;
        int32_t sv502_lmannounce;
};

struct srvsvc_SERVER_INFO_503 {
        uint32_t sv503_sessopens;
        uint32_t sv503_sessvcs;
        uint32_t sv503_opensearch;
        uint32_t sv503_sizreqbuf;
        uint32_t sv503_initworkitems;
        uint32_t sv503_maxworkitems;
        uint32_t sv503_rawworkitems;
        uint32_t sv503_irpstacksize;
        uint32_t sv503_maxrawbuflen;
        uint32_t sv503_sessusers;
        uint32_t sv503_sessconns;
        uint32_t sv503_maxpagedmemoryusage;
        uint32_t sv503_maxnonpagedmemoryusage;
        int32_t sv503_enablesoftcompat;
        int32_t sv503_enableforcedlogoff;
        int32_t sv503_timesource;
        int32_t sv503_acceptdownlevelapis;
        int32_t sv503_lmannounce;
        char * sv503_domain;
        uint32_t sv503_maxcopyreadlen;
        uint32_t sv503_maxcopywritelen;
        uint32_t sv503_minkeepsearch;
        uint32_t sv503_maxkeepsearch;
        uint32_t sv503_minkeepcomplsearch;
        uint32_t sv503_maxkeepcomplsearch;
        uint32_t sv503_threadcountadd;
        uint32_t sv503_numblockthreads;
        uint32_t sv503_scavtimeout;
        uint32_t sv503_minrcvqueue;
        uint32_t sv503_minfreeworkitems;
        uint32_t sv503_xactmemsize;
        uint32_t sv503_threadpriority;
        uint32_t sv503_maxmpxct;
        uint32_t sv503_oplockbreakwait;
        uint32_t sv503_oplockbreakresponsewait;
        int32_t sv503_enableoplocks;
        int32_t sv503_enableoplockforceclose;
        int32_t sv503_enablefcbopens;
        int32_t sv503_enableraw;
        int32_t sv503_enablesharednetdrives;
        uint32_t sv503_minfreeconnections;
        uint32_t sv503_maxfreeconnections;
};

union srvsvc_SERVER_INFO {
        struct srvsvc_SERVER_INFO_100 ServerInfo100;
        struct srvsvc_SERVER_INFO_101 ServerInfo101;
        struct srvsvc_SERVER_INFO_102 ServerInfo102;
        struct srvsvc_SERVER_INFO_103 ServerInfo103;
        struct srvsvc_SERVER_INFO_502 ServerInfo502;
        struct srvsvc_SERVER_INFO_503 ServerInfo503;
};

int srvsvc_SERVER_INFO_100_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SERVER_INFO_100_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SERVER_INFO_101_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SERVER_INFO_101_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SERVER_INFO_102_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SERVER_INFO_102_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SERVER_INFO_103_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SERVER_INFO_103_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SERVER_INFO_502_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SERVER_INFO_502_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SERVER_INFO_503_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SERVER_INFO_503_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SERVER_INFO_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SERVER_INFO_switch_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

/*
 * NetrConnectionEnum, NetrFileEnum, NetrFileGetInfo, NetrFileClose,
 * NetrSessionEnum and NetrSessionDel: generated from the [MS-SRVS] IDL.
 * Field names follow the IDL.
 */
enum CONNECTION_INFO_enum {
        CONNECTION_INFO_0 = 0,
        CONNECTION_INFO_1 = 1,
};

enum FILE_INFO_enum {
        FILE_INFO_2 = 2,
        FILE_INFO_3 = 3,
};

enum SESSION_INFO_enum {
        SESSION_INFO_0 = 0,
        SESSION_INFO_1 = 1,
        SESSION_INFO_2 = 2,
        SESSION_INFO_10 = 10,
        SESSION_INFO_502 = 502,
};

struct srvsvc_CONNECTION_INFO_0 {
        uint32_t coni0_id;
};

struct srvsvc_CONNECT_INFO_0_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_CONNECTION_INFO_0 * Buffer;
};

struct srvsvc_CONNECTION_INFO_1 {
        uint32_t coni1_id;
        uint32_t coni1_type;
        uint32_t coni1_num_opens;
        uint32_t coni1_num_users;
        uint32_t coni1_time;
        char * coni1_username;
        char * coni1_netname;
};

struct srvsvc_CONNECT_INFO_1_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_CONNECTION_INFO_1 * Buffer;
};

union srvsvc_CONNECT_ENUM_UNION {
        struct srvsvc_CONNECT_INFO_0_CONTAINER Level0;
        struct srvsvc_CONNECT_INFO_1_CONTAINER Level1;
};

struct srvsvc_CONNECT_ENUM_STRUCT {
        uint32_t Level;
        union srvsvc_CONNECT_ENUM_UNION ConnectInfo;
};

struct srvsvc_FILE_INFO_2 {
        uint32_t fi2_id;
};

struct srvsvc_FILE_INFO_2_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_FILE_INFO_2 * Buffer;
};

struct srvsvc_FILE_INFO_3 {
        uint32_t fi3_id;
        uint32_t fi3_permissions;
        uint32_t fi3_num_locks;
        char * fi3_pathname;
        char * fi3_username;
};

struct srvsvc_FILE_INFO_3_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_FILE_INFO_3 * Buffer;
};

union srvsvc_FILE_ENUM_UNION {
        struct srvsvc_FILE_INFO_2_CONTAINER Level2;
        struct srvsvc_FILE_INFO_3_CONTAINER Level3;
};

struct srvsvc_FILE_ENUM_STRUCT {
        uint32_t Level;
        union srvsvc_FILE_ENUM_UNION FileInfo;
};

union srvsvc_FILE_INFO {
        struct srvsvc_FILE_INFO_2 FileInfo2;
        struct srvsvc_FILE_INFO_3 FileInfo3;
};

struct srvsvc_SESSION_INFO_0 {
        char * sesi0_cname;
};

struct srvsvc_SESSION_INFO_0_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SESSION_INFO_0 * Buffer;
};

struct srvsvc_SESSION_INFO_1 {
        char * sesi1_cname;
        char * sesi1_username;
        uint32_t sesi1_num_opens;
        uint32_t sesi1_time;
        uint32_t sesi1_idle_time;
        uint32_t sesi1_user_flags;
};

struct srvsvc_SESSION_INFO_1_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SESSION_INFO_1 * Buffer;
};

struct srvsvc_SESSION_INFO_2 {
        char * sesi2_cname;
        char * sesi2_username;
        uint32_t sesi2_num_opens;
        uint32_t sesi2_time;
        uint32_t sesi2_idle_time;
        uint32_t sesi2_user_flags;
        char * sesi2_cltype_name;
};

struct srvsvc_SESSION_INFO_2_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SESSION_INFO_2 * Buffer;
};

struct srvsvc_SESSION_INFO_10 {
        char * sesi10_cname;
        char * sesi10_username;
        uint32_t sesi10_time;
        uint32_t sesi10_idle_time;
};

struct srvsvc_SESSION_INFO_10_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SESSION_INFO_10 * Buffer;
};

struct srvsvc_SESSION_INFO_502 {
        char * sesi502_cname;
        char * sesi502_username;
        uint32_t sesi502_num_opens;
        uint32_t sesi502_time;
        uint32_t sesi502_idle_time;
        uint32_t sesi502_user_flags;
        char * sesi502_cltype_name;
        char * sesi502_transport;
};

struct srvsvc_SESSION_INFO_502_CONTAINER {
        uint32_t EntriesRead;
        struct srvsvc_SESSION_INFO_502 * Buffer;
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

struct srvsvc_NetrConnectionEnum_req {
        char * ServerName;
        char * Qualifier;
        struct srvsvc_CONNECT_ENUM_STRUCT InfoStruct;
        uint32_t PreferedMaximumLength;
        uint32_t ResumeHandle;
};

struct srvsvc_NetrConnectionEnum_rep {
        struct srvsvc_CONNECT_ENUM_STRUCT InfoStruct;
        uint32_t TotalEntries;
        uint32_t ResumeHandle;
        uint32_t status;
};

struct srvsvc_NetrFileEnum_req {
        char * ServerName;
        char * BasePath;
        char * UserName;
        struct srvsvc_FILE_ENUM_STRUCT InfoStruct;
        uint32_t PreferedMaximumLength;
        uint32_t ResumeHandle;
};

struct srvsvc_NetrFileEnum_rep {
        struct srvsvc_FILE_ENUM_STRUCT InfoStruct;
        uint32_t TotalEntries;
        uint32_t ResumeHandle;
        uint32_t status;
};

struct srvsvc_NetrFileGetInfo_req {
        char * ServerName;
        uint32_t FileId;
        uint32_t Level;
};

struct srvsvc_NetrFileGetInfo_rep {
        union srvsvc_FILE_INFO InfoStruct;
        uint32_t status;
};

struct srvsvc_NetrFileClose_req {
        char * ServerName;
        uint32_t FileId;
};

struct srvsvc_NetrFileClose_rep {
        uint32_t status;
};

struct srvsvc_NetrSessionEnum_req {
        char * ServerName;
        char * ClientName;
        char * UserName;
        struct srvsvc_SESSION_ENUM_STRUCT InfoStruct;
        uint32_t PreferedMaximumLength;
        uint32_t ResumeHandle;
};

struct srvsvc_NetrSessionEnum_rep {
        struct srvsvc_SESSION_ENUM_STRUCT InfoStruct;
        uint32_t TotalEntries;
        uint32_t ResumeHandle;
        uint32_t status;
};

struct srvsvc_NetrSessionDel_req {
        char * ServerName;
        char * ClientName;
        char * UserName;
};

struct srvsvc_NetrSessionDel_rep {
        uint32_t status;
};

int srvsvc_CONNECTION_INFO_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_CONNECTION_INFO_0_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_CONNECT_INFO_0_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_CONNECT_INFO_0_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_CONNECTION_INFO_1_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_CONNECTION_INFO_1_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_CONNECT_INFO_1_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_CONNECT_INFO_1_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_CONNECT_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_CONNECT_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_CONNECT_ENUM_STRUCT_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_FILE_INFO_2_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_FILE_INFO_2_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_FILE_INFO_2_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_FILE_INFO_2_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_FILE_INFO_3_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_FILE_INFO_3_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_FILE_INFO_3_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_FILE_INFO_3_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_FILE_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_FILE_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_FILE_ENUM_STRUCT_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_FILE_INFO_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_FILE_INFO_switch_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_INFO_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_0_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_INFO_0_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_0_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_INFO_1_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_1_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_INFO_1_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_1_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_INFO_2_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_2_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_INFO_2_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_2_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_INFO_10_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_10_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_INFO_10_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_10_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_INFO_502_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_502_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_INFO_502_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_502_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

int srvsvc_SESSION_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_ENUM_STRUCT_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

/* NetrConnectionEnum opnum 0x08 (SRVSVC_NETRCONNECTIONENUM) */
int srvsvc_NetrConnectionEnum_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_NetrConnectionEnum_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

/* NetrFileEnum opnum 0x09 (SRVSVC_NETRFILEENUM) */
int srvsvc_NetrFileEnum_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_NetrFileEnum_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

/* NetrFileGetInfo opnum 0x0a (SRVSVC_NETRFILEGETINFO) */
int srvsvc_NetrFileGetInfo_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_NetrFileGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

/* NetrFileClose opnum 0x0b (SRVSVC_NETRFILECLOSE) */
int srvsvc_NetrFileClose_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_NetrFileClose_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

/* NetrSessionEnum opnum 0x0c (SRVSVC_NETRSESSIONENUM) */
int srvsvc_NetrSessionEnum_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_NetrSessionEnum_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

/* NetrSessionDel opnum 0x0d (SRVSVC_NETRSESSIONDEL) */
int srvsvc_NetrSessionDel_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_NetrSessionDel_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

struct srvsvc_NetrShareAdd_req {
        char * ServerName;
        uint32_t Level;
        union srvsvc_SHARE_INFO InfoStruct;
        uint32_t ParmErr;
};

struct srvsvc_NetrShareAdd_rep {
        uint32_t ParmErr;
        uint32_t status;
};
        
struct srvsvc_NetrShareSetInfo_req {
        char * ServerName;
        char * NetName;
        uint32_t Level;
        union srvsvc_SHARE_INFO ShareInfo;
        uint32_t ParmErr;
};

struct srvsvc_NetrShareSetInfo_rep {
        uint32_t ParmErr;
        uint32_t status;
};

struct srvsvc_NetrShareDel_req {
        char * ServerName;
        char * NetName;
        uint32_t Reserved;
};

struct srvsvc_NetrShareDel_rep {
        uint32_t status;
};

struct srvsvc_NetrShareDelSticky_req {
        char * ServerName;
        char * NetName;
        uint32_t Reserved;
};

struct srvsvc_NetrShareDelSticky_rep {
        uint32_t status;
};

struct srvsvc_NetrShareCheck_req {
        char * ServerName;
        char * Device;
};

struct srvsvc_NetrShareCheck_rep {
        uint32_t Type;
        uint32_t status;
};

struct srvsvc_NetrServerGetInfo_req {
        char * ServerName;
        uint32_t Level;
};

struct srvsvc_NetrServerGetInfo_rep {
        union srvsvc_SERVER_INFO InfoStruct;
        uint32_t status;
};

struct srvsvc_NetrServerSetInfo_req {
        char * ServerName;
        uint32_t Level;
        union srvsvc_SERVER_INFO ServerInfo;
        uint32_t ParmError;
};

struct srvsvc_NetrServerSetInfo_rep {
        uint32_t ParmError;
        uint32_t status;
};

/*
 * STAT_SERVER_0 / NetrServerStatisticsGet
 */
struct srvsvc_STAT_SERVER_0 {
        uint32_t sts0_start;
        uint32_t sts0_fopens;
        uint32_t sts0_devopens;
        uint32_t sts0_jobsqueued;
        uint32_t sts0_sopens;
        uint32_t sts0_stimedout;
        uint32_t sts0_serrorout;
        uint32_t sts0_pwerrors;
        uint32_t sts0_permerrors;
        uint32_t sts0_syserrors;
        uint32_t sts0_bytessent_low;
        uint32_t sts0_bytessent_high;
        uint32_t sts0_bytesrcvd_low;
        uint32_t sts0_bytesrcvd_high;
        uint32_t sts0_avresponse;
        uint32_t sts0_reqbufneed;
        uint32_t sts0_bigbufneed;
};

int srvsvc_STAT_SERVER_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_STAT_SERVER_0_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

struct srvsvc_NetrServerStatisticsGet_req {
        char * ServerName;
        char * Service;
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
        uint32_t tod_elapsedt;
        uint32_t tod_msecs;
        uint32_t tod_hours;
        uint32_t tod_mins;
        uint32_t tod_secs;
        uint32_t tod_hunds;
        int32_t tod_timezone;
        uint32_t tod_tinterval;
        uint32_t tod_day;
        uint32_t tod_month;
        uint32_t tod_year;
        uint32_t tod_weekday;
};

int srvsvc_TIME_OF_DAY_INFO_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_TIME_OF_DAY_INFO_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

struct srvsvc_NetrRemoteTOD_req {
        char * ServerName;
};

struct srvsvc_NetrRemoteTOD_rep {
        struct srvsvc_TIME_OF_DAY_INFO BufferPtr;
        uint32_t status;
};

int srvsvc_NetrShareEnum_rep_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct dcerpc_iovec *iov, int *offset,
                                   void *ptr);
int srvsvc_NetrShareEnum_req_coder(char *name, struct dcerpc_context *ctx,
                                   struct dcerpc_pdu *pdu,
                                   struct dcerpc_iovec *iov, int *offset,
                                   void *ptr);
int srvsvc_NetrShareGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct dcerpc_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrShareGetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                      struct dcerpc_pdu *pdu,
                                      struct dcerpc_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrShareSetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct dcerpc_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrShareSetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                      struct dcerpc_pdu *pdu,
                                      struct dcerpc_iovec *iov, int *offset,
                                      void *ptr);
int srvsvc_NetrServerGetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                       struct dcerpc_pdu *pdu,
                                       struct dcerpc_iovec *iov, int *offset,
                                       void *ptr);
int srvsvc_NetrServerGetInfo_rep_coder(char *name, struct dcerpc_context *ctx,
                                       struct dcerpc_pdu *pdu,
                                       struct dcerpc_iovec *iov, int *offset,
                                       void *ptr);
int srvsvc_NetrServerSetInfo_req_coder(char *name, struct dcerpc_context *ctx,
                                        struct dcerpc_pdu *pdu,
                                        struct dcerpc_iovec *iov, int *offset,
                                        void *ptr);
int srvsvc_NetrServerSetInfo_rep_coder(char *name, struct dcerpc_context *ctx,
                                        struct dcerpc_pdu *pdu,
                                        struct dcerpc_iovec *iov, int *offset,
                                        void *ptr);
int srvsvc_NetrServerStatisticsGet_req_coder(char *name, struct dcerpc_context *ctx,
                                              struct dcerpc_pdu *pdu,
                                              struct dcerpc_iovec *iov, int *offset,
                                              void *ptr);
int srvsvc_NetrServerStatisticsGet_rep_coder(char *name, struct dcerpc_context *ctx,
                                              struct dcerpc_pdu *pdu,
                                              struct dcerpc_iovec *iov, int *offset,
                                              void *ptr);
int srvsvc_NetrRemoteTOD_req_coder(char *name, struct dcerpc_context *ctx,
                                    struct dcerpc_pdu *pdu,
                                    struct dcerpc_iovec *iov, int *offset,
                                    void *ptr);
int srvsvc_NetrRemoteTOD_rep_coder(char *name, struct dcerpc_context *ctx,
                                    struct dcerpc_pdu *pdu,
                                    struct dcerpc_iovec *iov, int *offset,
                                    void *ptr);

/* NetrShareDel opnum 0x12 (SRVSVC_NETRSHAREDEL) */
int srvsvc_NetrShareDel_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_NetrShareDel_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

/* NetrShareDelSticky opnum 0x13 (SRVSVC_NETRSHAREDELSTICKY) */
int srvsvc_NetrShareDelSticky_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_NetrShareDelSticky_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

/* NetrShareCheck opnum 0x14 (SRVSVC_NETRSHARECHECK) */
int srvsvc_NetrShareCheck_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_NetrShareCheck_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

extern struct dcerpc_procedure srvsvc_procs[];
        
#ifdef __cplusplus
}
#endif

#endif /* !_DCERPC_SRVSVC_H_ */
