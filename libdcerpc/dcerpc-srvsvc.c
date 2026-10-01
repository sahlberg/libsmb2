/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2018 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>
#include <dcerpc/dcerpc-srvsvc.h>
#include "libsmb2-raw.h"
#include "libsmb2-private.h"
#include "dcerpc-private.h"

#define SRVSVC_UUID    0x4b324fc8, 0x1670, 0x01d3, {0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88}

p_syntax_id_t srvsvc_interface = {
        {SRVSVC_UUID}, 3, 0
};

static struct dcerpc_uint32_pretty_printer share_type_pp = {
        .fmt = "0x%08x",
        .bitfields = {
                { "DISKTREE",  0x00000003, SRVSVC_SHARE_TYPE_DISKTREE },
                { "PRINTQ",    0x00000003, SRVSVC_SHARE_TYPE_PRINTQ },
                { "DEVICE",    0x00000003, SRVSVC_SHARE_TYPE_DEVICE },
                { "IPC",       0x00000003, SRVSVC_SHARE_TYPE_IPC },
                { "TEMPORARY", SRVSVC_SHARE_TYPE_TEMPORARY,
                  SRVSVC_SHARE_TYPE_TEMPORARY },
                { "SPECIAL",   SRVSVC_SHARE_TYPE_HIDDEN,
                  SRVSVC_SHARE_TYPE_HIDDEN },
                { NULL, 0, 0},
        },
};

/* MS-SRVS 2.2.2.7 Software Type Flags (SERVER_INFO_* .type / SV_TYPE_*) */
static struct dcerpc_uint32_pretty_printer server_type_pp = {
        .fmt = "0x%08x",
        .bitfields = {
                { "WORKSTATION",       SRVSVC_SV_TYPE_WORKSTATION,
                  SRVSVC_SV_TYPE_WORKSTATION },
                { "SERVER",            SRVSVC_SV_TYPE_SERVER,
                  SRVSVC_SV_TYPE_SERVER },
                { "SQLSERVER",         SRVSVC_SV_TYPE_SQLSERVER,
                  SRVSVC_SV_TYPE_SQLSERVER },
                { "DOMAIN_CTRL",       SRVSVC_SV_TYPE_DOMAIN_CTRL,
                  SRVSVC_SV_TYPE_DOMAIN_CTRL },
                { "DOMAIN_BAKCTRL",    SRVSVC_SV_TYPE_DOMAIN_BAKCTRL,
                  SRVSVC_SV_TYPE_DOMAIN_BAKCTRL },
                { "TIME_SOURCE",       SRVSVC_SV_TYPE_TIME_SOURCE,
                  SRVSVC_SV_TYPE_TIME_SOURCE },
                { "AFP",               SRVSVC_SV_TYPE_AFP,
                  SRVSVC_SV_TYPE_AFP },
                { "NOVELL",            SRVSVC_SV_TYPE_NOVELL,
                  SRVSVC_SV_TYPE_NOVELL },
                { "DOMAIN_MEMBER",     SRVSVC_SV_TYPE_DOMAIN_MEMBER,
                  SRVSVC_SV_TYPE_DOMAIN_MEMBER },
                { "PRINTQ_SERVER",     SRVSVC_SV_TYPE_PRINTQ_SERVER,
                  SRVSVC_SV_TYPE_PRINTQ_SERVER },
                { "DIALIN_SERVER",     SRVSVC_SV_TYPE_DIALIN_SERVER,
                  SRVSVC_SV_TYPE_DIALIN_SERVER },
                { "XENIX_SERVER",      SRVSVC_SV_TYPE_XENIX_SERVER,
                  SRVSVC_SV_TYPE_XENIX_SERVER },
                { "NT",                SRVSVC_SV_TYPE_NT,
                  SRVSVC_SV_TYPE_NT },
                { "WFW",               SRVSVC_SV_TYPE_WFW,
                  SRVSVC_SV_TYPE_WFW },
                { "SERVER_MFPN",       SRVSVC_SV_TYPE_SERVER_MFPN,
                  SRVSVC_SV_TYPE_SERVER_MFPN },
                { "SERVER_NT",         SRVSVC_SV_TYPE_SERVER_NT,
                  SRVSVC_SV_TYPE_SERVER_NT },
                { "POTENTIAL_BROWSER", SRVSVC_SV_TYPE_POTENTIAL_BROWSER,
                  SRVSVC_SV_TYPE_POTENTIAL_BROWSER },
                { "BACKUP_BROWSER",    SRVSVC_SV_TYPE_BACKUP_BROWSER,
                  SRVSVC_SV_TYPE_BACKUP_BROWSER },
                { "MASTER_BROWSER",    SRVSVC_SV_TYPE_MASTER_BROWSER,
                  SRVSVC_SV_TYPE_MASTER_BROWSER },
                { "DOMAIN_MASTER",     SRVSVC_SV_TYPE_DOMAIN_MASTER,
                  SRVSVC_SV_TYPE_DOMAIN_MASTER },
                { "WINDOWS",           SRVSVC_SV_TYPE_WINDOWS,
                  SRVSVC_SV_TYPE_WINDOWS },
                { "DFS",               SRVSVC_SV_TYPE_DFS,
                  SRVSVC_SV_TYPE_DFS },
                { "CLUSTER_NT",        SRVSVC_SV_TYPE_CLUSTER_NT,
                  SRVSVC_SV_TYPE_CLUSTER_NT },
                { "TERMINALSERVER",    SRVSVC_SV_TYPE_TERMINALSERVER,
                  SRVSVC_SV_TYPE_TERMINALSERVER },
                { "CLUSTER_VS_NT",     SRVSVC_SV_TYPE_CLUSTER_VS_NT,
                  SRVSVC_SV_TYPE_CLUSTER_VS_NT },
                { "DCE",               SRVSVC_SV_TYPE_DCE,
                  SRVSVC_SV_TYPE_DCE },
                { "ALTERNATE_XPORT",   SRVSVC_SV_TYPE_ALTERNATE_XPORT,
                  SRVSVC_SV_TYPE_ALTERNATE_XPORT },
                { "LOCAL_LIST_ONLY",   SRVSVC_SV_TYPE_LOCAL_LIST_ONLY,
                  SRVSVC_SV_TYPE_LOCAL_LIST_ONLY },
                { "DOMAIN_ENUM",       SRVSVC_SV_TYPE_DOMAIN_ENUM,
                  SRVSVC_SV_TYPE_DOMAIN_ENUM },
                { NULL, 0, 0},
        },
};

/* PLATFORM_ID_* (SERVER_INFO_*.platform_id) — enum, exact match */
static struct dcerpc_uint32_pretty_printer platform_id_pp = {
        .fmt = "%u",
        .bitfields = {
                { "PLATFORM_ID_DOS", 0xffffffff, SRVSVC_PLATFORM_ID_DOS },
                { "PLATFORM_ID_OS2", 0xffffffff, SRVSVC_PLATFORM_ID_OS2 },
                { "PLATFORM_ID_NT",  0xffffffff, SRVSVC_PLATFORM_ID_NT },
                { "PLATFORM_ID_OSF", 0xffffffff, SRVSVC_PLATFORM_ID_OSF },
                { "PLATFORM_ID_VMS", 0xffffffff, SRVSVC_PLATFORM_ID_VMS },
                { NULL, 0, 0},
        },
};

/* Open file permissions (FILE_INFO_3.permissions / PERM_FILE_*) */
static struct dcerpc_uint32_pretty_printer file_perm_pp = {
        .fmt = "0x%08x",
        .bitfields = {
                { "PERM_FILE_READ",   SRVSVC_PERM_FILE_READ,
                  SRVSVC_PERM_FILE_READ },
                { "PERM_FILE_WRITE",  SRVSVC_PERM_FILE_WRITE,
                  SRVSVC_PERM_FILE_WRITE },
                { "PERM_FILE_CREATE", SRVSVC_PERM_FILE_CREATE,
                  SRVSVC_PERM_FILE_CREATE },
                { NULL, 0, 0},
        },
};

/* MS-SRVS Session User Flags (SESSION_INFO_*.user_flags) */
static struct dcerpc_uint32_pretty_printer sess_user_flags_pp = {
        .fmt = "0x%08x",
        .bitfields = {
                { "SESS_GUEST",        SRVSVC_SESS_GUEST,
                  SRVSVC_SESS_GUEST },
                { "SESS_NOENCRYPTION", SRVSVC_SESS_NOENCRYPTION,
                  SRVSVC_SESS_NOENCRYPTION },
                { NULL, 0, 0},
        },
};

/*
 * SRVSVC BEGIN:  DEFINITIONS FROM SRVSVC.IDL
 * [MS-SRVS].pdf
 */

/*
 * NetrShareEnum and NetrShareGetInfo types: SHARE_INFO levels 0, 1, 2,
 * 501, 502, 503, 1004, 1005, 1006 and 1501, their containers,
 * SHARE_ENUM_UNION, SHARE_ENUM_STRUCT and the SHARE_INFO union. Generated
 * from the [MS-SRVS] IDL; field names follow the IDL.
 */
int srvsvc_SHARE_INFO_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_1_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_2_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_501_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_502_I_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SHARE_INFO_503_I_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);

static int
srvsvc_SHARE_INFO_0_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SHARE_INFO_0),
                                   srvsvc_SHARE_INFO_0_coder);
}

static int
srvsvc_SHARE_INFO_1_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SHARE_INFO_1),
                                   srvsvc_SHARE_INFO_1_coder);
}

static int
srvsvc_SHARE_INFO_2_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SHARE_INFO_2),
                                   srvsvc_SHARE_INFO_2_coder);
}

static int
srvsvc_SHARE_INFO_501_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SHARE_INFO_501),
                                   srvsvc_SHARE_INFO_501_coder);
}

static int
srvsvc_SHARE_INFO_502_I_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SHARE_INFO_502_I),
                                   srvsvc_SHARE_INFO_502_I_coder);
}

static int
srvsvc_SHARE_INFO_503_I_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SHARE_INFO_503_I),
                                   srvsvc_SHARE_INFO_503_I_coder);
}

int
srvsvc_SHARE_INFO_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_0 *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("shi0_netname", dce, pdu, iov, offset, &s->shi0_netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_0_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_0_coder);
}

int
srvsvc_SHARE_INFO_0_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_0_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SHARE_INFO_0);
                        if (s->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        s->Buffer = dcerpc_alloc_data(pdu,
                                (size_t)s->EntriesRead * esize);
                        if (s->Buffer == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("Buffer", dce, pdu, iov, offset, s->Buffer,
                             PTR_UNIQUE, srvsvc_SHARE_INFO_0_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_0_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_0_CONTAINER_coder);
}

int
srvsvc_SHARE_INFO_1_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_1 *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("shi1_netname", dce, pdu, iov, offset, &s->shi1_netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi1_type", dce, pdu, iov, offset, &s->shi1_type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi1_remark", dce, pdu, iov, offset, &s->shi1_remark,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_1_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_1_coder);
}

int
srvsvc_SHARE_INFO_1_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_1_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SHARE_INFO_1);
                        if (s->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        s->Buffer = dcerpc_alloc_data(pdu,
                                (size_t)s->EntriesRead * esize);
                        if (s->Buffer == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("Buffer", dce, pdu, iov, offset, s->Buffer,
                             PTR_UNIQUE, srvsvc_SHARE_INFO_1_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_1_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_1_CONTAINER_coder);
}

int
srvsvc_SHARE_INFO_2_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_2 *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("shi2_netname", dce, pdu, iov, offset, &s->shi2_netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi2_type", dce, pdu, iov, offset, &s->shi2_type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi2_remark", dce, pdu, iov, offset, &s->shi2_remark,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi2_permissions", dce, pdu, iov, offset, &s->shi2_permissions)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi2_max_uses", dce, pdu, iov, offset, &s->shi2_max_uses)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi2_current_uses", dce, pdu, iov, offset, &s->shi2_current_uses)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi2_path", dce, pdu, iov, offset, &s->shi2_path,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi2_passwd", dce, pdu, iov, offset, &s->shi2_passwd,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_2_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_2_coder);
}

int
srvsvc_SHARE_INFO_2_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_2_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SHARE_INFO_2);
                        if (s->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        s->Buffer = dcerpc_alloc_data(pdu,
                                (size_t)s->EntriesRead * esize);
                        if (s->Buffer == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("Buffer", dce, pdu, iov, offset, s->Buffer,
                             PTR_UNIQUE, srvsvc_SHARE_INFO_2_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_2_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_2_CONTAINER_coder);
}

int
srvsvc_SHARE_INFO_501_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_501 *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("shi501_netname", dce, pdu, iov, offset, &s->shi501_netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi501_type", dce, pdu, iov, offset, &s->shi501_type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi501_remark", dce, pdu, iov, offset, &s->shi501_remark,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi501_flags", dce, pdu, iov, offset, &s->shi501_flags)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_501_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_501_coder);
}

int
srvsvc_SHARE_INFO_501_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_501_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SHARE_INFO_501);
                        if (s->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        s->Buffer = dcerpc_alloc_data(pdu,
                                (size_t)s->EntriesRead * esize);
                        if (s->Buffer == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("Buffer", dce, pdu, iov, offset, s->Buffer,
                             PTR_UNIQUE, srvsvc_SHARE_INFO_501_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_501_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_501_CONTAINER_coder);
}

int
srvsvc_SHARE_INFO_502_I_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_502_I *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("shi502_netname", dce, pdu, iov, offset, &s->shi502_netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi502_type", dce, pdu, iov, offset, &s->shi502_type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi502_remark", dce, pdu, iov, offset, &s->shi502_remark,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi502_permissions", dce, pdu, iov, offset, &s->shi502_permissions)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi502_max_uses", dce, pdu, iov, offset, &s->shi502_max_uses)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi502_current_uses", dce, pdu, iov, offset, &s->shi502_current_uses)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi502_path", dce, pdu, iov, offset, &s->shi502_path,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi502_passwd", dce, pdu, iov, offset, &s->shi502_passwd,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_blob_len_coder("shi502_reserved", dce, pdu, iov, offset,
                                  &s->shi502_reserved, s->shi502_security_descriptor,
                                  dcerpc_SECURITY_DESCRIPTOR_coder)) {
                return -1;
        }
        if (dcerpc_blob_coder("shi502_security_descriptor", dce, pdu, iov, offset,
                              s->shi502_reserved, &s->shi502_security_descriptor,
                              sizeof(SECURITY_DESCRIPTOR),
                              dcerpc_SECURITY_DESCRIPTOR_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_502_I_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_502_I_coder);
}

int
srvsvc_SHARE_INFO_502_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_502_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SHARE_INFO_502_I);
                        if (s->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        s->Buffer = dcerpc_alloc_data(pdu,
                                (size_t)s->EntriesRead * esize);
                        if (s->Buffer == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("Buffer", dce, pdu, iov, offset, s->Buffer,
                             PTR_UNIQUE, srvsvc_SHARE_INFO_502_I_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_502_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_502_CONTAINER_coder);
}

int
srvsvc_SHARE_INFO_503_I_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_503_I *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("shi503_netname", dce, pdu, iov, offset, &s->shi503_netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi503_type", dce, pdu, iov, offset, &s->shi503_type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi503_remark", dce, pdu, iov, offset, &s->shi503_remark,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi503_permissions", dce, pdu, iov, offset, &s->shi503_permissions)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi503_max_uses", dce, pdu, iov, offset, &s->shi503_max_uses)) {
                return -1;
        }
        if (dcerpc_uint32_coder("shi503_current_uses", dce, pdu, iov, offset, &s->shi503_current_uses)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi503_path", dce, pdu, iov, offset, &s->shi503_path,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi503_passwd", dce, pdu, iov, offset, &s->shi503_passwd,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("shi503_servername", dce, pdu, iov, offset, &s->shi503_servername,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_blob_len_coder("shi503_reserved", dce, pdu, iov, offset,
                                  &s->shi503_reserved, s->shi503_security_descriptor,
                                  dcerpc_SECURITY_DESCRIPTOR_coder)) {
                return -1;
        }
        if (dcerpc_blob_coder("shi503_security_descriptor", dce, pdu, iov, offset,
                              s->shi503_reserved, &s->shi503_security_descriptor,
                              sizeof(SECURITY_DESCRIPTOR),
                              dcerpc_SECURITY_DESCRIPTOR_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_503_I_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_503_I_coder);
}

int
srvsvc_SHARE_INFO_503_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_503_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SHARE_INFO_503_I);
                        if (s->EntriesRead > SIZE_MAX / esize) {
                                return -1;
                        }
                        s->Buffer = dcerpc_alloc_data(pdu,
                                (size_t)s->EntriesRead * esize);
                        if (s->Buffer == NULL) {
                                return -1;
                        }
                }
        }
        if (dcerpc_ptr_coder("Buffer", dce, pdu, iov, offset, s->Buffer,
                             PTR_UNIQUE, srvsvc_SHARE_INFO_503_I_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_503_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_503_CONTAINER_coder);
}

int
srvsvc_SHARE_INFO_1004_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_1004 *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("shi1004_remark", dce, pdu, iov, offset, &s->shi1004_remark,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_1004_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_1004_coder);
}

int
srvsvc_SHARE_INFO_1005_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_1005 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("shi1005_flags", dce, pdu, iov, offset, &s->shi1005_flags)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_1005_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_1005_coder);
}

int
srvsvc_SHARE_INFO_1006_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_1006 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("shi1006_max_uses", dce, pdu, iov, offset, &s->shi1006_max_uses)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_1006_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_1006_coder);
}

int
srvsvc_SHARE_INFO_1501_I_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_INFO_1501_I *s = ptr;

        (void)name;
        if (dcerpc_blob_len_coder("shi1501_reserved", dce, pdu, iov, offset,
                                  &s->shi1501_reserved, s->shi1501_security_descriptor,
                                  dcerpc_SECURITY_DESCRIPTOR_coder)) {
                return -1;
        }
        if (dcerpc_blob_coder("shi1501_security_descriptor", dce, pdu, iov, offset,
                              s->shi1501_reserved, &s->shi1501_security_descriptor,
                              sizeof(SECURITY_DESCRIPTOR),
                              dcerpc_SECURITY_DESCRIPTOR_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_INFO_1501_I_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_INFO_1501_I_coder);
}

int
srvsvc_SHARE_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        union srvsvc_SHARE_ENUM_UNION *u = ptr;

        (void)name;
        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                if (dcerpc_ptr_coder("Level0", dce, pdu, iov, offset, &u->Level0,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_0_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 1:
                if (dcerpc_ptr_coder("Level1", dce, pdu, iov, offset, &u->Level1,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_1_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 2:
                if (dcerpc_ptr_coder("Level2", dce, pdu, iov, offset, &u->Level2,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_2_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 501:
                if (dcerpc_ptr_coder("Level501", dce, pdu, iov, offset, &u->Level501,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_501_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 502:
                if (dcerpc_ptr_coder("Level502", dce, pdu, iov, offset, &u->Level502,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_502_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 503:
                if (dcerpc_ptr_coder("Level503", dce, pdu, iov, offset, &u->Level503,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_503_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        default:
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SHARE_ENUM_STRUCT *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &s->Level)) {
                return -1;
        }
        if (dcerpc_union_coder("ShareInfo", dce, pdu, iov, offset,
                               &s->Level, &s->ShareInfo,
                               srvsvc_SHARE_ENUM_UNION_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SHARE_ENUM_STRUCT_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SHARE_ENUM_STRUCT_coder);
}

int
srvsvc_SHARE_INFO_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        union srvsvc_SHARE_INFO *u = ptr;

        (void)name;
        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                if (dcerpc_ptr_coder("ShareInfo0", dce, pdu, iov, offset, &u->ShareInfo0,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_0_struct_coder)) {
                        return -1;
                }
                break;
        case 1:
                if (dcerpc_ptr_coder("ShareInfo1", dce, pdu, iov, offset, &u->ShareInfo1,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_1_struct_coder)) {
                        return -1;
                }
                break;
        case 2:
                if (dcerpc_ptr_coder("ShareInfo2", dce, pdu, iov, offset, &u->ShareInfo2,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_2_struct_coder)) {
                        return -1;
                }
                break;
        case 502:
                if (dcerpc_ptr_coder("ShareInfo502", dce, pdu, iov, offset, &u->ShareInfo502,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_502_I_struct_coder)) {
                        return -1;
                }
                break;
        case 1004:
                if (dcerpc_ptr_coder("ShareInfo1004", dce, pdu, iov, offset, &u->ShareInfo1004,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_1004_struct_coder)) {
                        return -1;
                }
                break;
        case 1006:
                if (dcerpc_ptr_coder("ShareInfo1006", dce, pdu, iov, offset, &u->ShareInfo1006,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_1006_struct_coder)) {
                        return -1;
                }
                break;
        case 1501:
                if (dcerpc_ptr_coder("ShareInfo1501", dce, pdu, iov, offset, &u->ShareInfo1501,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_1501_I_struct_coder)) {
                        return -1;
                }
                break;
        case 1005:
                if (dcerpc_ptr_coder("ShareInfo1005", dce, pdu, iov, offset, &u->ShareInfo1005,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_1005_struct_coder)) {
                        return -1;
                }
                break;
        case 501:
                if (dcerpc_ptr_coder("ShareInfo501", dce, pdu, iov, offset, &u->ShareInfo501,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_501_struct_coder)) {
                        return -1;
                }
                break;
        case 503:
                if (dcerpc_ptr_coder("ShareInfo503", dce, pdu, iov, offset, &u->ShareInfo503,
                                     PTR_UNIQUE, srvsvc_SHARE_INFO_503_I_struct_coder)) {
                        return -1;
                }
                break;
        default:
                return -1;
        }

        return 0;
}

/* The union as a [switch_is] parameter: discriminant from switch_is */
int
srvsvc_SHARE_INFO_switch_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        uint32_t level = dcerpc_get_switch_is(pdu);

        return dcerpc_union_coder(name, dce, pdu, iov, offset, &level, ptr,
                                  srvsvc_SHARE_INFO_coder);
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
                             struct dcerpc_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SERVER_INFO_100 *si100 = ptr;

        if (dcerpc_uint32_coder_pp("Platform_Id", dce, pdu, iov, offset,
                                   &si100->platform_id, &platform_id_pp)) {
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                             struct dcerpc_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SERVER_INFO_101 *si101 = ptr;

        if (dcerpc_uint32_coder_pp("Platform_Id", dce, pdu, iov, offset,
                                   &si101->platform_id, &platform_id_pp)) {
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
        if (dcerpc_uint32_coder_pp("Type", dce, pdu, iov, offset, &si101->type,
                                   &server_type_pp)) {
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                             struct dcerpc_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SERVER_INFO_102 *si102 = ptr;

        if (dcerpc_uint32_coder_pp("Platform_Id", dce, pdu, iov, offset,
                                   &si102->platform_id, &platform_id_pp)) {
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
        if (dcerpc_uint32_coder_pp("Type", dce, pdu, iov, offset, &si102->type,
                                   &server_type_pp)) {
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                             struct dcerpc_iovec *iov, int *offset,
                             void *ptr)
{
        struct srvsvc_SERVER_INFO_103 *si103 = ptr;

        if (dcerpc_uint32_coder_pp("Platform_Id", dce, pdu, iov, offset,
                                   &si103->platform_id, &platform_id_pp)) {
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
        if (dcerpc_uint32_coder_pp("Type", dce, pdu, iov, offset, &si103->type,
                                   &server_type_pp)) {
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                             struct dcerpc_iovec *iov, int *offset,
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                             struct dcerpc_iovec *iov, int *offset,
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                         struct dcerpc_iovec *iov, int *offset,
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
                                struct dcerpc_iovec *iov, int *offset,
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
                               struct dcerpc_iovec *iov, int *offset,
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
                                      struct dcerpc_iovec *iov, int *offset,
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
                                      struct dcerpc_iovec *iov, int *offset,
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
                                      struct dcerpc_iovec *iov, int *offset,
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
                        ctr->connection_info_0 = dcerpc_alloc_data(pdu,
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
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_CONNECTION_INFO_1 *ci = ptr;

        if (dcerpc_uint32_coder("Id", dce, pdu, iov, offset, &ci->id)) {
                return -1;
        }
        if (dcerpc_uint32_coder_pp("Type", dce, pdu, iov, offset, &ci->type,
                                   &share_type_pp)) {
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
                                      struct dcerpc_iovec *iov, int *offset,
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
                                      struct dcerpc_iovec *iov, int *offset,
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
                                      struct dcerpc_iovec *iov, int *offset,
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
                        ctr->connection_info_1 = dcerpc_alloc_data(pdu,
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
                                struct dcerpc_iovec *iov, int *offset,
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
                                 struct dcerpc_iovec *iov, int *offset,
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
                                        struct dcerpc_iovec *iov, int *offset,
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                         struct dcerpc_iovec *iov, int *offset,
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
                                struct dcerpc_iovec *iov, int *offset,
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
                                struct dcerpc_iovec *iov, int *offset,
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
                                   struct dcerpc_iovec *iov, int *offset,
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
                        ctr->file_info_2 = dcerpc_alloc_data(pdu,
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
                         struct dcerpc_iovec *iov, int *offset,
                         void *ptr)
{
        struct srvsvc_FILE_INFO_3 *fi = ptr;

        if (dcerpc_uint32_coder("Id", dce, pdu, iov, offset, &fi->id)) {
                return -1;
        }
        if (dcerpc_uint32_coder_pp("Permissions", dce, pdu, iov, offset,
                                   &fi->permissions, &file_perm_pp)) {
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
                                struct dcerpc_iovec *iov, int *offset,
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
                                struct dcerpc_iovec *iov, int *offset,
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
                                   struct dcerpc_iovec *iov, int *offset,
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
                        ctr->file_info_3 = dcerpc_alloc_data(pdu,
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
                             struct dcerpc_iovec *iov, int *offset,
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
                              struct dcerpc_iovec *iov, int *offset,
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
                                     struct dcerpc_iovec *iov, int *offset,
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
                              struct dcerpc_iovec *iov, int *offset,
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
                              struct dcerpc_iovec *iov, int *offset,
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
                       struct dcerpc_iovec *iov, int *offset,
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
                              struct dcerpc_iovec *iov, int *offset,
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
                                 struct dcerpc_iovec *iov, int *offset,
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
                                 struct dcerpc_iovec *iov, int *offset,
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
                               struct dcerpc_iovec *iov, int *offset,
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
                               struct dcerpc_iovec *iov, int *offset,
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
                            struct dcerpc_iovec *iov, int *offset,
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
                                   struct dcerpc_iovec *iov, int *offset,
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
                                   struct dcerpc_iovec *iov, int *offset,
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
                                      struct dcerpc_iovec *iov, int *offset,
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
                        ctr->session_info_0 = dcerpc_alloc_data(pdu,
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
                            struct dcerpc_iovec *iov, int *offset,
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
        if (dcerpc_uint32_coder_pp("UserFlags", dce, pdu, iov, offset,
                                   &si->user_flags, &sess_user_flags_pp)) {
                return -1;
        }
        return 0;
}

int
srvsvc_SESSION_INFO_1_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct dcerpc_iovec *iov, int *offset,
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
                                   struct dcerpc_iovec *iov, int *offset,
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
                                      struct dcerpc_iovec *iov, int *offset,
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
                        ctr->session_info_1 = dcerpc_alloc_data(pdu,
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
                            struct dcerpc_iovec *iov, int *offset,
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
        if (dcerpc_uint32_coder_pp("UserFlags", dce, pdu, iov, offset,
                                   &si->user_flags, &sess_user_flags_pp)) {
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
                                   struct dcerpc_iovec *iov, int *offset,
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
                                   struct dcerpc_iovec *iov, int *offset,
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
                                      struct dcerpc_iovec *iov, int *offset,
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
                        ctr->session_info_2 = dcerpc_alloc_data(pdu,
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
                             struct dcerpc_iovec *iov, int *offset,
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                                       struct dcerpc_iovec *iov, int *offset,
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
                        ctr->session_info_10 = dcerpc_alloc_data(pdu,
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
                              struct dcerpc_iovec *iov, int *offset,
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
        if (dcerpc_uint32_coder_pp("UserFlags", dce, pdu, iov, offset,
                                   &si->user_flags, &sess_user_flags_pp)) {
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
                                     struct dcerpc_iovec *iov, int *offset,
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
                                     struct dcerpc_iovec *iov, int *offset,
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
                                        struct dcerpc_iovec *iov, int *offset,
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
                        ctr->session_info_502 = dcerpc_alloc_data(pdu,
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
                                struct dcerpc_iovec *iov, int *offset,
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
                                 struct dcerpc_iovec *iov, int *offset,
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
                                        struct dcerpc_iovec *iov, int *offset,
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
                                 struct dcerpc_iovec *iov, int *offset,
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
                                 struct dcerpc_iovec *iov, int *offset,
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
                                struct dcerpc_iovec *iov, int *offset,
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
                                struct dcerpc_iovec *iov, int *offset,
                                void *ptr)
{
        struct srvsvc_NetrSessionDel_rep *rep = ptr;

        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x0e  NetrShareAdd  (SRVSVC_NETRSHAREADD)
 *****************/
int
srvsvc_NetrShareAdd_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareAdd_req *req = ptr;

        (void)name;
        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Level", dce, pdu, iov, offset, &req->Level,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->InfoStruct,
                             PTR_REF, srvsvc_SHARE_INFO_switch_coder)) {
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
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareAdd_rep *rep = ptr;

        (void)name;
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
 * Function: 0x0f  NetrShareEnum  (SRVSVC_NETRSHAREENUM)
 *****************/
int
srvsvc_NetrShareEnum_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareEnum_req *req = ptr;

        (void)name;
        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->InfoStruct,
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
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareEnum_rep *rep = ptr;

        (void)name;
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_REF, srvsvc_SHARE_ENUM_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TotalEntries", dce, pdu, iov, offset, &rep->TotalEntries,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset, &rep->ResumeHandle,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x10  NetrShareGetInfo  (SRVSVC_NETRSHAREGETINFO)
 *****************/
int
srvsvc_NetrShareGetInfo_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareGetInfo_req *req = ptr;

        (void)name;
        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset, &req->NetName,
                             PTR_REF, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Level", dce, pdu, iov, offset, &req->Level,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrShareGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareGetInfo_rep *rep = ptr;
        /* the discriminant is only in the request */
        struct srvsvc_NetrShareGetInfo_req *req = dcerpc_get_request(pdu);

        (void)name;
        if (req == NULL) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_REF, srvsvc_SHARE_INFO_switch_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x11  NetrShareSetInfo  (SRVSVC_NETRSHARESETINFO)
 *****************/
int
srvsvc_NetrShareSetInfo_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareSetInfo_req *req = ptr;

        (void)name;
        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset, &req->NetName,
                             PTR_REF, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Level", dce, pdu, iov, offset, &req->Level,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);
        if (dcerpc_ptr_coder("ShareInfo", dce, pdu, iov, offset, &req->ShareInfo,
                             PTR_REF, srvsvc_SHARE_INFO_switch_coder)) {
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
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareSetInfo_rep *rep = ptr;

        (void)name;
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
 * Function: 0x12  NetrShareDel  (SRVSVC_NETRSHAREDEL)
 *****************/
int
srvsvc_NetrShareDel_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareDel_req *req = ptr;

        (void)name;
        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset, &req->NetName,
                             PTR_REF, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Reserved", dce, pdu, iov, offset, &req->Reserved,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrShareDel_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareDel_rep *rep = ptr;

        (void)name;
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x13  NetrShareDelSticky  (SRVSVC_NETRSHAREDELSTICKY)
 *****************/
int
srvsvc_NetrShareDelSticky_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareDelSticky_req *req = ptr;

        (void)name;
        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("NetName", dce, pdu, iov, offset, &req->NetName,
                             PTR_REF, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Reserved", dce, pdu, iov, offset, &req->Reserved,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrShareDelSticky_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareDelSticky_rep *rep = ptr;

        (void)name;
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x14  NetrShareCheck  (SRVSVC_NETRSHARECHECK)
 *****************/
int
srvsvc_NetrShareCheck_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareCheck_req *req = ptr;

        (void)name;
        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Device", dce, pdu, iov, offset, &req->Device,
                             PTR_REF, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrShareCheck_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrShareCheck_rep *rep = ptr;

        (void)name;
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
                                       struct dcerpc_iovec *iov, int *offset,
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
                                       struct dcerpc_iovec *iov, int *offset,
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
                                   struct dcerpc_iovec *iov, int *offset,
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
                                   struct dcerpc_iovec *iov, int *offset,
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
                                 struct dcerpc_iovec *iov, int *offset,
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
        out = dcerpc_alloc_data(pdu,
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
                       struct dcerpc_iovec *iov, int *offset,
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
                              struct dcerpc_iovec *iov, int *offset,
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
                              struct dcerpc_iovec *iov, int *offset,
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
                                 struct dcerpc_iovec *iov, int *offset,
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
                        ctr->disk_info = dcerpc_alloc_data(pdu,
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
                                        struct dcerpc_iovec *iov, int *offset,
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                                    struct dcerpc_iovec *iov, int *offset,
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
                           struct dcerpc_iovec *iov, int *offset,
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
                                  struct dcerpc_iovec *iov, int *offset,
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
                                         struct dcerpc_iovec *iov, int *offset,
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
                                         struct dcerpc_iovec *iov, int *offset,
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

/*
 * typedef struct _TIME_OF_DAY_INFO {
 *   DWORD tod_elapsedt;
 *   DWORD tod_msecs;
 *   DWORD tod_hours;
 *   DWORD tod_mins;
 *   DWORD tod_secs;
 *   DWORD tod_hunds;
 *   long  tod_timezone;
 *   DWORD tod_tinterval;
 *   DWORD tod_day;
 *   DWORD tod_month;
 *   DWORD tod_year;
 *   DWORD tod_weekday;
 * } TIME_OF_DAY_INFO, *PTIME_OF_DAY_INFO, *LPTIME_OF_DAY_INFO;
 */
int
srvsvc_TIME_OF_DAY_INFO_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov, int *offset,
                              void *ptr)
{
        struct srvsvc_TIME_OF_DAY_INFO *tod = ptr;
        /* Not named "timezone": that shadows the POSIX global of
         * the same name declared by <time.h> on some platforms. */
        uint32_t tz = 0;

        if (dcerpc_uint32_coder("Elapsedt", dce, pdu, iov, offset, &tod->elapsedt)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Msecs", dce, pdu, iov, offset, &tod->msecs)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Hours", dce, pdu, iov, offset, &tod->hours)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Mins", dce, pdu, iov, offset, &tod->mins)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Secs", dce, pdu, iov, offset, &tod->secs)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Hunds", dce, pdu, iov, offset, &tod->hunds)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                tz = (uint32_t)tod->timezone;
        }
        if (dcerpc_uint32_coder("Timezone", dce, pdu, iov, offset, &tz)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && !dcerpc_get_cr(pdu)) {
                tod->timezone = (int32_t)tz;
        }
        if (dcerpc_uint32_coder("Tinterval", dce, pdu, iov, offset, &tod->tinterval)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Day", dce, pdu, iov, offset, &tod->day)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Month", dce, pdu, iov, offset, &tod->month)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Year", dce, pdu, iov, offset, &tod->year)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Weekday", dce, pdu, iov, offset, &tod->weekday)) {
                return -1;
        }
        return 0;
}

int
srvsvc_TIME_OF_DAY_INFO_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct dcerpc_iovec *iov, int *offset,
                                     void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_TIME_OF_DAY_INFO_coder);
}

/*****************
 * Function: 0x1c
 * NET_API_STATUS NetrRemoteTOD (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [out] LPTIME_OF_DAY_INFO * BufferPtr
 * );
 */
int
srvsvc_NetrRemoteTOD_req_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_NetrRemoteTOD_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrRemoteTOD_rep_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr)
{
        struct srvsvc_NetrRemoteTOD_rep *rep = ptr;

        if (dcerpc_ptr_coder("BufferPtr", dce, pdu, iov, offset, &rep->BufferPtr,
                             PTR_UNIQUE, srvsvc_TIME_OF_DAY_INFO_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}


/*
 * typedef struct _SERVER_TRANSPORT_INFO_3 {
 *       DWORD svti3_numberofvcs;
 *       [string] wchar_t *svti3_transportname;
 *       [size_is(svti3_transportaddresslength)] unsigned char *svti3_transportaddress;
 *       DWORD svti3_transportaddresslength;
 *       [string] wchar_t *svti3_networkaddress;
 *       [string] wchar_t *svti3_domain;
 *       DWORD svti3_flags;
 *       DWORD svti3_passwordlength;
 *       unsigned char svti3_password[256];
 * } SERVER_TRANSPORT_INFO_3;
 *
 * Levels 0, 1 and 2 are prefixes of level 3: 0 ends after networkaddress,
 * 1 adds domain, 2 adds flags.
 */
static int
srvsvc_SERVER_TRANSPORT_INFO_level_coder(int level, char *name,
                                         struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         struct dcerpc_iovec *iov,
                                         int *offset, void *ptr)
{
        struct srvsvc_SERVER_TRANSPORT_INFO *ti = ptr;
        int ndr = dcerpc_pdu_encoding(pdu) == ENCODING_NDR;
        int encode = dcerpc_pdu_direction(pdu) == DCERPC_ENCODE;
        uint32_t addrlen;
        uint32_t i;

        if (dcerpc_uint32_coder("NumberOfVcs", dce, pdu, iov, offset,
                                &ti->NumberOfVcs)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TransportName", dce, pdu, iov, offset,
                             &ti->TransportName, PTR_UNIQUE,
                             dcerpc_utf16z_coder)) {
                return -1;
        }
        if (ndr) {
                /* unique pointer to [size_is(...length)] bytes, then length */
                if (dcerpc_ptr_coder("TransportAddress", dce, pdu, iov, offset,
                                     encode && ti->TransportAddress.len == 0 ?
                                     NULL : &ti->TransportAddress,
                                     PTR_UNIQUE, dcerpc_bytes_coder)) {
                        return -1;
                }
                addrlen = ti->TransportAddress.len;
                if (dcerpc_uint32_coder("TransportAddressLength", dce, pdu,
                                        iov, offset, &addrlen)) {
                        return -1;
                }
        } else {
                if (dcerpc_bytes_coder("TransportAddress", dce, pdu, iov,
                                       offset, &ti->TransportAddress)) {
                        return -1;
                }
        }
        if (dcerpc_ptr_coder("NetworkAddress", dce, pdu, iov, offset,
                             &ti->NetworkAddress, PTR_UNIQUE,
                             dcerpc_utf16z_coder)) {
                return -1;
        }
        if (level >= 1 &&
            dcerpc_ptr_coder("Domain", dce, pdu, iov, offset, &ti->Domain,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (level >= 2 &&
            dcerpc_uint32_coder("Flags", dce, pdu, iov, offset, &ti->Flags)) {
                return -1;
        }
        if (level < 3) {
                return 0;
        }
        if (ndr) {
                if (dcerpc_uint32_coder("PasswordLength", dce, pdu, iov,
                                        offset, &ti->PasswordLength)) {
                        return -1;
                }
                for (i = 0; i < sizeof(ti->Password); i++) {
                        if (dcerpc_uint8_coder("Password", dce, pdu, iov,
                                               offset, &ti->Password[i])) {
                                return -1;
                        }
                }
        } else {
                /* YAML/JSON: the PasswordLength valid bytes, as hex */
                struct dcerpc_bytes pw;

                pw.len = ti->PasswordLength > sizeof(ti->Password) ?
                        sizeof(ti->Password) : ti->PasswordLength;
                pw.data = ti->Password;
                if (dcerpc_bytes_coder("Password", dce, pdu, iov, offset,
                                       &pw)) {
                        return -1;
                }
                if (!encode) {
                        if (pw.len > sizeof(ti->Password)) {
                                return -1;
                        }
                        if (pw.data != ti->Password) {
                                memcpy(ti->Password, pw.data, pw.len);
                        }
                        ti->PasswordLength = pw.len;
                }
        }
        return 0;
}

/*
 * Per-level element, struct-wrapper and array coders for
 * SERVER_TRANSPORT_INFO_<n> and its [size_is(EntriesRead)] Buffer.
 */
#define SRVSVC_XPORT_LEVEL_CODERS(n)                                         \
static int                                                                   \
srvsvc_SERVER_TRANSPORT_INFO_##n##_coder(char *name,                         \
                                         struct dcerpc_context *dce,         \
                                         struct dcerpc_pdu *pdu,             \
                                         struct dcerpc_iovec *iov,           \
                                         int *offset, void *ptr)             \
{                                                                            \
        return srvsvc_SERVER_TRANSPORT_INFO_level_coder(n, name, dce, pdu,   \
                                                        iov, offset, ptr);   \
}                                                                            \
static int                                                                   \
srvsvc_SERVER_TRANSPORT_INFO_##n##_STRUCT_coder(char *name,                  \
                                                struct dcerpc_context *dce,  \
                                                struct dcerpc_pdu *pdu,      \
                                                struct dcerpc_iovec *iov,    \
                                                int *offset, void *ptr)      \
{                                                                            \
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,         \
                                   srvsvc_SERVER_TRANSPORT_INFO_##n##_coder); \
}                                                                            \
static int                                                                   \
srvsvc_SERVER_TRANSPORT_INFO_##n##_carray_coder(char *name,                  \
                                                struct dcerpc_context *dce,  \
                                                struct dcerpc_pdu *pdu,      \
                                                struct dcerpc_iovec *iov,    \
                                                int *offset, void *ptr)      \
{                                                                            \
        return dcerpc_carray_coder("TransportInfo" #n, dce, pdu, iov,        \
                                   offset, dcerpc_get_size_is(pdu), ptr,     \
                                   sizeof(struct srvsvc_SERVER_TRANSPORT_INFO), \
                                   srvsvc_SERVER_TRANSPORT_INFO_##n##_STRUCT_coder); \
}

SRVSVC_XPORT_LEVEL_CODERS(0)
SRVSVC_XPORT_LEVEL_CODERS(1)
SRVSVC_XPORT_LEVEL_CODERS(2)
SRVSVC_XPORT_LEVEL_CODERS(3)

static dcerpc_coder srvsvc_xport_carray_coders[] = {
        srvsvc_SERVER_TRANSPORT_INFO_0_carray_coder,
        srvsvc_SERVER_TRANSPORT_INFO_1_carray_coder,
        srvsvc_SERVER_TRANSPORT_INFO_2_carray_coder,
        srvsvc_SERVER_TRANSPORT_INFO_3_carray_coder,
};

/*
 * typedef struct _SERVER_XPORT_INFO_<n>_CONTAINER {
 *       DWORD EntriesRead;
 *       [size_is(EntriesRead)] LPSERVER_TRANSPORT_INFO_<n> Buffer;
 * } SERVER_XPORT_INFO_<n>_CONTAINER;
 *
 * The level is the union discriminant (switch_is), which is in effect for
 * the container whether coded inline or as a deferred pointer referent.
 */
static int
srvsvc_SERVER_XPORT_INFO_CONTAINER_coder(char *name,
                                         struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         struct dcerpc_iovec *iov,
                                         int *offset, void *ptr)
{
        struct srvsvc_SERVER_XPORT_INFO_CONTAINER *ctr = ptr;
        int level = dcerpc_get_switch_is(pdu);

        if (level < 0 || level > 3) {
                return -1;
        }
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset,
                                &ctr->EntriesRead)) {
                return -1;
        }
        if (ctr->EntriesRead) {
                dcerpc_set_size_is(pdu, ctr->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ctr->EntriesRead &&
            ctr->Buffer == NULL) {
                size_t esize = sizeof(struct srvsvc_SERVER_TRANSPORT_INFO);

                if (ctr->EntriesRead > SIZE_MAX / esize) {
                        return -1;
                }
                ctr->Buffer = dcerpc_alloc_data(pdu,
                                (size_t)ctr->EntriesRead * esize);
                if (ctr->Buffer == NULL) {
                        return -1;
                }
        }
        if (dcerpc_ptr_coder("TransportInfo", dce, pdu, iov, offset,
                             ctr->Buffer, PTR_UNIQUE,
                             srvsvc_xport_carray_coders[level])) {
                return -1;
        }
        return 0;
}

/*
 * typedef [switch_type(DWORD)] union _SERVER_XPORT_ENUM_UNION {
 *       [case(0)] PSERVER_XPORT_INFO_0_CONTAINER Level0;
 *       [case(1)] PSERVER_XPORT_INFO_1_CONTAINER Level1;
 *       [case(2)] PSERVER_XPORT_INFO_2_CONTAINER Level2;
 *       [case(3)] PSERVER_XPORT_INFO_3_CONTAINER Level3;
 * } SERVER_XPORT_ENUM_UNION;
 */
static int
srvsvc_SERVER_XPORT_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct dcerpc_iovec *iov, int *offset,
                                     void *ptr)
{
        union srvsvc_SERVER_XPORT_ENUM_UNION *info = ptr;
        struct srvsvc_SERVER_XPORT_INFO_CONTAINER *ctr;
        char *arm;

        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                ctr = &info->Level0;
                arm = "XportInfo0Container";
                break;
        case 1:
                ctr = &info->Level1;
                arm = "XportInfo1Container";
                break;
        case 2:
                ctr = &info->Level2;
                arm = "XportInfo2Container";
                break;
        case 3:
                ctr = &info->Level3;
                arm = "XportInfo3Container";
                break;
        default:
                return -1;
        }
        return dcerpc_ptr_coder(arm, dce, pdu, iov, offset, ctr, PTR_UNIQUE,
                                srvsvc_SERVER_XPORT_INFO_CONTAINER_coder);
}

/*
 * typedef struct _SERVER_XPORT_ENUM_STRUCT {
 *       DWORD Level;
 *       [switch_is(Level)] SERVER_XPORT_ENUM_UNION XportInfo;
 * } SERVER_XPORT_ENUM_STRUCT, *PSERVER_XPORT_ENUM_STRUCT, *LPSERVER_XPORT_ENUM_STRUCT;
 */
static int
srvsvc_SERVER_XPORT_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                      struct dcerpc_pdu *pdu,
                                      struct dcerpc_iovec *iov, int *offset,
                                      void *ptr)
{
        struct srvsvc_SERVER_XPORT_ENUM_STRUCT *xes = ptr;

        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &xes->Level)) {
                return -1;
        }
        if (dcerpc_union_coder("XportInfo", dce, pdu, iov, offset,
                               &xes->Level, &xes->XportInfo,
                               srvsvc_SERVER_XPORT_ENUM_UNION_coder)) {
                return -1;
        }
        return 0;
}

static int
srvsvc_SERVER_XPORT_ENUM_STRUCT_struct_coder(char *name,
                                             struct dcerpc_context *dce,
                                             struct dcerpc_pdu *pdu,
                                             struct dcerpc_iovec *iov,
                                             int *offset, void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SERVER_XPORT_ENUM_STRUCT_coder);
}

/*****************
 * Function: 0x1a
 * NET_API_STATUS NetrServerTransportEnum (
 *   [in,string,unique] SRVSVC_HANDLE ServerName,
 *   [in,out] LPSERVER_XPORT_ENUM_STRUCT InfoStruct,
 *   [in] DWORD PreferedMaximumLength,
 *   [out] DWORD * TotalEntries,
 *   [in,out,unique] DWORD * ResumeHandle
 * );
 */
int
srvsvc_NetrServerTransportEnum_req_coder(char *name,
                                         struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         struct dcerpc_iovec *iov,
                                         int *offset, void *ptr)
{
        struct srvsvc_NetrServerTransportEnum_req *req = ptr;

        if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset,
                             &req->ServerName, PTR_UNIQUE,
                             dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset,
                             &req->InfoStruct, PTR_REF,
                             srvsvc_SERVER_XPORT_ENUM_STRUCT_struct_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("PreferedMaximumLength", dce, pdu, iov, offset,
                             &req->PreferedMaximumLength, PTR_REF,
                             dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset,
                             &req->ResumeHandle, PTR_UNIQUE,
                             dcerpc_uint32_coder)) {
                return -1;
        }
        return 0;
}

int
srvsvc_NetrServerTransportEnum_rep_coder(char *name,
                                         struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         struct dcerpc_iovec *iov,
                                         int *offset, void *ptr)
{
        struct srvsvc_NetrServerTransportEnum_rep *rep = ptr;

        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset,
                             &rep->InfoStruct, PTR_REF,
                             srvsvc_SERVER_XPORT_ENUM_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TotalEntries", dce, pdu, iov, offset,
                             &rep->TotalEntries, PTR_REF,
                             dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ResumeHandle", dce, pdu, iov, offset,
                             &rep->ResumeHandle, PTR_UNIQUE,
                             dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset,
                                &rep->status)) {
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
         srvsvc_NetrShareDelSticky_req_coder, sizeof(struct srvsvc_NetrShareDelSticky_req),
         srvsvc_NetrShareDelSticky_rep_coder, sizeof(struct srvsvc_NetrShareDelSticky_rep),
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
        {SRVSVC_NETRSERVERTRANSPORTENUM, "NetrServerTransportEnum",
         srvsvc_NetrServerTransportEnum_req_coder,
         sizeof(struct srvsvc_NetrServerTransportEnum_req),
         srvsvc_NetrServerTransportEnum_rep_coder,
         sizeof(struct srvsvc_NetrServerTransportEnum_rep),
        },
        {SRVSVC_NETRREMOTETOD, "NetrRemoteTOD",
         srvsvc_NetrRemoteTOD_req_coder, sizeof(struct srvsvc_NetrRemoteTOD_req),
         srvsvc_NetrRemoteTOD_rep_coder, sizeof(struct srvsvc_NetrRemoteTOD_rep),
        },
        {-1, NULL, NULL, 0, NULL, 0}
};

