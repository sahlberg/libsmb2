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

/*
 * SRVSVC BEGIN:  DEFINITIONS FROM SRVSVC.IDL
 * [MS-SRVS].pdf
 */

/*
 * Types for the connection, file, session, share and server calls:
 * generated from the [MS-SRVS] IDL; field names follow the IDL.
 */
int srvsvc_CONNECTION_INFO_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_CONNECTION_INFO_1_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_FILE_INFO_2_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_FILE_INFO_3_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_1_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_2_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_10_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
int srvsvc_SESSION_INFO_502_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                int *offset, void *ptr);
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
srvsvc_CONNECTION_INFO_0_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_CONNECTION_INFO_0),
                                   srvsvc_CONNECTION_INFO_0_coder);
}

static int
srvsvc_CONNECTION_INFO_1_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_CONNECTION_INFO_1),
                                   srvsvc_CONNECTION_INFO_1_coder);
}

static int
srvsvc_FILE_INFO_2_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_FILE_INFO_2),
                                   srvsvc_FILE_INFO_2_coder);
}

static int
srvsvc_FILE_INFO_3_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_FILE_INFO_3),
                                   srvsvc_FILE_INFO_3_coder);
}

static int
srvsvc_SESSION_INFO_0_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SESSION_INFO_0),
                                   srvsvc_SESSION_INFO_0_coder);
}

static int
srvsvc_SESSION_INFO_1_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SESSION_INFO_1),
                                   srvsvc_SESSION_INFO_1_coder);
}

static int
srvsvc_SESSION_INFO_2_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SESSION_INFO_2),
                                   srvsvc_SESSION_INFO_2_coder);
}

static int
srvsvc_SESSION_INFO_10_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SESSION_INFO_10),
                                   srvsvc_SESSION_INFO_10_coder);
}

static int
srvsvc_SESSION_INFO_502_carray_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_carray_coder(name, dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct srvsvc_SESSION_INFO_502),
                                   srvsvc_SESSION_INFO_502_coder);
}

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
srvsvc_CONNECTION_INFO_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_CONNECTION_INFO_0 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("coni0_id", dce, pdu, iov, offset, &s->coni0_id)) {
                return -1;
        }

        return 0;
}

int
srvsvc_CONNECTION_INFO_0_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_CONNECTION_INFO_0_coder);
}

int
srvsvc_CONNECT_INFO_0_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_CONNECT_INFO_0_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_CONNECTION_INFO_0);
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
                             PTR_UNIQUE, srvsvc_CONNECTION_INFO_0_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_CONNECT_INFO_0_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_CONNECT_INFO_0_CONTAINER_coder);
}

int
srvsvc_CONNECTION_INFO_1_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_CONNECTION_INFO_1 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("coni1_id", dce, pdu, iov, offset, &s->coni1_id)) {
                return -1;
        }
        if (dcerpc_uint32_coder("coni1_type", dce, pdu, iov, offset, &s->coni1_type)) {
                return -1;
        }
        if (dcerpc_uint32_coder("coni1_num_opens", dce, pdu, iov, offset, &s->coni1_num_opens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("coni1_num_users", dce, pdu, iov, offset, &s->coni1_num_users)) {
                return -1;
        }
        if (dcerpc_uint32_coder("coni1_time", dce, pdu, iov, offset, &s->coni1_time)) {
                return -1;
        }
        if (dcerpc_ptr_coder("coni1_username", dce, pdu, iov, offset, &s->coni1_username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("coni1_netname", dce, pdu, iov, offset, &s->coni1_netname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_CONNECTION_INFO_1_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_CONNECTION_INFO_1_coder);
}

int
srvsvc_CONNECT_INFO_1_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_CONNECT_INFO_1_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_CONNECTION_INFO_1);
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
                             PTR_UNIQUE, srvsvc_CONNECTION_INFO_1_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_CONNECT_INFO_1_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_CONNECT_INFO_1_CONTAINER_coder);
}

int
srvsvc_CONNECT_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        union srvsvc_CONNECT_ENUM_UNION *u = ptr;

        (void)name;
        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                if (dcerpc_ptr_coder("Level0", dce, pdu, iov, offset, &u->Level0,
                                     PTR_UNIQUE, srvsvc_CONNECT_INFO_0_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 1:
                if (dcerpc_ptr_coder("Level1", dce, pdu, iov, offset, &u->Level1,
                                     PTR_UNIQUE, srvsvc_CONNECT_INFO_1_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        default:
                /* NDR conformance pass: the discriminant is not read yet */
                if (dcerpc_pdu_is_conformance_run(pdu)) {
                        return 0;
                }
                return -1;
        }

        return 0;
}

int
srvsvc_CONNECT_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_CONNECT_ENUM_STRUCT *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &s->Level)) {
                return -1;
        }
        if (dcerpc_union_coder("ConnectInfo", dce, pdu, iov, offset,
                               &s->Level, &s->ConnectInfo,
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

int
srvsvc_FILE_INFO_2_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_FILE_INFO_2 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("fi2_id", dce, pdu, iov, offset, &s->fi2_id)) {
                return -1;
        }

        return 0;
}

int
srvsvc_FILE_INFO_2_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_FILE_INFO_2_coder);
}

int
srvsvc_FILE_INFO_2_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_FILE_INFO_2_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_FILE_INFO_2);
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
                             PTR_UNIQUE, srvsvc_FILE_INFO_2_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_FILE_INFO_2_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_FILE_INFO_2_CONTAINER_coder);
}

int
srvsvc_FILE_INFO_3_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_FILE_INFO_3 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("fi3_id", dce, pdu, iov, offset, &s->fi3_id)) {
                return -1;
        }
        if (dcerpc_uint32_coder("fi3_permissions", dce, pdu, iov, offset, &s->fi3_permissions)) {
                return -1;
        }
        if (dcerpc_uint32_coder("fi3_num_locks", dce, pdu, iov, offset, &s->fi3_num_locks)) {
                return -1;
        }
        if (dcerpc_ptr_coder("fi3_pathname", dce, pdu, iov, offset, &s->fi3_pathname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("fi3_username", dce, pdu, iov, offset, &s->fi3_username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_FILE_INFO_3_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_FILE_INFO_3_coder);
}

int
srvsvc_FILE_INFO_3_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_FILE_INFO_3_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_FILE_INFO_3);
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
                             PTR_UNIQUE, srvsvc_FILE_INFO_3_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_FILE_INFO_3_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_FILE_INFO_3_CONTAINER_coder);
}

int
srvsvc_FILE_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        union srvsvc_FILE_ENUM_UNION *u = ptr;

        (void)name;
        switch (dcerpc_get_switch_is(pdu)) {
        case 2:
                if (dcerpc_ptr_coder("Level2", dce, pdu, iov, offset, &u->Level2,
                                     PTR_UNIQUE, srvsvc_FILE_INFO_2_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 3:
                if (dcerpc_ptr_coder("Level3", dce, pdu, iov, offset, &u->Level3,
                                     PTR_UNIQUE, srvsvc_FILE_INFO_3_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        default:
                /* NDR conformance pass: the discriminant is not read yet */
                if (dcerpc_pdu_is_conformance_run(pdu)) {
                        return 0;
                }
                return -1;
        }

        return 0;
}

int
srvsvc_FILE_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_FILE_ENUM_STRUCT *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &s->Level)) {
                return -1;
        }
        if (dcerpc_union_coder("FileInfo", dce, pdu, iov, offset,
                               &s->Level, &s->FileInfo,
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

int
srvsvc_FILE_INFO_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        union srvsvc_FILE_INFO *u = ptr;

        (void)name;
        switch (dcerpc_get_switch_is(pdu)) {
        case 2:
                if (dcerpc_ptr_coder("FileInfo2", dce, pdu, iov, offset, &u->FileInfo2,
                                     PTR_UNIQUE, srvsvc_FILE_INFO_2_struct_coder)) {
                        return -1;
                }
                break;
        case 3:
                if (dcerpc_ptr_coder("FileInfo3", dce, pdu, iov, offset, &u->FileInfo3,
                                     PTR_UNIQUE, srvsvc_FILE_INFO_3_struct_coder)) {
                        return -1;
                }
                break;
        default:
                /* NDR conformance pass: the discriminant is not read yet */
                if (dcerpc_pdu_is_conformance_run(pdu)) {
                        return 0;
                }
                return -1;
        }

        return 0;
}

/* The union as a [switch_is] parameter: discriminant from switch_is */
int
srvsvc_FILE_INFO_switch_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        uint32_t level = dcerpc_get_switch_is(pdu);

        return dcerpc_union_coder(name, dce, pdu, iov, offset, &level, ptr,
                                  srvsvc_FILE_INFO_coder);
}

int
srvsvc_SESSION_INFO_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_INFO_0 *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("sesi0_cname", dce, pdu, iov, offset, &s->sesi0_cname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_INFO_0_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_0_coder);
}

int
srvsvc_SESSION_INFO_0_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_INFO_0_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SESSION_INFO_0);
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
                             PTR_UNIQUE, srvsvc_SESSION_INFO_0_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_INFO_0_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_0_CONTAINER_coder);
}

int
srvsvc_SESSION_INFO_1_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_INFO_1 *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("sesi1_cname", dce, pdu, iov, offset, &s->sesi1_cname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sesi1_username", dce, pdu, iov, offset, &s->sesi1_username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi1_num_opens", dce, pdu, iov, offset, &s->sesi1_num_opens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi1_time", dce, pdu, iov, offset, &s->sesi1_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi1_idle_time", dce, pdu, iov, offset, &s->sesi1_idle_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi1_user_flags", dce, pdu, iov, offset, &s->sesi1_user_flags)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_INFO_1_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_1_coder);
}

int
srvsvc_SESSION_INFO_1_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_INFO_1_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SESSION_INFO_1);
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
                             PTR_UNIQUE, srvsvc_SESSION_INFO_1_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_INFO_1_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_1_CONTAINER_coder);
}

int
srvsvc_SESSION_INFO_2_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_INFO_2 *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("sesi2_cname", dce, pdu, iov, offset, &s->sesi2_cname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sesi2_username", dce, pdu, iov, offset, &s->sesi2_username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi2_num_opens", dce, pdu, iov, offset, &s->sesi2_num_opens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi2_time", dce, pdu, iov, offset, &s->sesi2_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi2_idle_time", dce, pdu, iov, offset, &s->sesi2_idle_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi2_user_flags", dce, pdu, iov, offset, &s->sesi2_user_flags)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sesi2_cltype_name", dce, pdu, iov, offset, &s->sesi2_cltype_name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_INFO_2_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_2_coder);
}

int
srvsvc_SESSION_INFO_2_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_INFO_2_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SESSION_INFO_2);
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
                             PTR_UNIQUE, srvsvc_SESSION_INFO_2_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_INFO_2_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_2_CONTAINER_coder);
}

int
srvsvc_SESSION_INFO_10_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_INFO_10 *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("sesi10_cname", dce, pdu, iov, offset, &s->sesi10_cname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sesi10_username", dce, pdu, iov, offset, &s->sesi10_username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi10_time", dce, pdu, iov, offset, &s->sesi10_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi10_idle_time", dce, pdu, iov, offset, &s->sesi10_idle_time)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_INFO_10_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_10_coder);
}

int
srvsvc_SESSION_INFO_10_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_INFO_10_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SESSION_INFO_10);
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
                             PTR_UNIQUE, srvsvc_SESSION_INFO_10_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_INFO_10_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_10_CONTAINER_coder);
}

int
srvsvc_SESSION_INFO_502_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_INFO_502 *s = ptr;

        (void)name;
        if (dcerpc_ptr_coder("sesi502_cname", dce, pdu, iov, offset, &s->sesi502_cname,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sesi502_username", dce, pdu, iov, offset, &s->sesi502_username,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi502_num_opens", dce, pdu, iov, offset, &s->sesi502_num_opens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi502_time", dce, pdu, iov, offset, &s->sesi502_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi502_idle_time", dce, pdu, iov, offset, &s->sesi502_idle_time)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sesi502_user_flags", dce, pdu, iov, offset, &s->sesi502_user_flags)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sesi502_cltype_name", dce, pdu, iov, offset, &s->sesi502_cltype_name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sesi502_transport", dce, pdu, iov, offset, &s->sesi502_transport,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_INFO_502_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_502_coder);
}

int
srvsvc_SESSION_INFO_502_CONTAINER_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_INFO_502_CONTAINER *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("EntriesRead", dce, pdu, iov, offset, &s->EntriesRead)) {
                return -1;
        }
        if (s->EntriesRead) {
                dcerpc_set_size_is(pdu, s->EntriesRead);
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && s->EntriesRead) {
                if (s->Buffer == NULL) {
                        size_t esize = sizeof(struct srvsvc_SESSION_INFO_502);
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
                             PTR_UNIQUE, srvsvc_SESSION_INFO_502_carray_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_INFO_502_CONTAINER_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SESSION_INFO_502_CONTAINER_coder);
}

int
srvsvc_SESSION_ENUM_UNION_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        union srvsvc_SESSION_ENUM_UNION *u = ptr;

        (void)name;
        switch (dcerpc_get_switch_is(pdu)) {
        case 0:
                if (dcerpc_ptr_coder("Level0", dce, pdu, iov, offset, &u->Level0,
                                     PTR_UNIQUE, srvsvc_SESSION_INFO_0_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 1:
                if (dcerpc_ptr_coder("Level1", dce, pdu, iov, offset, &u->Level1,
                                     PTR_UNIQUE, srvsvc_SESSION_INFO_1_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 2:
                if (dcerpc_ptr_coder("Level2", dce, pdu, iov, offset, &u->Level2,
                                     PTR_UNIQUE, srvsvc_SESSION_INFO_2_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 10:
                if (dcerpc_ptr_coder("Level10", dce, pdu, iov, offset, &u->Level10,
                                     PTR_UNIQUE, srvsvc_SESSION_INFO_10_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        case 502:
                if (dcerpc_ptr_coder("Level502", dce, pdu, iov, offset, &u->Level502,
                                     PTR_UNIQUE, srvsvc_SESSION_INFO_502_CONTAINER_struct_coder)) {
                        return -1;
                }
                break;
        default:
                /* NDR conformance pass: the discriminant is not read yet */
                if (dcerpc_pdu_is_conformance_run(pdu)) {
                        return 0;
                }
                return -1;
        }

        return 0;
}

int
srvsvc_SESSION_ENUM_STRUCT_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SESSION_ENUM_STRUCT *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("Level", dce, pdu, iov, offset, &s->Level)) {
                return -1;
        }
        if (dcerpc_union_coder("SessionInfo", dce, pdu, iov, offset,
                               &s->Level, &s->SessionInfo,
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
                /* NDR conformance pass: the discriminant is not read yet */
                if (dcerpc_pdu_is_conformance_run(pdu)) {
                        return 0;
                }
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
                /* NDR conformance pass: the discriminant is not read yet */
                if (dcerpc_pdu_is_conformance_run(pdu)) {
                        return 0;
                }
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

int
srvsvc_SERVER_INFO_100_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SERVER_INFO_100 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("sv100_platform_id", dce, pdu, iov, offset, &s->sv100_platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sv100_name", dce, pdu, iov, offset, &s->sv100_name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SERVER_INFO_100_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SERVER_INFO_100_coder);
}

int
srvsvc_SERVER_INFO_101_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SERVER_INFO_101 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("sv101_platform_id", dce, pdu, iov, offset, &s->sv101_platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sv101_name", dce, pdu, iov, offset, &s->sv101_name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv101_version_major", dce, pdu, iov, offset, &s->sv101_version_major)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv101_version_minor", dce, pdu, iov, offset, &s->sv101_version_minor)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv101_type", dce, pdu, iov, offset, &s->sv101_type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sv101_comment", dce, pdu, iov, offset, &s->sv101_comment,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SERVER_INFO_101_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SERVER_INFO_101_coder);
}

int
srvsvc_SERVER_INFO_102_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SERVER_INFO_102 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("sv102_platform_id", dce, pdu, iov, offset, &s->sv102_platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sv102_name", dce, pdu, iov, offset, &s->sv102_name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv102_version_major", dce, pdu, iov, offset, &s->sv102_version_major)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv102_version_minor", dce, pdu, iov, offset, &s->sv102_version_minor)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv102_type", dce, pdu, iov, offset, &s->sv102_type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sv102_comment", dce, pdu, iov, offset, &s->sv102_comment,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv102_users", dce, pdu, iov, offset, &s->sv102_users)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv102_disc", dce, pdu, iov, offset, &s->sv102_disc)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv102_hidden", dce, pdu, iov, offset, &s->sv102_hidden)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv102_announce", dce, pdu, iov, offset, &s->sv102_announce)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv102_anndelta", dce, pdu, iov, offset, &s->sv102_anndelta)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv102_licenses", dce, pdu, iov, offset, &s->sv102_licenses)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sv102_userpath", dce, pdu, iov, offset, &s->sv102_userpath,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SERVER_INFO_102_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SERVER_INFO_102_coder);
}

int
srvsvc_SERVER_INFO_103_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SERVER_INFO_103 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("sv103_platform_id", dce, pdu, iov, offset, &s->sv103_platform_id)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sv103_name", dce, pdu, iov, offset, &s->sv103_name,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv103_version_major", dce, pdu, iov, offset, &s->sv103_version_major)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv103_version_minor", dce, pdu, iov, offset, &s->sv103_version_minor)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv103_type", dce, pdu, iov, offset, &s->sv103_type)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sv103_comment", dce, pdu, iov, offset, &s->sv103_comment,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv103_users", dce, pdu, iov, offset, &s->sv103_users)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv103_disc", dce, pdu, iov, offset, &s->sv103_disc)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv103_hidden", dce, pdu, iov, offset, &s->sv103_hidden)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv103_announce", dce, pdu, iov, offset, &s->sv103_announce)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv103_anndelta", dce, pdu, iov, offset, &s->sv103_anndelta)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv103_licenses", dce, pdu, iov, offset, &s->sv103_licenses)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sv103_userpath", dce, pdu, iov, offset, &s->sv103_userpath,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv103_capabilities", dce, pdu, iov, offset, &s->sv103_capabilities)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SERVER_INFO_103_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SERVER_INFO_103_coder);
}

int
srvsvc_SERVER_INFO_502_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SERVER_INFO_502 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("sv502_sessopens", dce, pdu, iov, offset, &s->sv502_sessopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_sessvcs", dce, pdu, iov, offset, &s->sv502_sessvcs)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_opensearch", dce, pdu, iov, offset, &s->sv502_opensearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_sizreqbuf", dce, pdu, iov, offset, &s->sv502_sizreqbuf)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_initworkitems", dce, pdu, iov, offset, &s->sv502_initworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_maxworkitems", dce, pdu, iov, offset, &s->sv502_maxworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_rawworkitems", dce, pdu, iov, offset, &s->sv502_rawworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_irpstacksize", dce, pdu, iov, offset, &s->sv502_irpstacksize)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_maxrawbuflen", dce, pdu, iov, offset, &s->sv502_maxrawbuflen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_sessusers", dce, pdu, iov, offset, &s->sv502_sessusers)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_sessconns", dce, pdu, iov, offset, &s->sv502_sessconns)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_maxpagedmemoryusage", dce, pdu, iov, offset, &s->sv502_maxpagedmemoryusage)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_maxnonpagedmemoryusage", dce, pdu, iov, offset, &s->sv502_maxnonpagedmemoryusage)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_enablesoftcompat", dce, pdu, iov, offset, &s->sv502_enablesoftcompat)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_enableforcedlogoff", dce, pdu, iov, offset, &s->sv502_enableforcedlogoff)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_timesource", dce, pdu, iov, offset, &s->sv502_timesource)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_acceptdownlevelapis", dce, pdu, iov, offset, &s->sv502_acceptdownlevelapis)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv502_lmannounce", dce, pdu, iov, offset, &s->sv502_lmannounce)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SERVER_INFO_502_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SERVER_INFO_502_coder);
}

int
srvsvc_SERVER_INFO_503_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_SERVER_INFO_503 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("sv503_sessopens", dce, pdu, iov, offset, &s->sv503_sessopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_sessvcs", dce, pdu, iov, offset, &s->sv503_sessvcs)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_opensearch", dce, pdu, iov, offset, &s->sv503_opensearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_sizreqbuf", dce, pdu, iov, offset, &s->sv503_sizreqbuf)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_initworkitems", dce, pdu, iov, offset, &s->sv503_initworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_maxworkitems", dce, pdu, iov, offset, &s->sv503_maxworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_rawworkitems", dce, pdu, iov, offset, &s->sv503_rawworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_irpstacksize", dce, pdu, iov, offset, &s->sv503_irpstacksize)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_maxrawbuflen", dce, pdu, iov, offset, &s->sv503_maxrawbuflen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_sessusers", dce, pdu, iov, offset, &s->sv503_sessusers)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_sessconns", dce, pdu, iov, offset, &s->sv503_sessconns)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_maxpagedmemoryusage", dce, pdu, iov, offset, &s->sv503_maxpagedmemoryusage)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_maxnonpagedmemoryusage", dce, pdu, iov, offset, &s->sv503_maxnonpagedmemoryusage)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_enablesoftcompat", dce, pdu, iov, offset, &s->sv503_enablesoftcompat)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_enableforcedlogoff", dce, pdu, iov, offset, &s->sv503_enableforcedlogoff)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_timesource", dce, pdu, iov, offset, &s->sv503_timesource)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_acceptdownlevelapis", dce, pdu, iov, offset, &s->sv503_acceptdownlevelapis)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_lmannounce", dce, pdu, iov, offset, &s->sv503_lmannounce)) {
                return -1;
        }
        if (dcerpc_ptr_coder("sv503_domain", dce, pdu, iov, offset, &s->sv503_domain,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_maxcopyreadlen", dce, pdu, iov, offset, &s->sv503_maxcopyreadlen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_maxcopywritelen", dce, pdu, iov, offset, &s->sv503_maxcopywritelen)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_minkeepsearch", dce, pdu, iov, offset, &s->sv503_minkeepsearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_maxkeepsearch", dce, pdu, iov, offset, &s->sv503_maxkeepsearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_minkeepcomplsearch", dce, pdu, iov, offset, &s->sv503_minkeepcomplsearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_maxkeepcomplsearch", dce, pdu, iov, offset, &s->sv503_maxkeepcomplsearch)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_threadcountadd", dce, pdu, iov, offset, &s->sv503_threadcountadd)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_numblockthreads", dce, pdu, iov, offset, &s->sv503_numblockthreads)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_scavtimeout", dce, pdu, iov, offset, &s->sv503_scavtimeout)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_minrcvqueue", dce, pdu, iov, offset, &s->sv503_minrcvqueue)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_minfreeworkitems", dce, pdu, iov, offset, &s->sv503_minfreeworkitems)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_xactmemsize", dce, pdu, iov, offset, &s->sv503_xactmemsize)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_threadpriority", dce, pdu, iov, offset, &s->sv503_threadpriority)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_maxmpxct", dce, pdu, iov, offset, &s->sv503_maxmpxct)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_oplockbreakwait", dce, pdu, iov, offset, &s->sv503_oplockbreakwait)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_oplockbreakresponsewait", dce, pdu, iov, offset, &s->sv503_oplockbreakresponsewait)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_enableoplocks", dce, pdu, iov, offset, &s->sv503_enableoplocks)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_enableoplockforceclose", dce, pdu, iov, offset, &s->sv503_enableoplockforceclose)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_enablefcbopens", dce, pdu, iov, offset, &s->sv503_enablefcbopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_enableraw", dce, pdu, iov, offset, &s->sv503_enableraw)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_enablesharednetdrives", dce, pdu, iov, offset, &s->sv503_enablesharednetdrives)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_minfreeconnections", dce, pdu, iov, offset, &s->sv503_minfreeconnections)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sv503_maxfreeconnections", dce, pdu, iov, offset, &s->sv503_maxfreeconnections)) {
                return -1;
        }

        return 0;
}

int
srvsvc_SERVER_INFO_503_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_SERVER_INFO_503_coder);
}

int
srvsvc_SERVER_INFO_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        union srvsvc_SERVER_INFO *u = ptr;

        (void)name;
        switch (dcerpc_get_switch_is(pdu)) {
        case 100:
                if (dcerpc_ptr_coder("ServerInfo100", dce, pdu, iov, offset, &u->ServerInfo100,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_100_struct_coder)) {
                        return -1;
                }
                break;
        case 101:
                if (dcerpc_ptr_coder("ServerInfo101", dce, pdu, iov, offset, &u->ServerInfo101,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_101_struct_coder)) {
                        return -1;
                }
                break;
        case 102:
                if (dcerpc_ptr_coder("ServerInfo102", dce, pdu, iov, offset, &u->ServerInfo102,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_102_struct_coder)) {
                        return -1;
                }
                break;
        case 103:
                if (dcerpc_ptr_coder("ServerInfo103", dce, pdu, iov, offset, &u->ServerInfo103,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_103_struct_coder)) {
                        return -1;
                }
                break;
        case 502:
                if (dcerpc_ptr_coder("ServerInfo502", dce, pdu, iov, offset, &u->ServerInfo502,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_502_struct_coder)) {
                        return -1;
                }
                break;
        case 503:
                if (dcerpc_ptr_coder("ServerInfo503", dce, pdu, iov, offset, &u->ServerInfo503,
                                     PTR_UNIQUE, srvsvc_SERVER_INFO_503_struct_coder)) {
                        return -1;
                }
                break;
        default:
                /* NDR conformance pass: the discriminant is not read yet */
                if (dcerpc_pdu_is_conformance_run(pdu)) {
                        return 0;
                }
                return -1;
        }

        return 0;
}

/* The union as a [switch_is] parameter: discriminant from switch_is */
int
srvsvc_SERVER_INFO_switch_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        uint32_t level = dcerpc_get_switch_is(pdu);

        return dcerpc_union_coder(name, dce, pdu, iov, offset, &level, ptr,
                                  srvsvc_SERVER_INFO_coder);
}

int
srvsvc_STAT_SERVER_0_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_STAT_SERVER_0 *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("sts0_start", dce, pdu, iov, offset, &s->sts0_start)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_fopens", dce, pdu, iov, offset, &s->sts0_fopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_devopens", dce, pdu, iov, offset, &s->sts0_devopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_jobsqueued", dce, pdu, iov, offset, &s->sts0_jobsqueued)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_sopens", dce, pdu, iov, offset, &s->sts0_sopens)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_stimedout", dce, pdu, iov, offset, &s->sts0_stimedout)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_serrorout", dce, pdu, iov, offset, &s->sts0_serrorout)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_pwerrors", dce, pdu, iov, offset, &s->sts0_pwerrors)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_permerrors", dce, pdu, iov, offset, &s->sts0_permerrors)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_syserrors", dce, pdu, iov, offset, &s->sts0_syserrors)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_bytessent_low", dce, pdu, iov, offset, &s->sts0_bytessent_low)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_bytessent_high", dce, pdu, iov, offset, &s->sts0_bytessent_high)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_bytesrcvd_low", dce, pdu, iov, offset, &s->sts0_bytesrcvd_low)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_bytesrcvd_high", dce, pdu, iov, offset, &s->sts0_bytesrcvd_high)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_avresponse", dce, pdu, iov, offset, &s->sts0_avresponse)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_reqbufneed", dce, pdu, iov, offset, &s->sts0_reqbufneed)) {
                return -1;
        }
        if (dcerpc_uint32_coder("sts0_bigbufneed", dce, pdu, iov, offset, &s->sts0_bigbufneed)) {
                return -1;
        }

        return 0;
}

int
srvsvc_STAT_SERVER_0_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_STAT_SERVER_0_coder);
}

int
srvsvc_TIME_OF_DAY_INFO_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_TIME_OF_DAY_INFO *s = ptr;

        (void)name;
        if (dcerpc_uint32_coder("tod_elapsedt", dce, pdu, iov, offset, &s->tod_elapsedt)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_msecs", dce, pdu, iov, offset, &s->tod_msecs)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_hours", dce, pdu, iov, offset, &s->tod_hours)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_mins", dce, pdu, iov, offset, &s->tod_mins)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_secs", dce, pdu, iov, offset, &s->tod_secs)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_hunds", dce, pdu, iov, offset, &s->tod_hunds)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_timezone", dce, pdu, iov, offset, &s->tod_timezone)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_tinterval", dce, pdu, iov, offset, &s->tod_tinterval)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_day", dce, pdu, iov, offset, &s->tod_day)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_month", dce, pdu, iov, offset, &s->tod_month)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_year", dce, pdu, iov, offset, &s->tod_year)) {
                return -1;
        }
        if (dcerpc_uint32_coder("tod_weekday", dce, pdu, iov, offset, &s->tod_weekday)) {
                return -1;
        }

        return 0;
}

int
srvsvc_TIME_OF_DAY_INFO_struct_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   srvsvc_TIME_OF_DAY_INFO_coder);
}

/*****************
 * Function: 0x08  NetrConnectionEnum  (SRVSVC_NETRCONNECTIONENUM)
 *****************/
int
srvsvc_NetrConnectionEnum_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrConnectionEnum_req *req = ptr;

        (void)name;
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ServerName == NULL) {
                if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->Qualifier == NULL) {
                if (dcerpc_ptr_coder("Qualifier", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("Qualifier", dce, pdu, iov, offset, &req->Qualifier,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->InfoStruct,
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

        (void)name;
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_REF, srvsvc_CONNECT_ENUM_STRUCT_coder)) {
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
 * Function: 0x09  NetrFileEnum  (SRVSVC_NETRFILEENUM)
 *****************/
int
srvsvc_NetrFileEnum_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrFileEnum_req *req = ptr;

        (void)name;
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ServerName == NULL) {
                if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->BasePath == NULL) {
                if (dcerpc_ptr_coder("BasePath", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("BasePath", dce, pdu, iov, offset, &req->BasePath,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->UserName == NULL) {
                if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, &req->UserName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->InfoStruct,
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

        (void)name;
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_REF, srvsvc_FILE_ENUM_STRUCT_coder)) {
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
 * Function: 0x0a  NetrFileGetInfo  (SRVSVC_NETRFILEGETINFO)
 *****************/
int
srvsvc_NetrFileGetInfo_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrFileGetInfo_req *req = ptr;

        (void)name;
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ServerName == NULL) {
                if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("FileId", dce, pdu, iov, offset, &req->FileId,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Level", dce, pdu, iov, offset, &req->Level,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrFileGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrFileGetInfo_rep *rep = ptr;
        /* the discriminant is only in the request */
        struct srvsvc_NetrFileGetInfo_req *req = dcerpc_get_request(pdu);

        (void)name;
        if (req == NULL) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_REF, srvsvc_FILE_INFO_switch_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x0b  NetrFileClose  (SRVSVC_NETRFILECLOSE)
 *****************/
int
srvsvc_NetrFileClose_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrFileClose_req *req = ptr;

        (void)name;
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ServerName == NULL) {
                if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("FileId", dce, pdu, iov, offset, &req->FileId,
                             PTR_REF, dcerpc_uint32_coder)) {
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

        (void)name;
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x0c  NetrSessionEnum  (SRVSVC_NETRSESSIONENUM)
 *****************/
int
srvsvc_NetrSessionEnum_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrSessionEnum_req *req = ptr;

        (void)name;
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ServerName == NULL) {
                if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ClientName == NULL) {
                if (dcerpc_ptr_coder("ClientName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ClientName", dce, pdu, iov, offset, &req->ClientName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->UserName == NULL) {
                if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, &req->UserName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &req->InfoStruct,
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

        (void)name;
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_REF, srvsvc_SESSION_ENUM_STRUCT_coder)) {
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
 * Function: 0x0d  NetrSessionDel  (SRVSVC_NETRSESSIONDEL)
 *****************/
int
srvsvc_NetrSessionDel_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrSessionDel_req *req = ptr;

        (void)name;
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ServerName == NULL) {
                if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ClientName == NULL) {
                if (dcerpc_ptr_coder("ClientName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ClientName", dce, pdu, iov, offset, &req->ClientName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->UserName == NULL) {
                if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("UserName", dce, pdu, iov, offset, &req->UserName,
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

        (void)name;
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

/*****************
 * Function: 0x15  NetrServerGetInfo  (SRVSVC_NETRSERVERGETINFO)
 *****************/
int
srvsvc_NetrServerGetInfo_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrServerGetInfo_req *req = ptr;

        (void)name;
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ServerName == NULL) {
                if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Level", dce, pdu, iov, offset, &req->Level,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

int
srvsvc_NetrServerGetInfo_rep_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrServerGetInfo_rep *rep = ptr;
        /* the discriminant is only in the request */
        struct srvsvc_NetrServerGetInfo_req *req = dcerpc_get_request(pdu);

        (void)name;
        if (req == NULL) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_REF, srvsvc_SERVER_INFO_switch_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x16  NetrServerSetInfo  (SRVSVC_NETRSERVERSETINFO)
 *****************/
int
srvsvc_NetrServerSetInfo_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrServerSetInfo_req *req = ptr;

        (void)name;
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ServerName == NULL) {
                if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Level", dce, pdu, iov, offset, &req->Level,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        dcerpc_set_switch_is(pdu, req->Level);
        if (dcerpc_ptr_coder("ServerInfo", dce, pdu, iov, offset, &req->ServerInfo,
                             PTR_REF, srvsvc_SERVER_INFO_switch_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ParmError", dce, pdu, iov, offset, &req->ParmError,
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

        (void)name;
        if (dcerpc_ptr_coder("ParmError", dce, pdu, iov, offset, &rep->ParmError,
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

/*****************
 * Function: 0x18  NetrServerStatisticsGet  (SRVSVC_NETRSERVERSTATISTICSGET)
 *****************/
int
srvsvc_NetrServerStatisticsGet_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrServerStatisticsGet_req *req = ptr;

        (void)name;
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ServerName == NULL) {
                if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->Service == NULL) {
                if (dcerpc_ptr_coder("Service", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("Service", dce, pdu, iov, offset, &req->Service,
                                    PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Level", dce, pdu, iov, offset, &req->Level,
                             PTR_REF, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Options", dce, pdu, iov, offset, &req->Options,
                             PTR_REF, dcerpc_uint32_coder)) {
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

        (void)name;
        if (dcerpc_ptr_coder("InfoStruct", dce, pdu, iov, offset, &rep->InfoStruct,
                             PTR_UNIQUE, srvsvc_STAT_SERVER_0_struct_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*****************
 * Function: 0x1c  NetrRemoteTOD  (SRVSVC_NETRREMOTETOD)
 *****************/
int
srvsvc_NetrRemoteTOD_req_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct srvsvc_NetrRemoteTOD_req *req = ptr;

        (void)name;
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            req->ServerName == NULL) {
                if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, NULL,
                                     PTR_UNIQUE, dcerpc_utf16z_coder)) {
                        return -1;
                }
        } else if (dcerpc_ptr_coder("ServerName", dce, pdu, iov, offset, &req->ServerName,
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

        (void)name;
        if (dcerpc_ptr_coder("BufferPtr", dce, pdu, iov, offset, &rep->BufferPtr,
                             PTR_UNIQUE, srvsvc_TIME_OF_DAY_INFO_struct_coder)) {
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

