/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2020 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
#include <dcerpc/dcerpc-lsa.h>
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

#define LSA_UUID    0x12345778, 0x1234, 0xabcd, {0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}

p_syntax_id_t lsa_interface = {
        {LSA_UUID}, 0, 0
};

/* Policy DesiredAccess (LSA_POLICY_*) */
static struct dcerpc_uint32_pretty_printer policy_access_pp = {
        .fmt = "0x%08x",
        .bitfields = {
                { "VIEW_LOCAL_INFORMATION",
                  LSA_POLICY_VIEW_LOCAL_INFORMATION,
                  LSA_POLICY_VIEW_LOCAL_INFORMATION },
                { "VIEW_AUDIT_INFORMATION",
                  LSA_POLICY_VIEW_AUDIT_INFORMATION,
                  LSA_POLICY_VIEW_AUDIT_INFORMATION },
                { "GET_PRIVATE_INFORMATION",
                  LSA_POLICY_GET_PRIVATE_INFORMATION,
                  LSA_POLICY_GET_PRIVATE_INFORMATION },
                { "TRUST_ADMIN",
                  LSA_POLICY_TRUST_ADMIN, LSA_POLICY_TRUST_ADMIN },
                { "CREATE_ACCOUNT",
                  LSA_POLICY_CREATE_ACCOUNT, LSA_POLICY_CREATE_ACCOUNT },
                { "CREATE_SECRET",
                  LSA_POLICY_CREATE_SECRET, LSA_POLICY_CREATE_SECRET },
                { "CREATE_PRIVILEGE",
                  LSA_POLICY_CREATE_PRIVILEGE, LSA_POLICY_CREATE_PRIVILEGE },
                { "SET_DEFAULT_QUOTA_LIMITS",
                  LSA_POLICY_SET_DEFAULT_QUOTA_LIMITS,
                  LSA_POLICY_SET_DEFAULT_QUOTA_LIMITS },
                { "SET_AUDIT_REQUIREMENTS",
                  LSA_POLICY_SET_AUDIT_REQUIREMENTS,
                  LSA_POLICY_SET_AUDIT_REQUIREMENTS },
                { "AUDIT_LOG_ADMIN",
                  LSA_POLICY_AUDIT_LOG_ADMIN, LSA_POLICY_AUDIT_LOG_ADMIN },
                { "SERVER_ADMIN",
                  LSA_POLICY_SERVER_ADMIN, LSA_POLICY_SERVER_ADMIN },
                { "LOOKUP_NAMES",
                  LSA_POLICY_LOOKUP_NAMES, LSA_POLICY_LOOKUP_NAMES },
                { "NOTIFICATION",
                  LSA_POLICY_NOTIFICATION, LSA_POLICY_NOTIFICATION },
                { NULL, 0, 0},
        },
};

/* SID_NAME_USE on translated names/SIDs */
static struct dcerpc_uint32_pretty_printer sid_name_use_pp = {
        .fmt = "%u",
        .bitfields = {
                { "SidTypeUser", 0xffffffff, LSA_SID_TYPE_USER },
                { "SidTypeGroup", 0xffffffff, LSA_SID_TYPE_GROUP },
                { "SidTypeDomain", 0xffffffff, LSA_SID_TYPE_DOMAIN },
                { "SidTypeAlias", 0xffffffff, LSA_SID_TYPE_ALIAS },
                { "SidTypeWellKnownGroup", 0xffffffff,
                  LSA_SID_TYPE_WELL_KNOWN_GROUP },
                { "SidTypeDeletedAccount", 0xffffffff,
                  LSA_SID_TYPE_DELETED_ACCOUNT },
                { "SidTypeInvalid", 0xffffffff, LSA_SID_TYPE_INVALID },
                { "SidTypeUnknown", 0xffffffff, LSA_SID_TYPE_UNKNOWN },
                { "SidTypeComputer", 0xffffffff, LSA_SID_TYPE_COMPUTER },
                { "SidTypeLabel", 0xffffffff, LSA_SID_TYPE_LABEL },
                { "SidTypeLogonSession", 0xffffffff,
                  LSA_SID_TYPE_LOGON_SESSION },
                { NULL, 0, 0},
        },
};

/* LSAP_LOOKUP_LEVEL */
static struct dcerpc_uint32_pretty_printer lookup_level_pp = {
        .fmt = "%u",
        .bitfields = {
                { "LsapLookupWksta", 0xffffffff, LSA_LOOKUP_WKSTA },
                { "LsapLookupPDC", 0xffffffff, LSA_LOOKUP_PDC },
                { "LsapLookupTDL", 0xffffffff, LSA_LOOKUP_TDL },
                { "LsapLookupGC", 0xffffffff, LSA_LOOKUP_GC },
                { "LsapLookupXForestReferral", 0xffffffff,
                  LSA_LOOKUP_XFOREST_REFERRAL },
                { "LsapLookupXForestResolve", 0xffffffff,
                  LSA_LOOKUP_XFOREST_RESOLVE },
                { "LsapLookupRODCReferralToFullDC", 0xffffffff,
                  LSA_LOOKUP_RODC_REFERRAL_TO_FULL_DC },
                { NULL, 0, 0},
        },
};

static int
lsa_PRPC_SID_ptr_coder(char *name, struct dcerpc_context *dce,
                       struct dcerpc_pdu *pdu,
                       struct dcerpc_iovec *iov, int *offset,
                       void *ptr)
{
        return dcerpc_ptr_coder("SID", dce, pdu, iov, offset,
                                ptr,
                                PTR_UNIQUE, dcerpc_sid_coder);
}

static int
lsa_PRPC_SID_array_coder(char *name, struct dcerpc_context *dce,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov, int *offset,
                         void *ptr)
{
        PLSAPR_SID_ENUM_BUFFER seb = ptr;

        return dcerpc_carray_coder("SIDS", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), &seb->SidInfo[0],
                                   sizeof(RPC_SID),
                                   lsa_PRPC_SID_ptr_coder);
}

/*
 * typedef struct _LSAPR_SID_ENUM_BUFFER {
 *      [range(0,20480)] uint32_t Entries;
 *      [size_is(Entries)] PRPC_SID SidInfo;
 * } LSAPR_SID_ENUM_BUFFER, *PLSAPR_SID_ENUM_BUFFER;
 */
static int
_lsa_SID_ENUM_BUFFER_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          void *ptr)
{
        PLSAPR_SID_ENUM_BUFFER seb = ptr;
        uint32_t val;

        val = seb->Entries;
        if (dcerpc_uint32_coder("Entries", dce, pdu, iov, offset, &val)) {
                return -1;
        }
        seb->Entries = val;
        dcerpc_set_size_is(pdu, seb->Entries);

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && seb->Entries) {

                seb->SidInfo = dcerpc_alloc_data(pdu,
                                               (size_t)val * sizeof(RPC_SID));
                if (seb->SidInfo == NULL) {
                        return -1;
                }
        }

        if (dcerpc_ptr_coder("SIDS", dce, pdu, iov, offset, seb,
                             PTR_UNIQUE, lsa_PRPC_SID_array_coder)) {
                return -1;
        }

        return 0;
}

static int
lsa_SID_ENUM_BUFFER_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          void *ptr)
{
        return dcerpc_struct_coder("SIDS", dce, pdu, iov, offset, ptr,
                                   _lsa_SID_ENUM_BUFFER_coder);
}

/*
 * typedef struct _LSAPR_TRANSLATED_NAME_EX {
 *      SID_NAME_USE Use;
 *      RPC_UNICODE_STRING Name;
 *      uint32_t DomainIndex;
 *      uint32_t Flags;
 * } LSAPR_TRANSLATED_NAME_EX, *PLSAPR_TRANSLATED_NAME_EX;
 */
static int
lsa_TRANSLATED_NAME_EX_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct dcerpc_iovec *iov, int *offset,
                             void *ptr)
{
        LSAPR_TRANSLATED_NAME_EX *tn = ptr;

        if (dcerpc_uint32_coder_pp("Use", dce, pdu, iov, offset, &tn->Use,
                                   &sid_name_use_pp)) {
                return -1;
        }
        if (dcerpc_RPC_UNICODE_STRING_coder("Name", dce, pdu, iov, offset,
                                         &tn->Name)) {
                return -1;
        }
        if (dcerpc_uint32_coder("DomainIndex", dce, pdu, iov, offset, &tn->DomainIndex)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Flags", dce, pdu, iov, offset, &tn->Flags)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _LSAPR_TRANSLATED_NAMES_EX {
 *      [range(0,20480)] unsigned long Entries;
 *      [size_is(Entries)] PLSAPR_TRANSLATED_NAME_EX Names;
 * } LSAPR_TRANSLATED_NAMES_EX, *PLSAPR_TRANSLATED_NAMES_EX;
 */
static int
TRANSLATED_NAME_EX_array_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr)
{
        LSAPR_TRANSLATED_NAMES_EX *tn = ptr;

        return dcerpc_carray_coder("TranslatedNameEx", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), &tn->Names[0],
                                   sizeof(LSAPR_TRANSLATED_NAME_EX),
                                   lsa_TRANSLATED_NAME_EX_coder);
}

static int
lsa_TRANSLATED_NAMES_EX_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov, int *offset,
                              void *ptr)
{
        LSAPR_TRANSLATED_NAMES_EX *tn = ptr;
        uint32_t val;

        val = tn->Entries;
        if (dcerpc_uint32_coder("Entries", dce, pdu, iov, offset, &val)) {
                return -1;
        }
        tn->Entries = val;
        dcerpc_set_size_is(pdu, tn->Entries);

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && tn->Entries) {
                tn->Names = dcerpc_alloc_data(pdu,
                                            tn->Entries * sizeof(LSAPR_TRANSLATED_NAME_EX));
                if (tn->Names == NULL) {
                        return -1;
                }
        }

        if (dcerpc_ptr_coder("TranslatedNameEx", dce, pdu, iov, offset, ptr,
                             PTR_UNIQUE, TRANSLATED_NAME_EX_array_coder)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _LSAPR_OBJECT_ATTRIBUTES {
 *      unsigned long Length = 0;
 *      unsigned char *RootDirectory = NULL;
 *      PSTRING ObjectName = NULL;
 *      unsigned long Attributes = 0;
 *      PLSAPR_SECURITY_DESCRIPTOR SecurityDescriptor = NULL;
 *      PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService = NULL;
 * } LSAPR_OBJECT_ATTRIBUTES, *PLSAPR_OBJECT_ATTRIBUTES;
 *
 * For OpenPolicy2, RootDirectory MUST be NULL and everything else is
 * ignored. Encode a fixed empty object on the wire.
 */
static int
lsa_ObjectAttributes_coder(char *name, struct dcerpc_context *dce,
                           struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov, int *offset,
                           void *ptr)
{
        uint32_t len = 24;
        uint32_t attr = 0;

        if (dcerpc_uint32_coder("Length", dce, pdu, iov, offset, &len)) {
                return -1;
        }
        /* Always NULL for OpenPolicy2 */
        if (dcerpc_ptr_coder("RootDirectory", dce, pdu, iov, offset, NULL,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ObjectName", dce, pdu, iov, offset, NULL,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Attributes", dce, pdu, iov, offset, &attr)) {
                return -1;
        }
        if (dcerpc_ptr_coder("SecurityDescriptor", dce, pdu, iov, offset, NULL,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("SecurityQualityOfService", dce, pdu, iov, offset, NULL,
                             PTR_UNIQUE, dcerpc_uint32_coder)) {
                return -1;
        }

        return 0;
}

static int
lsa_ObjectAttributes_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct dcerpc_iovec *iov, int *offset,
                                  void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   lsa_ObjectAttributes_coder);
}

static int
lsa_PolicyHandle_STRUCT_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov, int *offset,
                              void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   dcerpc_context_handle_coder);
}

/**********************
 * Function: 0x00
 *	NTSTATUS LsarClose (
 *		[in,out] dcerpc_context_handle PolicyHandle
 *		);
 **********************/
int
lsa_Close_req_coder(char *name, struct dcerpc_context *dce,
                    struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, int *offset,
                    void *ptr)
{
        struct lsa_close_req *req = ptr;

        if (dcerpc_ptr_coder("PolicyHandle", dce, pdu, iov, offset, &req->PolicyHandle,
                             PTR_REF, lsa_PolicyHandle_STRUCT_coder)) {
                return -1;
        }

        return 0;
}

int
lsa_Close_rep_coder(char *name, struct dcerpc_context *dce,
                    struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, int *offset,
                    void *ptr)
{
        struct lsa_close_rep *rep = ptr;

        if (dcerpc_ptr_coder("PolicyHandle", dce, pdu, iov, offset, &rep->PolicyHandle,
                             PTR_REF, lsa_PolicyHandle_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/**********************
 * Function:     0x2c
 *      NTSTATUS LsarOpenPolicy2(
 *              [in,unique,string] wchar_t* SystemName,
 *              [in] PLSAPR_OBJECT_ATTRIBUTES ObjectAttributes,
 *              [in] uint32_t DesiredAccess,
 *		[out] dcerpc_context_handle PolicyHandle
 *              );
 **********************/
int
lsa_OpenPolicy2_req_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          void *ptr)
{
        struct lsa_openpolicy2_req *req = ptr;

        if (dcerpc_ptr_coder("SystemName", dce, pdu, iov, offset, &req->SystemName,
                             PTR_UNIQUE, dcerpc_utf16z_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("ObjectAttributes", dce, pdu, iov, offset, &req->ObjectAttributes,
                             PTR_REF, lsa_ObjectAttributes_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder_pp("DesiredAccess", dce, pdu, iov, offset,
                                   &req->DesiredAccess, &policy_access_pp)) {
                return -1;
        }
        return 0;
}

int
lsa_OpenPolicy2_rep_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          void *ptr)
{
        struct lsa_openpolicy2_rep *rep = ptr;

        if (dcerpc_ptr_coder("PolicyHandle", dce, pdu, iov, offset, &rep->PolicyHandle,
                             PTR_REF, lsa_PolicyHandle_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _LSAPR_TRUST_INFORMATION {
 *       RPC_UNICODE_STRING Name;
 *       PRPC_SID Sid;
 * } LSAPR_TRUST_INFORMATION, *PLSAPR_TRUST_INFORMATION;
*/
static int
lsa_TRUST_INFORMATION_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct dcerpc_iovec *iov, int *offset,
                            void *ptr)
{
        LSAPR_TRUST_INFORMATION *ti = ptr;

        if (dcerpc_RPC_UNICODE_STRING_coder("Name", dce, pdu, iov, offset,
                                          &ti->Name)) {
                return -1;
        }
        if (dcerpc_ptr_coder("SID", dce, pdu, iov, offset, &ti->Sid,
                             PTR_UNIQUE, dcerpc_sid_coder)) {
                return -1;
        }

        return 0;
}

static int
RDL_DOMAINS_array_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        void *ptr)
{
        LSAPR_REFERENCED_DOMAIN_LIST *rdl = ptr;

        return dcerpc_carray_coder("Domain", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), &rdl->Domains[0],
                                   sizeof(LSAPR_TRUST_INFORMATION),
                                   lsa_TRUST_INFORMATION_coder);
}


/*
 * typedef struct _LSAPR_REFERENCED_DOMAIN_LIST {
 *      uint32_t Entries;
 *      LSAPR_TRUST_INFORMATION *Domains;
 *      uint32_t MaxEntries;  must be ignored
 * } LSAPR_REFERENCED_DOMAIN_LIST, *PLSAPR_REFERENCED_DOMAIN_LIST;
 */
static int
lsa_REFERENCED_DOMAIN_LIST_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct dcerpc_iovec *iov, int *offset,
                                 void *ptr)
{
        LSAPR_REFERENCED_DOMAIN_LIST *rdl = ptr;
        uint32_t val;

        val = rdl->Entries;
        if (dcerpc_uint32_coder("Entries", dce, pdu, iov, offset, &val)) {
                return -1;
        }
        rdl->Entries = val;
        dcerpc_set_size_is(pdu, rdl->Entries);

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && rdl->Entries) {
                rdl->Domains = dcerpc_alloc_data(pdu,
                                               rdl->Entries * sizeof(LSAPR_TRUST_INFORMATION));
                if (rdl->Domains == NULL) {
                        return -1;
                }
        }

        if (dcerpc_ptr_coder("RDLDomains", dce, pdu, iov, offset, ptr,
                             PTR_UNIQUE, RDL_DOMAINS_array_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MaxEntries", dce, pdu, iov, offset, &rdl->MaxEntries)) {
                return -1;
        }

        return 0;
}

/**********************
 * Function:     0x39
 * NTSTATUS LsarLookupSids2(
 *       [in] dcerpc_context_handle PolicyHandle,
 *       [in] PLSAPR_SID_ENUM_BUFFER SidEnumBuffer,
 *       [out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
 *       [in, out] PLSAPR_TRANSLATED_NAMES_EX TranslatedNames,
 *       [in] LSAP_LOOKUP_LEVEL LookupLevel,
 *       [in, out] unsigned long* MappedCount,
 *       [in] unsigned long LookupOptions, (SHOULD BE 0)
 *       [in] unsigned long ClientRevision
 *       );
 *******************/
int
lsa_LookupSids2_req_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          void *ptr)
{
        struct lsa_lookupsids2_req *req = (struct lsa_lookupsids2_req*) ptr;
        uint32_t val;

        if (dcerpc_ptr_coder("PolicyHandle", dce, pdu, iov, offset, &req->PolicyHandle,
                             PTR_REF, dcerpc_context_handle_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("SidEnumBuffer", dce, pdu, iov, offset, &req->SidEnumBuffer,
                             PTR_REF, lsa_SID_ENUM_BUFFER_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TranslatedNames", dce, pdu, iov, offset, &req->TranslatedNames,
                             PTR_REF, lsa_TRANSLATED_NAMES_EX_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder_pp("LookupLevel", dce, pdu, iov, offset,
                                   &req->LookupLevel, &lookup_level_pp)) {
                return -1;
        }

        val = 0;
        if (dcerpc_uint32_coder("MappedCount", dce, pdu, iov, offset, &val)) {
                return -1;
        }
        if (dcerpc_uint32_coder("LookupOptions", dce, pdu, iov, offset, &val)) {
                return -1;
        }
        val = 2;
        if (dcerpc_uint32_coder("ClientRevision", dce, pdu, iov, offset, &val)) {
                return -1;
        }

        return 0;
}

int
lsa_LookupSids2_rep_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          void *ptr)
{
        struct lsa_lookupsids2_rep *rep = ptr;

        if (dcerpc_ptr_coder("ReferencedDomainList", dce, pdu, iov, offset, &rep->ReferencedDomains,
                             PTR_UNIQUE, lsa_REFERENCED_DOMAIN_LIST_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TranslatedNames", dce, pdu, iov, offset, &rep->TranslatedNames,
                             PTR_REF, lsa_TRANSLATED_NAMES_EX_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MappedCount", dce, pdu, iov, offset, &rep->MappedCount)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

/*
 * typedef struct _LSAPR_TRANSLATED_SID_EX {
 *   SID_NAME_USE Use;
 *   unsigned long RelativeId;
 *   long DomainIndex;
 *   unsigned long Flags;
 * } LSAPR_TRANSLATED_SID_EX;
 */
static int
lsa_TRANSLATED_SID_EX_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct dcerpc_iovec *iov, int *offset,
                            void *ptr)
{
        LSAPR_TRANSLATED_SID_EX *ts = ptr;

        if (dcerpc_uint32_coder_pp("Use", dce, pdu, iov, offset, &ts->Use,
                                   &sid_name_use_pp)) {
                return -1;
        }
        if (dcerpc_uint32_coder("RelativeId", dce, pdu, iov, offset, &ts->RelativeId)) {
                return -1;
        }
        if (dcerpc_uint32_coder("DomainIndex", dce, pdu, iov, offset, &ts->DomainIndex)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Flags", dce, pdu, iov, offset, &ts->Flags)) {
                return -1;
        }

        return 0;
}

static int
TRANSLATED_SID_EX_array_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov, int *offset,
                              void *ptr)
{
        LSAPR_TRANSLATED_SIDS_EX *ts = ptr;

        return dcerpc_carray_coder("TranslatedSidEx", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), &ts->Sids[0],
                                   sizeof(LSAPR_TRANSLATED_SID_EX),
                                   lsa_TRANSLATED_SID_EX_coder);
}

/*
 * typedef struct _LSAPR_TRANSLATED_SIDS_EX {
 *   [range(0,1000)] unsigned long Entries;
 *   [size_is(Entries)] PLSAPR_TRANSLATED_SID_EX Sids;
 * } LSAPR_TRANSLATED_SIDS_EX;
 */
static int
lsa_TRANSLATED_SIDS_EX_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct dcerpc_iovec *iov, int *offset,
                             void *ptr)
{
        LSAPR_TRANSLATED_SIDS_EX *ts = ptr;
        uint32_t val;

        val = ts->Entries;
        if (dcerpc_uint32_coder("Entries", dce, pdu, iov, offset, &val)) {
                return -1;
        }
        ts->Entries = val;
        dcerpc_set_size_is(pdu, ts->Entries);

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && ts->Entries) {
                ts->Sids = dcerpc_alloc_data(pdu,
                                           ts->Entries * sizeof(LSAPR_TRANSLATED_SID_EX));
                if (ts->Sids == NULL) {
                        return -1;
                }
        }

        /* Field name matches carray name (same pattern as TranslatedNameEx). */
        if (dcerpc_ptr_coder("TranslatedSidEx", dce, pdu, iov, offset, ptr,
                             PTR_UNIQUE, TRANSLATED_SID_EX_array_coder)) {
                return -1;
        }

        return 0;
}

/*
 * Array element: RPC_UNICODE_STRING viewed as char *.
 * ptr is &Names[i] (char **).
 */
static int
lsa_NAME_STRING_coder(char *name, struct dcerpc_context *dce,
                      struct dcerpc_pdu *pdu,
                      struct dcerpc_iovec *iov, int *offset,
                      void *ptr)
{
        return dcerpc_RPC_UNICODE_STRING_coder("Name", dce, pdu, iov, offset, ptr);
}

/*
 * Top-level [size_is(Count)] array of RPC_UNICODE_STRING.
 * Encoded via PTR_REF so unique string buffers are deferred correctly
 * (top_level forced to 0 for the array body, then pointees flushed).
 */
static int
lsa_NAMES_array_coder(char *name, struct dcerpc_context *dce,
                      struct dcerpc_pdu *pdu,
                      struct dcerpc_iovec *iov, int *offset,
                      void *ptr)
{
        return dcerpc_carray_coder("Names", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(char *),
                                   lsa_NAME_STRING_coder);
}

/**********************
 * Function:     0x3a
 * NTSTATUS LsarLookupNames2(
 *       [in] dcerpc_context_handle PolicyHandle,
 *       [in, range(0,1000)] unsigned long Count,
 *       [in, size_is(Count)] PRPC_UNICODE_STRING Names,
 *       [out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
 *       [in, out] PLSAPR_TRANSLATED_SIDS_EX TranslatedSids,
 *       [in] LSAP_LOOKUP_LEVEL LookupLevel,
 *       [in, out] unsigned long* MappedCount,
 *       [in] unsigned long LookupOptions,
 *       [in] unsigned long ClientRevision
 *       );
 *******************/
int
lsa_LookupNames2_req_coder(char *name, struct dcerpc_context *dce,
                           struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov, int *offset,
                           void *ptr)
{
        struct lsa_lookupnames2_req *req = (struct lsa_lookupnames2_req *)ptr;
        uint32_t val;
        void *names_ptr;

        if (dcerpc_ptr_coder("PolicyHandle", dce, pdu, iov, offset, &req->PolicyHandle,
                             PTR_REF, dcerpc_context_handle_coder)) {
                return -1;
        }

        val = req->Count;
        if (dcerpc_uint32_coder("Count", dce, pdu, iov, offset, &val)) {
                return -1;
        }
        req->Count = val;
        dcerpc_set_size_is(pdu, req->Count);

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && req->Count) {
                if (req->Names == NULL) {
                        req->Names = dcerpc_alloc_data(pdu,
                                (size_t)req->Count * sizeof(char *));
                        if (req->Names == NULL) {
                                return -1;
                        }
                }
        }

        /*
         * Top-level conformant array: use PTR_REF so pointees are deferred
         * after the array fixed part (same as other top-level [in] arrays).
         * When Count is 0, pass a non-NULL dummy base; carray does not
         * dereference elements when size_is is 0.
         */
        names_ptr = req->Names;
        if (names_ptr == NULL) {
                names_ptr = &req->Names;
        }
        if (dcerpc_ptr_coder("Names", dce, pdu, iov, offset, names_ptr,
                             PTR_REF, lsa_NAMES_array_coder)) {
                return -1;
        }

        if (dcerpc_ptr_coder("TranslatedSids", dce, pdu, iov, offset, &req->TranslatedSids,
                             PTR_REF, lsa_TRANSLATED_SIDS_EX_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder_pp("LookupLevel", dce, pdu, iov, offset,
                                   &req->LookupLevel, &lookup_level_pp)) {
                return -1;
        }

        val = 0;
        if (dcerpc_uint32_coder("MappedCount", dce, pdu, iov, offset, &val)) {
                return -1;
        }
        if (dcerpc_uint32_coder("LookupOptions", dce, pdu, iov, offset, &val)) {
                return -1;
        }
        val = 2;
        if (dcerpc_uint32_coder("ClientRevision", dce, pdu, iov, offset, &val)) {
                return -1;
        }

        return 0;
}

int
lsa_LookupNames2_rep_coder(char *name, struct dcerpc_context *dce,
                           struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov, int *offset,
                           void *ptr)
{
        struct lsa_lookupnames2_rep *rep = ptr;

        if (dcerpc_ptr_coder("ReferencedDomainList", dce, pdu, iov, offset, &rep->ReferencedDomains,
                             PTR_UNIQUE, lsa_REFERENCED_DOMAIN_LIST_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("TranslatedSids", dce, pdu, iov, offset, &rep->TranslatedSids,
                             PTR_REF, lsa_TRANSLATED_SIDS_EX_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MappedCount", dce, pdu, iov, offset, &rep->MappedCount)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }

        return 0;
}

struct dcerpc_procedure lsa_procs[] = {
        {LSA_CLOSE, "Close",
         lsa_Close_req_coder, sizeof(struct lsa_close_req),
         lsa_Close_rep_coder, sizeof(struct lsa_close_rep),
        },
        {LSA_OPENPOLICY2, "OpenPolicy2",
         lsa_OpenPolicy2_req_coder, sizeof(struct lsa_openpolicy2_req),
         lsa_OpenPolicy2_rep_coder, sizeof(struct lsa_openpolicy2_rep),
        },
        {LSA_LOOKUPSIDS2, "LookupSids2",
         lsa_LookupSids2_req_coder, sizeof(struct lsa_lookupsids2_req),
         lsa_LookupSids2_rep_coder, sizeof(struct lsa_lookupsids2_rep),
        },
        {LSA_LOOKUPNAMES2, "LookupNames2",
         lsa_LookupNames2_req_coder, sizeof(struct lsa_lookupnames2_req),
         lsa_LookupNames2_rep_coder, sizeof(struct lsa_lookupnames2_rep),
        },
        {-1, NULL, NULL, 0, NULL, 0}
};
