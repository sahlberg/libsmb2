/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2020 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _DCERPC_LSA_H_
#define _DCERPC_LSA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>

#define LSA_CLOSE          0x00
#define LSA_OPENPOLICY2    0x2c
#define LSA_LOOKUPSIDS2    0x39
#define LSA_LOOKUPNAMES2   0x3a

/* Access Mask. LSA policy-specific flags (MS-LSAD). */
#define LSA_POLICY_VIEW_LOCAL_INFORMATION    0x00000001
#define LSA_POLICY_VIEW_AUDIT_INFORMATION    0x00000002
#define LSA_POLICY_GET_PRIVATE_INFORMATION   0x00000004
#define LSA_POLICY_TRUST_ADMIN               0x00000008
#define LSA_POLICY_CREATE_ACCOUNT            0x00000010
#define LSA_POLICY_CREATE_SECRET             0x00000020
#define LSA_POLICY_CREATE_PRIVILEGE          0x00000040
#define LSA_POLICY_SET_DEFAULT_QUOTA_LIMITS  0x00000080
#define LSA_POLICY_SET_AUDIT_REQUIREMENTS    0x00000100
#define LSA_POLICY_AUDIT_LOG_ADMIN           0x00000200
#define LSA_POLICY_SERVER_ADMIN              0x00000400
#define LSA_POLICY_LOOKUP_NAMES              0x00000800
#define LSA_POLICY_NOTIFICATION              0x00001000

/* SID_NAME_USE (translated name/sid Use field) */
#define LSA_SID_TYPE_USER             1
#define LSA_SID_TYPE_GROUP            2
#define LSA_SID_TYPE_DOMAIN           3
#define LSA_SID_TYPE_ALIAS            4
#define LSA_SID_TYPE_WELL_KNOWN_GROUP 5
#define LSA_SID_TYPE_DELETED_ACCOUNT  6
#define LSA_SID_TYPE_INVALID          7
#define LSA_SID_TYPE_UNKNOWN          8
#define LSA_SID_TYPE_COMPUTER         9
#define LSA_SID_TYPE_LABEL            10
#define LSA_SID_TYPE_LOGON_SESSION    11

/* LSAP_LOOKUP_LEVEL */
#define LSA_LOOKUP_WKSTA                   1
#define LSA_LOOKUP_PDC                     2
#define LSA_LOOKUP_TDL                     3
#define LSA_LOOKUP_GC                      4
#define LSA_LOOKUP_XFOREST_REFERRAL        5
#define LSA_LOOKUP_XFOREST_RESOLVE         6
#define LSA_LOOKUP_RODC_REFERRAL_TO_FULL_DC 7

typedef struct _SID_ENUM_BUFFER {
        uint32_t Entries;
        RPC_SID *SidInfo;
} LSAPR_SID_ENUM_BUFFER, *PLSAPR_SID_ENUM_BUFFER;

        
typedef struct _LSAPR_TRANSLATED_NAME_EX {
        uint32_t Use;
        char *Name;
        uint32_t DomainIndex;
        uint32_t Flags;
} LSAPR_TRANSLATED_NAME_EX, *PLSAPR_TRANSLATED_NAME_EX;

typedef struct _LSAPR_TRANSLATED_NAMES_EX {
        uint32_t Entries;
        LSAPR_TRANSLATED_NAME_EX  *Names;
} LSAPR_TRANSLATED_NAMES_EX, *PLSAPR_TRANSLATED_NAMES_EX;

typedef enum _LSAP_LOOKUP_LEVEL {
        LsapLookupWksta = LSA_LOOKUP_WKSTA,
        LsapLookupPDC = LSA_LOOKUP_PDC,
        LsapLookupTDL = LSA_LOOKUP_TDL,
        LsapLookupGC = LSA_LOOKUP_GC,
        LsapLookupXForestReferral = LSA_LOOKUP_XFOREST_REFERRAL,
        LsapLookupXForestResolve = LSA_LOOKUP_XFOREST_RESOLVE,
        LsapLookupRODCReferralToFullDC = LSA_LOOKUP_RODC_REFERRAL_TO_FULL_DC
} LSAP_LOOKUP_LEVEL, *PLSAP_LOOKUP_LEVEL;

typedef struct _LSAPR_TRUST_INFORMATION {
        char *Name;
        RPC_SID Sid;
} LSAPR_TRUST_INFORMATION, *PLSAPR_TRUST_INFORMATION;

typedef struct _LSAPR_REFERENCED_DOMAIN_LIST {
        uint32_t Entries;
        LSAPR_TRUST_INFORMATION *Domains;
        uint32_t MaxEntries; /* must be ignored */
} LSAPR_REFERENCED_DOMAIN_LIST, *PLSAPR_REFERENCED_DOMAIN_LIST;

/* For OPENPOLICY2: RootDirectory MUST be zero. Everything else is ignored. */
typedef struct _LSAPR_OBJECT_ATTRIBUTES {
        uint32_t Length;
        unsigned char *RootDirectory;
        void *ObjectName;
        uint32_t Attributes;
        void *SecurityDescriptor;
        void *SecurityQualityOfService;
} LSAPR_OBJECT_ATTRIBUTES, *PLSAPR_OBJECT_ATTRIBUTES;

struct lsa_close_req {
        struct dcerpc_context_handle PolicyHandle;
};

struct lsa_close_rep {
        uint32_t status;

        struct dcerpc_context_handle PolicyHandle;
};

struct lsa_openpolicy2_req {
        char *SystemName;
        LSAPR_OBJECT_ATTRIBUTES ObjectAttributes;
        uint32_t DesiredAccess;
};

struct lsa_openpolicy2_rep {
        uint32_t status;

        struct dcerpc_context_handle PolicyHandle;
};

struct lsa_lookupsids2_req {
        struct dcerpc_context_handle PolicyHandle;
        LSAPR_SID_ENUM_BUFFER SidEnumBuffer;
        LSAPR_TRANSLATED_NAMES_EX TranslatedNames;
        uint32_t LookupLevel;
};

struct lsa_lookupsids2_rep {
        uint32_t status;

        LSAPR_REFERENCED_DOMAIN_LIST ReferencedDomains;
        LSAPR_TRANSLATED_NAMES_EX TranslatedNames;
        uint32_t MappedCount;
};

/*
 * typedef struct _LSAPR_TRANSLATED_SID_EX {
 *   SID_NAME_USE Use;
 *   unsigned long RelativeId;
 *   long DomainIndex;
 *   unsigned long Flags;
 * } LSAPR_TRANSLATED_SID_EX;
 */
typedef struct _LSAPR_TRANSLATED_SID_EX {
        uint32_t Use;
        uint32_t RelativeId;
        uint32_t DomainIndex;
        uint32_t Flags;
} LSAPR_TRANSLATED_SID_EX, *PLSAPR_TRANSLATED_SID_EX;

/*
 * typedef struct _LSAPR_TRANSLATED_SIDS_EX {
 *   [range(0,1000)] unsigned long Entries;
 *   [size_is(Entries)] PLSAPR_TRANSLATED_SID_EX Sids;
 * } LSAPR_TRANSLATED_SIDS_EX;
 */
typedef struct _LSAPR_TRANSLATED_SIDS_EX {
        uint32_t Entries;
        LSAPR_TRANSLATED_SID_EX *Sids;
} LSAPR_TRANSLATED_SIDS_EX, *PLSAPR_TRANSLATED_SIDS_EX;

/*
 * NTSTATUS LsarLookupNames2(
 *   [in] LSAPR_HANDLE PolicyHandle,
 *   [in, range(0,1000)] unsigned long Count,
 *   [in, size_is(Count)] PRPC_UNICODE_STRING Names,
 *   [out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
 *   [in, out] PLSAPR_TRANSLATED_SIDS_EX TranslatedSids,
 *   [in] LSAP_LOOKUP_LEVEL LookupLevel,
 *   [in, out] unsigned long* MappedCount,
 *   [in] unsigned long LookupOptions,
 *   [in] unsigned long ClientRevision
 * );
 */
struct lsa_lookupnames2_req {
        struct dcerpc_context_handle PolicyHandle;
        uint32_t Count;
        char **Names;
        LSAPR_TRANSLATED_SIDS_EX TranslatedSids;
        uint32_t LookupLevel;
};

struct lsa_lookupnames2_rep {
        uint32_t status;

        LSAPR_REFERENCED_DOMAIN_LIST ReferencedDomains;
        LSAPR_TRANSLATED_SIDS_EX TranslatedSids;
        uint32_t MappedCount;
};

int lsa_Close_rep_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        void *ptr);
int lsa_Close_req_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        void *ptr);
int lsa_LookupSids2_rep_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov, int *offset,
                              void *ptr);
int lsa_LookupSids2_req_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov, int *offset,
                              void *ptr);
int lsa_LookupNames2_rep_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr);
int lsa_LookupNames2_req_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr);
int lsa_OpenPolicy2_rep_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov, int *offset,
                              void *ptr);
int lsa_OpenPolicy2_req_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov, int *offset,
                              void *ptr);

extern struct dcerpc_procedure lsa_procs[];

#ifdef __cplusplus
}
#endif

#endif /* !_DCERPC_LSA_H_ */
