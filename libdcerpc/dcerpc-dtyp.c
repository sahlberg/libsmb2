/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2020 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 * MS-DTYP common data types used across DCE/RPC interfaces.
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

#include <errno.h>
#include <stdio.h>

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

unsigned char NT_SID_AUTHORITY[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

/*
 * typedef struct _RPC_SID {
 *      unsigned char Revision;
 *      unsigned char SubAuthorityCount;
 *      byte IdentifierAuthority[6];
 *      [size_is(SubAuthorityCount)] uint32_t SubAuthority[];
 * } RPC_SID, *PRPC_SID, *PSID;
 */
static int
ndr_sid_coder(char *name, struct dcerpc_context *dce,
              struct dcerpc_pdu *pdu,
              struct dcerpc_iovec *iov, int *offset,
              void *ptr)
{
        RPC_SID *sid = ptr;
        uint64_t count;
        int i;

        count = sid->SubAuthorityCount;
        if (ndr_uint3264_coder("", dce, pdu, iov, offset, &count)) {
                return -1;
        }

        if (ndr_uint8_coder("Revision", dce, pdu, iov, offset, &sid->Revision)) {
                return -1;
        }
        if (ndr_uint8_coder("SubAuthorityCount", dce, pdu, iov, offset, &sid->SubAuthorityCount)) {
                return -1;
        }
        for (i = 0; i < 6; i++) {
                if (ndr_uint8_coder("IdentifierAuthority", dce, pdu, iov, offset, &sid->IdentifierAuthority[i])) {
                        return -1;
                }
        }
        for (i = 0; i < count; i++) {
                if (ndr_uint32_coder("Subauthority", dce, pdu, iov, offset, &sid->SubAuthority[i])) {
                        return -1;
                }
        }

        return 0;
}

/*
 * YAML representation of an RPC_SID is the standard SID string form:
 *   S-<revision>-<identifier-authority>-<subauth0>-<subauth1>-...
 * e.g. S-1-5-32-544
 *
 * Identifier authority is a big-endian 48-bit value. If it fits in 32 bits
 * it is written in decimal; otherwise as a 0x-prefixed hex value (Windows
 * ConvertSidToStringSid rules).
 */
static int
yaml_sid_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
               struct dcerpc_iovec *iov, int *offset, void *ptr)
{
        RPC_SID *sid = ptr;
        int i;

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                const char *p;
                char *end;
                unsigned long rev;
                unsigned long long ia;
                uint32_t sub[15];
                int count = 0;

                yaml_next_kv(pdu, iov, offset);
                if (strcmp(dcerpc_pdu_yaml_key(pdu), name)) {
                        printf("Wrong YAML key encountered for sid. Expected %s but got %s\n",
                               name, dcerpc_pdu_yaml_key(pdu));
                        return -1;
                }
                dcerpc_pdu_clear_yaml_key(pdu);

                p = dcerpc_pdu_yaml_val(pdu);
                if (p == NULL || (p[0] != 'S' && p[0] != 's') || p[1] != '-') {
                        printf("Failed to parse SID value for %s: %s\n",
                               name, dcerpc_pdu_yaml_val(pdu) ?
                               dcerpc_pdu_yaml_val(pdu) : "(null)");
                        return -1;
                }
                p += 2;

                rev = strtoul(p, &end, 10);
                if (end == p || *end != '-' || rev > 255) {
                        printf("Failed to parse SID revision for %s: %s\n",
                               name, dcerpc_pdu_yaml_val(pdu));
                        return -1;
                }
                p = end + 1;

                if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
                        ia = strtoull(p, &end, 16);
                } else {
                        ia = strtoull(p, &end, 10);
                }
                if (end == p) {
                        printf("Failed to parse SID authority for %s: %s\n",
                               name, dcerpc_pdu_yaml_val(pdu));
                        return -1;
                }
                p = end;

                while (*p == '-') {
                        unsigned long sa;

                        p++;
                        if (count >= 15) {
                                printf("Too many SID subauthorities for %s: %s\n",
                                       name, dcerpc_pdu_yaml_val(pdu));
                                return -1;
                        }
                        sa = strtoul(p, &end, 10);
                        if (end == p) {
                                printf("Failed to parse SID subauthority for %s: %s\n",
                                       name, dcerpc_pdu_yaml_val(pdu));
                                return -1;
                        }
                        sub[count++] = (uint32_t)sa;
                        p = end;
                }
                if (*p != '\0') {
                        printf("Failed to parse SID value for %s: %s\n",
                               name, dcerpc_pdu_yaml_val(pdu));
                        return -1;
                }

                sid->Revision = (uint8_t)rev;
                sid->SubAuthorityCount = (uint8_t)count;
                for (i = 0; i < 6; i++) {
                        sid->IdentifierAuthority[i] =
                                (uint8_t)((ia >> (8 * (5 - i))) & 0xff);
                }
                for (i = 0; i < count; i++) {
                        sid->SubAuthority[i] = sub[i];
                }

                yaml_next_kv(pdu, iov, offset);
                return 0;
        } else {
                uint64_t ia = 0;
                char sidstr[256];
                int len;

                for (i = 0; i < 6; i++) {
                        ia = (ia << 8) | sid->IdentifierAuthority[i];
                }

                if (ia <= 0xffffffffULL) {
                        len = snprintf(sidstr, sizeof(sidstr),
                                       "S-%u-%llu",
                                       sid->Revision,
                                       (unsigned long long)ia);
                } else {
                        len = snprintf(sidstr, sizeof(sidstr),
                                       "S-%u-0x%llx",
                                       sid->Revision,
                                       (unsigned long long)ia);
                }
                if (len < 0 || (size_t)len >= sizeof(sidstr)) {
                        printf("Failed to format SID for %s\n", name);
                        return -1;
                }
                for (i = 0; i < sid->SubAuthorityCount; i++) {
                        int n;

                        n = snprintf(sidstr + len, sizeof(sidstr) - (size_t)len,
                                     "-%u", sid->SubAuthority[i]);
                        if (n < 0 ||
                            (size_t)len + (size_t)n >= sizeof(sidstr)) {
                                printf("Failed to format SID for %s\n", name);
                                return -1;
                        }
                        len += n;
                }

                yaml_print_preamble(dce, pdu, iov, offset);
                if (*offset + 256 < iov->len) {
                        *offset += snprintf((char *)&iov->buf[*offset],
                                           iov->len - *offset,
                                           "%s: %s\n", name, sidstr);
                }
                return 0;
        }
}

/*
 * JSON representation of an RPC_SID is the standard SID string form,
 * same as YAML: S-<revision>-<authority>-<subauth>...
 */
static int
json_sid_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
               struct dcerpc_iovec *iov, int *offset, void *ptr)
{
        RPC_SID *sid = ptr;
        int i;

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                const char *p;
                char *end;
                char *val;
                unsigned long rev;
                unsigned long long ia;
                uint32_t sub[15];
                int count = 0;

                if (json_expect_key(pdu, iov, offset, name) < 0) {
                        return -1;
                }
                if (json_parse_string(iov, offset, &val) < 0) {
                        return -1;
                }

                p = val;
                if (p == NULL || (p[0] != 'S' && p[0] != 's') || p[1] != '-') {
                        printf("Failed to parse SID value for %s: %s\n",
                               name, val ? val : "(null)");
                        return -1;
                }
                p += 2;

                rev = strtoul(p, &end, 10);
                if (end == p || *end != '-' || rev > 255) {
                        printf("Failed to parse SID revision for %s: %s\n",
                               name, val);
                        return -1;
                }
                p = end + 1;

                if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
                        ia = strtoull(p, &end, 16);
                } else {
                        ia = strtoull(p, &end, 10);
                }
                if (end == p) {
                        printf("Failed to parse SID authority for %s: %s\n",
                               name, val);
                        return -1;
                }
                p = end;

                while (*p == '-') {
                        unsigned long sa;

                        p++;
                        if (count >= 15) {
                                printf("Too many SID subauthorities for %s: %s\n",
                                       name, val);
                                return -1;
                        }
                        sa = strtoul(p, &end, 10);
                        if (end == p) {
                                printf("Failed to parse SID subauthority for %s: %s\n",
                                       name, val);
                                return -1;
                        }
                        sub[count++] = (uint32_t)sa;
                        p = end;
                }
                if (*p != '\0') {
                        printf("Failed to parse SID value for %s: %s\n",
                               name, val);
                        return -1;
                }

                sid->Revision = (uint8_t)rev;
                sid->SubAuthorityCount = (uint8_t)count;
                for (i = 0; i < 6; i++) {
                        sid->IdentifierAuthority[i] =
                                (uint8_t)((ia >> (8 * (5 - i))) & 0xff);
                }
                for (i = 0; i < count; i++) {
                        sid->SubAuthority[i] = sub[i];
                }
                return 0;
        } else {
                uint64_t ia = 0;
                char sidstr[256];
                int len;

                for (i = 0; i < 6; i++) {
                        ia = (ia << 8) | sid->IdentifierAuthority[i];
                }

                if (ia <= 0xffffffffULL) {
                        len = snprintf(sidstr, sizeof(sidstr),
                                       "S-%u-%llu",
                                       sid->Revision,
                                       (unsigned long long)ia);
                } else {
                        len = snprintf(sidstr, sizeof(sidstr),
                                       "S-%u-0x%llx",
                                       sid->Revision,
                                       (unsigned long long)ia);
                }
                if (len < 0 || (size_t)len >= sizeof(sidstr)) {
                        printf("Failed to format SID for %s\n", name);
                        return -1;
                }
                for (i = 0; i < sid->SubAuthorityCount; i++) {
                        int n;

                        n = snprintf(sidstr + len, sizeof(sidstr) - (size_t)len,
                                     "-%u", sid->SubAuthority[i]);
                        if (n < 0 ||
                            (size_t)len + (size_t)n >= sizeof(sidstr)) {
                                printf("Failed to format SID for %s\n", name);
                                return -1;
                        }
                        len += n;
                }

                json_sep(pdu, iov, offset);
                if (json_append_quoted(iov, offset, name) < 0) {
                        return -1;
                }
                if (json_append(iov, offset, ": ") < 0) {
                        return -1;
                }
                if (json_append_quoted(iov, offset, sidstr) < 0) {
                        return -1;
                }
                return 0;
        }
}

int
dcerpc_sid_coder(char *name, struct dcerpc_context *dce,
                 struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, int *offset,
                 void *ptr)
{
        switch (dcerpc_pdu_encoding(pdu)) {
        case ENCODING_NDR:
                if (ndr_sid_coder(name, dce, pdu, iov, offset, ptr)) {
                        return -1;
                }
                return 0;
        case ENCODING_YAML:
                if (yaml_sid_coder(name, dce, pdu, iov, offset, ptr)) {
                        return -1;
                }
                return 0;
        case ENCODING_JSON:
                if (json_sid_coder(name, dce, pdu, iov, offset, ptr)) {
                        return -1;
                }
                return 0;
        }
        return 0;
}

/*
 * MS-DTYP 2.4.4.1 ACE_HEADER
 *
 * typedef struct _ACE_HEADER {
 *     UCHAR AceType;
 *     UCHAR AceFlags;
 *     USHORT AceSize;
 * } ACE_HEADER, *PACE_HEADER;
 */

/* AceType is an exclusive enum (mask 0xffffffff matches a single value). */
static struct dcerpc_uint32_pretty_printer ace_type_pp = {
        .fmt = "0x%02x",
        .bitfields = {
                { "ACCESS_ALLOWED_ACE_TYPE", 0xffffffff,
                  ACCESS_ALLOWED_ACE_TYPE },
                { "ACCESS_DENIED_ACE_TYPE", 0xffffffff,
                  ACCESS_DENIED_ACE_TYPE },
                { "SYSTEM_AUDIT_ACE_TYPE", 0xffffffff,
                  SYSTEM_AUDIT_ACE_TYPE },
                { "SYSTEM_ALARM_ACE_TYPE", 0xffffffff,
                  SYSTEM_ALARM_ACE_TYPE },
                { "ACCESS_ALLOWED_COMPOUND_ACE_TYPE", 0xffffffff,
                  ACCESS_ALLOWED_COMPOUND_ACE_TYPE },
                { "ACCESS_ALLOWED_OBJECT_ACE_TYPE", 0xffffffff,
                  ACCESS_ALLOWED_OBJECT_ACE_TYPE },
                { "ACCESS_DENIED_OBJECT_ACE_TYPE", 0xffffffff,
                  ACCESS_DENIED_OBJECT_ACE_TYPE },
                { "SYSTEM_AUDIT_OBJECT_ACE_TYPE", 0xffffffff,
                  SYSTEM_AUDIT_OBJECT_ACE_TYPE },
                { "SYSTEM_ALARM_OBJECT_ACE_TYPE", 0xffffffff,
                  SYSTEM_ALARM_OBJECT_ACE_TYPE },
                { "ACCESS_ALLOWED_CALLBACK_ACE_TYPE", 0xffffffff,
                  ACCESS_ALLOWED_CALLBACK_ACE_TYPE },
                { "ACCESS_DENIED_CALLBACK_ACE_TYPE", 0xffffffff,
                  ACCESS_DENIED_CALLBACK_ACE_TYPE },
                { "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE", 0xffffffff,
                  ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE },
                { "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE", 0xffffffff,
                  ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE },
                { "SYSTEM_AUDIT_CALLBACK_ACE_TYPE", 0xffffffff,
                  SYSTEM_AUDIT_CALLBACK_ACE_TYPE },
                { "SYSTEM_ALARM_CALLBACK_ACE_TYPE", 0xffffffff,
                  SYSTEM_ALARM_CALLBACK_ACE_TYPE },
                { "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE", 0xffffffff,
                  SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE },
                { "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE", 0xffffffff,
                  SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE },
                { "SYSTEM_MANDATORY_LABEL_ACE_TYPE", 0xffffffff,
                  SYSTEM_MANDATORY_LABEL_ACE_TYPE },
                { "SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE", 0xffffffff,
                  SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE },
                { "SYSTEM_SCOPED_POLICY_ID_ACE_TYPE", 0xffffffff,
                  SYSTEM_SCOPED_POLICY_ID_ACE_TYPE },
                { NULL, 0, 0 },
        },
};

/* AceFlags is a bitfield; each flag is its own mask bit. */
static struct dcerpc_uint32_pretty_printer ace_flags_pp = {
        .fmt = "0x%02x",
        .bitfields = {
                { "OBJECT_INHERIT_ACE",
                  OBJECT_INHERIT_ACE, OBJECT_INHERIT_ACE },
                { "CONTAINER_INHERIT_ACE",
                  CONTAINER_INHERIT_ACE, CONTAINER_INHERIT_ACE },
                { "NO_PROPAGATE_INHERIT_ACE",
                  NO_PROPAGATE_INHERIT_ACE, NO_PROPAGATE_INHERIT_ACE },
                { "INHERIT_ONLY_ACE",
                  INHERIT_ONLY_ACE, INHERIT_ONLY_ACE },
                { "INHERITED_ACE",
                  INHERITED_ACE, INHERITED_ACE },
                { "SUCCESSFUL_ACCESS_ACE_FLAG",
                  SUCCESSFUL_ACCESS_ACE_FLAG, SUCCESSFUL_ACCESS_ACE_FLAG },
                { "FAILED_ACCESS_ACE_FLAG",
                  FAILED_ACCESS_ACE_FLAG, FAILED_ACCESS_ACE_FLAG },
                { NULL, 0, 0 },
        },
};

/*
 * Encode a uint8_t field. NDR uses the native 1-byte form; YAML/JSON promote
 * to uint32 so the shared pretty-printer can name enum/flag values.
 */
static int
dcerpc_uint8_pp_coder(char *name, struct dcerpc_context *dce,
                      struct dcerpc_pdu *pdu,
                      struct dcerpc_iovec *iov, int *offset,
                      void *ptr,
                      struct dcerpc_uint32_pretty_printer *pp)
{
        uint8_t *v = ptr;
        uint32_t tmp = 0;

        if (dcerpc_pdu_encoding(pdu) == ENCODING_NDR) {
                return ndr_uint8_coder(name, dce, pdu, iov, offset, v);
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                tmp = *v;
        }
        if (dcerpc_uint32_coder_pp(name, dce, pdu, iov, offset, &tmp, pp)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                if (tmp > 0xff) {
                        return -1;
                }
                *v = (uint8_t)tmp;
        }
        return 0;
}

static int
ace_header_fields_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        void *ptr)
{
        ACE_HEADER *hdr = ptr;

        if (dcerpc_uint8_pp_coder("AceType", dce, pdu, iov, offset,
                                  &hdr->AceType, &ace_type_pp)) {
                return -1;
        }
        if (dcerpc_uint8_pp_coder("AceFlags", dce, pdu, iov, offset,
                                  &hdr->AceFlags, &ace_flags_pp)) {
                return -1;
        }
        /*
         * AceSize is a wire-only field. It is not emitted or accepted in
         * YAML/JSON; parent ACE coders derive it from the body (e.g. Sid).
         * NDR still reads/writes it as required by MS-DTYP 2.4.4.1.
         */
        if (dcerpc_pdu_encoding(pdu) == ENCODING_NDR) {
                if (dcerpc_uint16_coder("AceSize", dce, pdu, iov, offset,
                                        &hdr->AceSize)) {
                        return -1;
                }
        }
        return 0;
}

int
dcerpc_ACE_HEADER_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   ace_header_fields_coder);
}

/*
 * MS-DTYP 2.4.3 ACCESS_MASK — standard / generic rights bitfield.
 * Object-specific bits in the low 16 bits are protocol-dependent and
 * are left as raw values.
 */
static struct dcerpc_uint32_pretty_printer access_mask_pp = {
        .fmt = "0x%08x",
        .bitfields = {
                { "GENERIC_READ",
                  GENERIC_READ, GENERIC_READ },
                { "GENERIC_WRITE",
                  GENERIC_WRITE, GENERIC_WRITE },
                { "GENERIC_EXECUTE",
                  GENERIC_EXECUTE, GENERIC_EXECUTE },
                { "GENERIC_ALL",
                  GENERIC_ALL, GENERIC_ALL },
                { "MAXIMUM_ALLOWED",
                  MAXIMUM_ALLOWED, MAXIMUM_ALLOWED },
                { "ACCESS_SYSTEM_SECURITY",
                  ACCESS_SYSTEM_SECURITY, ACCESS_SYSTEM_SECURITY },
                { "SYNCHRONIZE",
                  SYNCHRONIZE, SYNCHRONIZE },
                { "WRITE_OWNER",
                  WRITE_OWNER, WRITE_OWNER },
                { "WRITE_DACL",
                  WRITE_DACL, WRITE_DACL },
                { "READ_CONTROL",
                  READ_CONTROL, READ_CONTROL },
                { "DELETE",
                  DELETE, DELETE },
                { NULL, 0, 0 },
        },
};

/*
 * Packet SID (MS-DTYP 2.4.2.2) as used inside ACEs / ACLs / security
 * descriptors. Unlike RPC_SID there is no leading size_is count.
 */
static int
ndr_packet_sid_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        RPC_SID *sid = ptr;
        uint8_t count;
        int i;

        if (ndr_uint8_coder("Revision", dce, pdu, iov, offset,
                            &sid->Revision)) {
                return -1;
        }
        if (ndr_uint8_coder("SubAuthorityCount", dce, pdu, iov, offset,
                            &sid->SubAuthorityCount)) {
                return -1;
        }
        for (i = 0; i < 6; i++) {
                if (ndr_uint8_coder("IdentifierAuthority", dce, pdu, iov,
                                    offset, &sid->IdentifierAuthority[i])) {
                        return -1;
                }
        }

        /*
         * During the conformance run SubAuthorityCount is not updated on
         * decode; use the in-memory count (encode) or 0 (fresh decode).
         * Alignment is already raised by Mask (uint32) in the ACE.
         */
        count = sid->SubAuthorityCount;
        if (count > MAXSUBAUTH) {
                return -1;
        }
        for (i = 0; i < count; i++) {
                if (ndr_uint32_coder("SubAuthority", dce, pdu, iov, offset,
                                     &sid->SubAuthority[i])) {
                        return -1;
                }
        }
        return 0;
}

/*
 * SID field for ACE packet types: NDR = packet form; YAML/JSON = S-R-I-...
 */
static int
dcerpc_packet_sid_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        void *ptr)
{
        switch (dcerpc_pdu_encoding(pdu)) {
        case ENCODING_NDR:
                return ndr_packet_sid_coder(name, dce, pdu, iov, offset, ptr);
        case ENCODING_YAML:
                return yaml_sid_coder(name, dce, pdu, iov, offset, ptr);
        case ENCODING_JSON:
                return json_sid_coder(name, dce, pdu, iov, offset, ptr);
        }
        return 0;
}

/*
 * Shared layout for simple Header+Mask+Sid ACEs (allow, deny, audit, alarm,
 * mandatory label, scoped policy id):
 *   Header(4) + Mask(4) + SID(8 + 4*SubAuthorityCount)
 */
struct ace_mask_sid {
        ACE_HEADER Header;
        ACCESS_MASK Mask;
        RPC_SID Sid;
};

static uint16_t
ace_mask_sid_size(const struct ace_mask_sid *ace)
{
        return (uint16_t)(8 + 8 + 4 * ace->Sid.SubAuthorityCount);
}

static int
ace_mask_sid_fields_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          void *ptr)
{
        struct ace_mask_sid *ace = ptr;

        /*
         * AceSize is not part of the YAML/JSON model. On NDR encode it must
         * be filled before Header is written; on text decode it is derived
         * after Sid is known.
         */
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                ace->Header.AceSize = ace_mask_sid_size(ace);
        }

        if (dcerpc_ACE_HEADER_coder("Header", dce, pdu, iov, offset,
                                    &ace->Header)) {
                return -1;
        }
        if (dcerpc_uint32_coder_pp("Mask", dce, pdu, iov, offset,
                                   &ace->Mask, &access_mask_pp)) {
                return -1;
        }
        if (dcerpc_packet_sid_coder("Sid", dce, pdu, iov, offset,
                                    &ace->Sid)) {
                return -1;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE &&
            dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                ace->Header.AceSize = ace_mask_sid_size(ace);
        }
        return 0;
}

/*
 * MS-DTYP simple Header+Mask+Sid ACEs. Same packet layout; AceType only:
 *   ACCESS_ALLOWED_ACE_TYPE (0x00)
 *   ACCESS_DENIED_ACE_TYPE (0x01)
 *   SYSTEM_AUDIT_ACE_TYPE (0x02)
 *   SYSTEM_ALARM_ACE_TYPE (0x03)
 *   SYSTEM_MANDATORY_LABEL_ACE_TYPE (0x11)
 *   SYSTEM_SCOPED_POLICY_ID_ACE_TYPE (0x13)
 */
int
dcerpc_ACCESS_ALLOWED_ACE_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct dcerpc_iovec *iov, int *offset,
                                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   ace_mask_sid_fields_coder);
}

int
dcerpc_ACCESS_DENIED_ACE_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   ace_mask_sid_fields_coder);
}

int
dcerpc_SYSTEM_AUDIT_ACE_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov, int *offset,
                              void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   ace_mask_sid_fields_coder);
}

int
dcerpc_SYSTEM_ALARM_ACE_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov, int *offset,
                              void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   ace_mask_sid_fields_coder);
}

int
dcerpc_SYSTEM_MANDATORY_LABEL_ACE_coder(char *name, struct dcerpc_context *dce,
                                        struct dcerpc_pdu *pdu,
                                        struct dcerpc_iovec *iov, int *offset,
                                        void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   ace_mask_sid_fields_coder);
}

int
dcerpc_SYSTEM_SCOPED_POLICY_ID_ACE_coder(char *name, struct dcerpc_context *dce,
                                         struct dcerpc_pdu *pdu,
                                         struct dcerpc_iovec *iov, int *offset,
                                         void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   ace_mask_sid_fields_coder);
}

/*
 * MS-DTYP 2.4.5 ACL
 *
 * typedef struct _ACL {
 *     unsigned char AclRevision;
 *     unsigned char Sbz1;
 *     unsigned short AclSize;
 *     unsigned short AceCount;
 *     unsigned short Sbz2;
 * } ACL;
 * followed by AceCount ACE records (packet form, no NDR size_is).
 */

static struct dcerpc_uint32_pretty_printer acl_revision_pp = {
        .fmt = "0x%02x",
        .bitfields = {
                { "ACL_REVISION", 0xffffffff, ACL_REVISION },
                { "ACL_REVISION_DS", 0xffffffff, ACL_REVISION_DS },
                { NULL, 0, 0 },
        },
};

static uint16_t
acl_compute_size(const ACL *acl)
{
        uint16_t size = 8; /* header */
        uint16_t i;

        if (acl->Aces == NULL) {
                return size;
        }
        for (i = 0; i < acl->AceCount; i++) {
                size = (uint16_t)(size +
                        ace_mask_sid_size((const struct ace_mask_sid *)
                                          &acl->Aces[i]));
        }
        return size;
}

/*
 * Encode/decode AceCount ACEs packed after the ACL header.
 * NDR: sequential packet ACEs (no array conformance count).
 * YAML/JSON: named array "Aces".
 */
static int
acl_aces_coder(char *name, struct dcerpc_context *dce,
               struct dcerpc_pdu *pdu,
               struct dcerpc_iovec *iov, int *offset,
               void *ptr)
{
        ACL *acl = ptr;
        uint16_t i;

        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                if (acl->AceCount == 0) {
                        return 0;
                }
                if (acl->Aces == NULL) {
                        return -1;
                }
                return dcerpc_carray_coder("Aces", dce, pdu, iov, offset,
                                           acl->AceCount, acl->Aces,
                                           (int)sizeof(ACCESS_ALLOWED_ACE),
                                           ace_mask_sid_fields_coder);
        }

        /* NDR packet form: ACEs back-to-back, no size_is prefix. */
        for (i = 0; i < acl->AceCount; i++) {
                if (ace_mask_sid_fields_coder("Ace", dce, pdu, iov, offset,
                                              &acl->Aces[i])) {
                        return -1;
                }
        }
        return 0;
}

static int
acl_fields_coder(char *name, struct dcerpc_context *dce,
                 struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, int *offset,
                 void *ptr)
{
        ACL *acl = ptr;
        uint16_t ace_count;
        uint8_t zero = 0;

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                acl->Sbz1 = 0;
                acl->Sbz2 = 0;
                acl->AclSize = acl_compute_size(acl);
        }

        if (dcerpc_uint8_pp_coder("AclRevision", dce, pdu, iov, offset,
                                  &acl->AclRevision, &acl_revision_pp)) {
                return -1;
        }

        /* Sbz1: wire-only reserved zero */
        if (dcerpc_pdu_encoding(pdu) == ENCODING_NDR) {
                if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                        zero = 0;
                        if (ndr_uint8_coder("Sbz1", dce, pdu, iov, offset,
                                            &zero)) {
                                return -1;
                        }
                } else {
                        if (ndr_uint8_coder("Sbz1", dce, pdu, iov, offset,
                                            &acl->Sbz1)) {
                                return -1;
                        }
                }
                if (dcerpc_uint16_coder("AclSize", dce, pdu, iov, offset,
                                        &acl->AclSize)) {
                        return -1;
                }
        }

        ace_count = acl->AceCount;
        if (dcerpc_uint16_coder("AceCount", dce, pdu, iov, offset,
                                &ace_count)) {
                return -1;
        }
        acl->AceCount = ace_count;

        /* Sbz2: wire-only reserved zero */
        if (dcerpc_pdu_encoding(pdu) == ENCODING_NDR) {
                if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                        zero = 0;
                        /*
                         * Sbz2 is USHORT; write via uint16 with a zero value.
                         */
                        {
                                uint16_t z16 = 0;

                                if (dcerpc_uint16_coder("Sbz2", dce, pdu, iov,
                                                        offset, &z16)) {
                                        return -1;
                                }
                        }
                } else {
                        if (dcerpc_uint16_coder("Sbz2", dce, pdu, iov, offset,
                                                &acl->Sbz2)) {
                                return -1;
                        }
                }
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && acl->AceCount) {
                acl->Aces = dcerpc_alloc_data(pdu,
                                            (size_t)acl->AceCount *
                                            sizeof(ACCESS_ALLOWED_ACE));
                if (acl->Aces == NULL) {
                        return -1;
                }
        }

        if (acl_aces_coder("Aces", dce, pdu, iov, offset, acl)) {
                return -1;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE &&
            dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                acl->Sbz1 = 0;
                acl->Sbz2 = 0;
                acl->AclSize = acl_compute_size(acl);
        }
        return 0;
}

int
dcerpc_ACL_coder(char *name, struct dcerpc_context *dce,
                 struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, int *offset,
                 void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   acl_fields_coder);
}

/*
 * MS-DTYP 2.4.6 SECURITY_DESCRIPTOR (self-relative packet form)
 */

static struct dcerpc_uint32_pretty_printer sd_control_pp = {
        .fmt = "0x%04x",
        .bitfields = {
                { "SE_OWNER_DEFAULTED",
                  SE_OWNER_DEFAULTED, SE_OWNER_DEFAULTED },
                { "SE_GROUP_DEFAULTED",
                  SE_GROUP_DEFAULTED, SE_GROUP_DEFAULTED },
                { "SE_DACL_PRESENT",
                  SE_DACL_PRESENT, SE_DACL_PRESENT },
                { "SE_DACL_DEFAULTED",
                  SE_DACL_DEFAULTED, SE_DACL_DEFAULTED },
                { "SE_SACL_PRESENT",
                  SE_SACL_PRESENT, SE_SACL_PRESENT },
                { "SE_SACL_DEFAULTED",
                  SE_SACL_DEFAULTED, SE_SACL_DEFAULTED },
                { "SE_DACL_AUTO_INHERIT_REQ",
                  SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERIT_REQ },
                { "SE_SACL_AUTO_INHERIT_REQ",
                  SE_SACL_AUTO_INHERIT_REQ, SE_SACL_AUTO_INHERIT_REQ },
                { "SE_DACL_AUTO_INHERITED",
                  SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERITED },
                { "SE_SACL_AUTO_INHERITED",
                  SE_SACL_AUTO_INHERITED, SE_SACL_AUTO_INHERITED },
                { "SE_DACL_PROTECTED",
                  SE_DACL_PROTECTED, SE_DACL_PROTECTED },
                { "SE_SACL_PROTECTED",
                  SE_SACL_PROTECTED, SE_SACL_PROTECTED },
                { "SE_RM_CONTROL_VALID",
                  SE_RM_CONTROL_VALID, SE_RM_CONTROL_VALID },
                { "SE_SELF_RELATIVE",
                  SE_SELF_RELATIVE, SE_SELF_RELATIVE },
                { NULL, 0, 0 },
        },
};

static int
sd_write_u32_at(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int pos, uint32_t val)
{
        int o = pos;

        return ndr_uint32_coder("", dce, pdu, iov, &o, &val);
}

static int
sd_read_u32_at(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
               struct dcerpc_iovec *iov, int pos, uint32_t *val)
{
        int o = pos;

        return ndr_uint32_coder("", dce, pdu, iov, &o, val);
}

/*
 * Optional Owner/Group SID for YAML/JSON: present key allocates on decode;
 * missing key leaves *sidp as NULL. NDR path does not use this helper.
 */
static int
sd_optional_sid_text(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     RPC_SID **sidp)
{
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                if (*sidp == NULL) {
                        return 0;
                }
                return dcerpc_packet_sid_coder(name, dce, pdu, iov, offset,
                                               *sidp);
        }

        /* DECODE */
        if (dcerpc_pdu_encoding(pdu) == ENCODING_YAML) {
                if (dcerpc_pdu_yaml_key(pdu) == NULL ||
                    strcmp(dcerpc_pdu_yaml_key(pdu), name)) {
                        return 0;
                }
        } else {
                int rc;
                char *jk;

                rc = dcerpc_json_next_key(pdu, iov, offset);
                if (rc != 0) {
                        return rc < 0 ? -1 : 0;
                }
                jk = dcerpc_pdu_json_key(pdu);
                if (jk == NULL || strcmp(jk, name)) {
                        return 0;
                }
        }

        *sidp = dcerpc_alloc_data(pdu,
                                sizeof(RPC_SID));
        if (*sidp == NULL) {
                return -1;
        }
        return dcerpc_packet_sid_coder(name, dce, pdu, iov, offset, *sidp);
}

/*
 * Optional Sacl/Dacl for YAML/JSON.
 */
static int
sd_optional_acl_text(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     ACL **aclp)
{
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                if (*aclp == NULL) {
                        return 0;
                }
                return dcerpc_ACL_coder(name, dce, pdu, iov, offset, *aclp);
        }

        if (dcerpc_pdu_encoding(pdu) == ENCODING_YAML) {
                if (dcerpc_pdu_yaml_key(pdu) == NULL ||
                    strcmp(dcerpc_pdu_yaml_key(pdu), name)) {
                        return 0;
                }
        } else {
                int rc;
                char *jk;

                rc = dcerpc_json_next_key(pdu, iov, offset);
                if (rc != 0) {
                        return rc < 0 ? -1 : 0;
                }
                jk = dcerpc_pdu_json_key(pdu);
                if (jk == NULL || strcmp(jk, name)) {
                        return 0;
                }
        }

        *aclp = dcerpc_alloc_data(pdu,
                                sizeof(ACL));
        if (*aclp == NULL) {
                return -1;
        }
        return dcerpc_ACL_coder(name, dce, pdu, iov, offset, *aclp);
}

static int
sd_ndr_encode(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
              struct dcerpc_iovec *iov, int *offset, SECURITY_DESCRIPTOR *sd)
{
        int base;
        int pos;
        uint32_t off_owner = 0, off_group = 0, off_sacl = 0, off_dacl = 0;
        uint16_t control;
        uint8_t rev, sbz1;

        base = *offset;
        control = sd->Control | SE_SELF_RELATIVE;
        if (sd->Dacl) {
                control = (uint16_t)(control | SE_DACL_PRESENT);
        }
        if (sd->Sacl) {
                control = (uint16_t)(control | SE_SACL_PRESENT);
        }
        sd->Control = control;
        sd->Sbz1 = 0;

        rev = sd->Revision ? sd->Revision : 1;
        if (ndr_uint8_coder("Revision", dce, pdu, iov, offset, &rev)) {
                return -1;
        }
        sbz1 = 0;
        if (ndr_uint8_coder("Sbz1", dce, pdu, iov, offset, &sbz1)) {
                return -1;
        }
        if (dcerpc_uint16_coder("Control", dce, pdu, iov, offset, &control)) {
                return -1;
        }

        /* Placeholder offsets; patched after bodies are written. */
        if (sd_write_u32_at(dce, pdu, iov, base + 4, 0) ||
            sd_write_u32_at(dce, pdu, iov, base + 8, 0) ||
            sd_write_u32_at(dce, pdu, iov, base + 12, 0) ||
            sd_write_u32_at(dce, pdu, iov, base + 16, 0)) {
                return -1;
        }
        *offset = base + 20;
        pos = *offset;

        if (sd->Owner) {
                off_owner = (uint32_t)(pos - base);
                *offset = pos;
                if (ndr_packet_sid_coder("Owner", dce, pdu, iov, offset,
                                         sd->Owner)) {
                        return -1;
                }
                pos = *offset;
        }
        if (sd->Group) {
                off_group = (uint32_t)(pos - base);
                *offset = pos;
                if (ndr_packet_sid_coder("Group", dce, pdu, iov, offset,
                                         sd->Group)) {
                        return -1;
                }
                pos = *offset;
        }
        if (sd->Sacl) {
                off_sacl = (uint32_t)(pos - base);
                *offset = pos;
                if (acl_fields_coder("Sacl", dce, pdu, iov, offset, sd->Sacl)) {
                        return -1;
                }
                pos = *offset;
        }
        if (sd->Dacl) {
                off_dacl = (uint32_t)(pos - base);
                *offset = pos;
                if (acl_fields_coder("Dacl", dce, pdu, iov, offset, sd->Dacl)) {
                        return -1;
                }
                pos = *offset;
        }

        if (sd_write_u32_at(dce, pdu, iov, base + 4, off_owner) ||
            sd_write_u32_at(dce, pdu, iov, base + 8, off_group) ||
            sd_write_u32_at(dce, pdu, iov, base + 12, off_sacl) ||
            sd_write_u32_at(dce, pdu, iov, base + 16, off_dacl)) {
                return -1;
        }
        *offset = pos;
        return 0;
}

static int
sd_ndr_decode(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
              struct dcerpc_iovec *iov, int *offset, SECURITY_DESCRIPTOR *sd)
{
        int base;
        int end;
        int o;
        uint32_t off_owner, off_group, off_sacl, off_dacl;

        base = *offset;
        if (ndr_uint8_coder("Revision", dce, pdu, iov, offset, &sd->Revision)) {
                return -1;
        }
        if (ndr_uint8_coder("Sbz1", dce, pdu, iov, offset, &sd->Sbz1)) {
                return -1;
        }
        if (dcerpc_uint16_coder("Control", dce, pdu, iov, offset, &sd->Control)) {
                return -1;
        }
        if (sd_read_u32_at(dce, pdu, iov, base + 4, &off_owner) ||
            sd_read_u32_at(dce, pdu, iov, base + 8, &off_group) ||
            sd_read_u32_at(dce, pdu, iov, base + 12, &off_sacl) ||
            sd_read_u32_at(dce, pdu, iov, base + 16, &off_dacl)) {
                return -1;
        }
        *offset = base + 20;
        end = base + 20;

        if (off_owner) {
                o = base + (int)off_owner;
                sd->Owner = dcerpc_alloc_data(pdu,
                                            sizeof(RPC_SID));
                if (sd->Owner == NULL) {
                        return -1;
                }
                if (ndr_packet_sid_coder("Owner", dce, pdu, iov, &o,
                                         sd->Owner)) {
                        return -1;
                }
                if (o > end) {
                        end = o;
                }
        }
        if (off_group) {
                o = base + (int)off_group;
                sd->Group = dcerpc_alloc_data(pdu,
                                            sizeof(RPC_SID));
                if (sd->Group == NULL) {
                        return -1;
                }
                if (ndr_packet_sid_coder("Group", dce, pdu, iov, &o,
                                         sd->Group)) {
                        return -1;
                }
                if (o > end) {
                        end = o;
                }
        }
        if (off_sacl) {
                o = base + (int)off_sacl;
                sd->Sacl = dcerpc_alloc_data(pdu,
                                           sizeof(ACL));
                if (sd->Sacl == NULL) {
                        return -1;
                }
                if (acl_fields_coder("Sacl", dce, pdu, iov, &o, sd->Sacl)) {
                        return -1;
                }
                if (o > end) {
                        end = o;
                }
        }
        if (off_dacl) {
                o = base + (int)off_dacl;
                sd->Dacl = dcerpc_alloc_data(pdu,
                                           sizeof(ACL));
                if (sd->Dacl == NULL) {
                        return -1;
                }
                if (acl_fields_coder("Dacl", dce, pdu, iov, &o, sd->Dacl)) {
                        return -1;
                }
                if (o > end) {
                        end = o;
                }
        }

        *offset = end;
        return 0;
}

static struct dcerpc_uint32_pretty_printer sd_revision_pp = {
        .fmt = "%u",
        .bitfields = {
                { "SECURITY_DESCRIPTOR_REVISION", 0xffffffff, 1 },
                { NULL, 0, 0 },
        },
};

static int
security_descriptor_fields_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct dcerpc_iovec *iov, int *offset,
                                 void *ptr)
{
        SECURITY_DESCRIPTOR *sd = ptr;
        uint16_t control;
        uint32_t control32 = 0;

        if (dcerpc_pdu_encoding(pdu) == ENCODING_NDR) {
                if (dcerpc_pdu_is_conformance_run(pdu)) {
                        dcerpc_pdu_raise_max_alignment(pdu, 4);
                        return 0;
                }
                if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                        return sd_ndr_encode(dce, pdu, iov, offset, sd);
                }
                return sd_ndr_decode(dce, pdu, iov, offset, sd);
        }

        /* YAML / JSON — logical absolute form (no offsets / Sbz1) */
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE &&
            sd->Revision == 0) {
                sd->Revision = 1;
        }
        if (dcerpc_uint8_pp_coder("Revision", dce, pdu, iov, offset,
                                  &sd->Revision, &sd_revision_pp)) {
                return -1;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                control = sd->Control | SE_SELF_RELATIVE;
                if (sd->Dacl) {
                        control = (uint16_t)(control | SE_DACL_PRESENT);
                }
                if (sd->Sacl) {
                        control = (uint16_t)(control | SE_SACL_PRESENT);
                }
                sd->Control = control;
                control32 = control;
        }
        if (dcerpc_uint32_coder_pp("Control", dce, pdu, iov, offset,
                                   &control32, &sd_control_pp)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                sd->Control = (uint16_t)control32;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                if (sd_optional_sid_text("Owner", dce, pdu, iov, offset,
                                         &sd->Owner) ||
                    sd_optional_sid_text("Group", dce, pdu, iov, offset,
                                         &sd->Group) ||
                    sd_optional_acl_text("Sacl", dce, pdu, iov, offset,
                                         &sd->Sacl) ||
                    sd_optional_acl_text("Dacl", dce, pdu, iov, offset,
                                         &sd->Dacl)) {
                        return -1;
                }
        } else {
                /*
                 * Accept Owner/Group/Sacl/Dacl in any order. Each helper
                 * no-ops when the current key is not its own.
                 */
                int i;

                for (i = 0; i < 4; i++) {
                        char *key;

                        if (dcerpc_pdu_encoding(pdu) == ENCODING_YAML) {
                                key = dcerpc_pdu_yaml_key(pdu);
                        } else {
                                int rc;

                                rc = dcerpc_json_next_key(pdu, iov, offset);
                                if (rc != 0) {
                                        break;
                                }
                                key = dcerpc_pdu_json_key(pdu);
                        }
                        if (key == NULL) {
                                break;
                        }
                        if (!strcmp(key, "Owner")) {
                                if (sd_optional_sid_text("Owner", dce, pdu, iov,
                                                         offset, &sd->Owner)) {
                                        return -1;
                                }
                        } else if (!strcmp(key, "Group")) {
                                if (sd_optional_sid_text("Group", dce, pdu, iov,
                                                         offset, &sd->Group)) {
                                        return -1;
                                }
                        } else if (!strcmp(key, "Sacl")) {
                                if (sd_optional_acl_text("Sacl", dce, pdu, iov,
                                                         offset, &sd->Sacl)) {
                                        return -1;
                                }
                        } else if (!strcmp(key, "Dacl")) {
                                if (sd_optional_acl_text("Dacl", dce, pdu, iov,
                                                         offset, &sd->Dacl)) {
                                        return -1;
                                }
                        } else {
                                break;
                        }
                }
                sd->Sbz1 = 0;
        }
        return 0;
}

int
dcerpc_SECURITY_DESCRIPTOR_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct dcerpc_iovec *iov, int *offset,
                                 void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   security_descriptor_fields_coder);
}
