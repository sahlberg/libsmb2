/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2020 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
#include "libsmb2-dcerpc.h"
#include "libsmb2-dcerpc-lsa.h"
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
              struct smb2_iovec *iov, int *offset,
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
               struct smb2_iovec *iov, int *offset, void *ptr)
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
               struct smb2_iovec *iov, int *offset, void *ptr)
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
                 struct smb2_iovec *iov, int *offset,
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
