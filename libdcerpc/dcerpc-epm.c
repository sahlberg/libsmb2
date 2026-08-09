/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <stdio.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-epm.h>
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

/* MS-RPCE / C706: uuid(e1af8308-5d1f-11c9-91a4-08002b14a0fa), version(3.0) */
#define EPM_UUID 0xe1af8308, 0x5d1f, 0x11c9, \
        {0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa}

p_syntax_id_t epm_interface = {
        {EPM_UUID}, 3, 0
};

/* NDR transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0 */
static const dcerpc_uuid_t ndr_transfer_uuid = {
        0x8a885d04, 0x1ceb, 0x11c9,
        {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
};

static struct dcerpc_uint32_pretty_printer inquiry_type_pp = {
        .fmt = "0x%08x",
        .bitfields = {
                { "RPC_C_EP_ALL_ELTS", 0xffffffff, RPC_C_EP_ALL_ELTS },
                { "RPC_C_EP_MATCH_BY_IF", 0xffffffff, RPC_C_EP_MATCH_BY_IF },
                { "RPC_C_EP_MATCH_BY_OBJ", 0xffffffff, RPC_C_EP_MATCH_BY_OBJ },
                { "RPC_C_EP_MATCH_BY_BOTH", 0xffffffff, RPC_C_EP_MATCH_BY_BOTH },
                { NULL, 0, 0},
        },
};

static struct dcerpc_uint32_pretty_printer vers_option_pp = {
        .fmt = "0x%08x",
        .bitfields = {
                { "RPC_C_VERS_ALL", 0xffffffff, RPC_C_VERS_ALL },
                { "RPC_C_VERS_COMPATIBLE", 0xffffffff, RPC_C_VERS_COMPATIBLE },
                { "RPC_C_VERS_EXACT", 0xffffffff, RPC_C_VERS_EXACT },
                { "RPC_C_VERS_MAJOR_ONLY", 0xffffffff, RPC_C_VERS_MAJOR_ONLY },
                { "RPC_C_VERS_UPTO", 0xffffffff, RPC_C_VERS_UPTO },
                { NULL, 0, 0},
        },
};

/**********************
 * UUID field (NDR / YAML / JSON)
 **********************/
static int
epm_uuid_field_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        dcerpc_uuid_t *uuid = ptr;
        int i;

        if (dcerpc_pdu_encoding(pdu) == ENCODING_NDR) {
                return ndr_uuid_coder(name, dce, pdu, iov, offset, uuid);
        }

#ifdef HAVE_DCERPC_FULL
        if (dcerpc_pdu_encoding(pdu) == ENCODING_YAML) {
                if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                        unsigned int v1, v2, v3;
                        unsigned int b[8];

                        yaml_next_kv(pdu, iov, offset);
                        if (strcmp(dcerpc_pdu_yaml_key(pdu), name)) {
                                /* optional unique: missing key */
                                return 0;
                        }
                        dcerpc_pdu_clear_yaml_key(pdu);
                        if (sscanf(dcerpc_pdu_yaml_val(pdu),
                                   "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                   &v1, &v2, &v3,
                                   &b[0], &b[1], &b[2], &b[3],
                                   &b[4], &b[5], &b[6], &b[7]) != 11) {
                                return -1;
                        }
                        uuid->v1 = v1;
                        uuid->v2 = (uint16_t)v2;
                        uuid->v3 = (uint16_t)v3;
                        for (i = 0; i < 8; i++) {
                                uuid->v4[i] = (uint8_t)b[i];
                        }
                        yaml_next_kv(pdu, iov, offset);
                        return 0;
                }
                yaml_print_preamble(dce, pdu, iov, offset);
                if (*offset + 256 < (int)iov->len) {
                        *offset += snprintf((char *)&iov->buf[*offset],
                                           iov->len - *offset,
                                           "%s: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                                           name,
                                           uuid->v1, uuid->v2, uuid->v3,
                                           uuid->v4[0], uuid->v4[1],
                                           uuid->v4[2], uuid->v4[3],
                                           uuid->v4[4], uuid->v4[5],
                                           uuid->v4[6], uuid->v4[7]);
                }
                return 0;
        }
        if (dcerpc_pdu_encoding(pdu) == ENCODING_JSON) {
                if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                        char *val;
                        unsigned int v1, v2, v3;
                        unsigned int b[8];

                        if (json_expect_key(pdu, iov, offset, name) < 0) {
                                return -1;
                        }
                        if (json_parse_string(iov, offset, &val) < 0) {
                                return -1;
                        }
                        if (sscanf(val,
                                   "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                   &v1, &v2, &v3,
                                   &b[0], &b[1], &b[2], &b[3],
                                   &b[4], &b[5], &b[6], &b[7]) != 11) {
                                return -1;
                        }
                        uuid->v1 = v1;
                        uuid->v2 = (uint16_t)v2;
                        uuid->v3 = (uint16_t)v3;
                        for (i = 0; i < 8; i++) {
                                uuid->v4[i] = (uint8_t)b[i];
                        }
                        return 0;
                }
                {
                        char uuidstr[64];

                        snprintf(uuidstr, sizeof(uuidstr),
                                 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                 uuid->v1, uuid->v2, uuid->v3,
                                 uuid->v4[0], uuid->v4[1],
                                 uuid->v4[2], uuid->v4[3],
                                 uuid->v4[4], uuid->v4[5],
                                 uuid->v4[6], uuid->v4[7]);
                        json_sep(pdu, iov, offset);
                        if (json_append_quoted(iov, offset, name) < 0) {
                                return -1;
                        }
                        if (json_append(iov, offset, ": ") < 0) {
                                return -1;
                        }
                        if (json_append_quoted(iov, offset, uuidstr) < 0) {
                                return -1;
                        }
                }
                return 0;
        }
#else
        (void)dce;
        (void)i;
#endif
        return -1;
}

/**********************
 * twr_t
 *
 *   unsigned32 tower_length;
 *   [size_is(tower_length)] byte tower_octet_string[];
 *
 * Wire: tower_length, then conformant max_count, then bytes.
 **********************/
static int
epm_tower_bytes_coder(char *name, struct dcerpc_context *dce,
                      struct dcerpc_pdu *pdu,
                      struct dcerpc_iovec *iov, int *offset,
                      void *ptr)
{
        struct epm_twr_t *twr = ptr;
        uint32_t max_count;
        uint32_t i;

        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                /* YAML/JSON: hex string under TowerOctetString */
                if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                        if (twr->tower_length == 0 ||
                            twr->tower_octet_string == NULL) {
                                return 0;
                        }
#ifdef HAVE_DCERPC_FULL
                        if (dcerpc_pdu_encoding(pdu) == ENCODING_YAML) {
                                yaml_print_preamble(dce, pdu, iov, offset);
                                if (*offset + 32 + (int)twr->tower_length * 2 <
                                    (int)iov->len) {
                                        *offset += snprintf(
                                                (char *)&iov->buf[*offset],
                                                iov->len - *offset,
                                                "TowerOctetString: ");
                                        for (i = 0; i < twr->tower_length; i++) {
                                                *offset += snprintf(
                                                        (char *)&iov->buf[*offset],
                                                        iov->len - *offset,
                                                        "%02x",
                                                        twr->tower_octet_string[i]);
                                        }
                                        *offset += snprintf(
                                                (char *)&iov->buf[*offset],
                                                iov->len - *offset, "\n");
                                }
                                return 0;
                        }
#endif
                        return 0;
                }
                return 0;
        }

        if (dcerpc_get_cr(pdu)) {
                return 0;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                max_count = twr->tower_length;
        } else {
                max_count = 0;
        }
        if (dcerpc_uint32_coder("MaxCount", dce, pdu, iov, offset, &max_count)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                if (max_count > 0x100000) {
                        return -1;
                }
                twr->tower_length = max_count;
                if (max_count == 0) {
                        twr->tower_octet_string = NULL;
                        return 0;
                }
                twr->tower_octet_string = dcerpc_alloc_data(pdu, max_count);
                if (twr->tower_octet_string == NULL) {
                        return -1;
                }
                for (i = 0; i < max_count; i++) {
                        if (ndr_uint8_coder("Data", dce, pdu, iov, offset,
                                            &twr->tower_octet_string[i])) {
                                return -1;
                        }
                }
                return 0;
        }
        for (i = 0; i < max_count; i++) {
                uint8_t byte = twr->tower_octet_string ?
                        twr->tower_octet_string[i] : 0;

                if (ndr_uint8_coder("Data", dce, pdu, iov, offset, &byte)) {
                        return -1;
                }
        }
        return 0;
}

int
epm_twr_coder(char *name, struct dcerpc_context *dce,
              struct dcerpc_pdu *pdu,
              struct dcerpc_iovec *iov, int *offset,
              void *ptr)
{
        struct epm_twr_t *twr = ptr;
        uint32_t len;

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                len = twr->tower_length;
        } else {
                len = 0;
        }
        if (dcerpc_uint32_coder("TowerLength", dce, pdu, iov, offset, &len)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                twr->tower_length = len;
        }
        /*
         * Conformant array body is coded after tower_length. size_is is
         * tower_length; for NDR the array also writes max_count.
         */
        if (epm_tower_bytes_coder("TowerOctetString", dce, pdu, iov, offset,
                                  twr)) {
                return -1;
        }
        return 0;
}

static int
epm_twr_STRUCT_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   epm_twr_coder);
}

/**********************
 * Annotation: [string] char annotation[64]
 * Wire (MIDL/Windows): varying string — offset, actual_count, bytes
 **********************/
static int
epm_annotation_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        char **ann = ptr;
        uint32_t off = 0;
        uint32_t actual;
        uint32_t i;
        const char *s;
        char *out;

        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                return dcerpc_utf16z_coder(name, dce, pdu, iov, offset, ann);
        }

        if (dcerpc_get_cr(pdu)) {
                return 0;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                s = *ann ? *ann : "";
                actual = (uint32_t)strlen(s) + 1;
                if (actual > EPM_MAX_ANNOTATION_SIZE) {
                        actual = EPM_MAX_ANNOTATION_SIZE;
                }
                if (dcerpc_uint32_coder("Offset", dce, pdu, iov, offset, &off)) {
                        return -1;
                }
                if (dcerpc_uint32_coder("ActualCount", dce, pdu, iov, offset,
                                        &actual)) {
                        return -1;
                }
                for (i = 0; i < actual; i++) {
                        uint8_t ch = (i + 1 == actual) ? 0 : (uint8_t)s[i];

                        if (ndr_uint8_coder("Annotation", dce, pdu, iov, offset,
                                            &ch)) {
                                return -1;
                        }
                }
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
                *ann = NULL;
                return 0;
        }
        if (actual > EPM_MAX_ANNOTATION_SIZE || *offset < 0 ||
            (uint64_t)*offset + actual > iov->len) {
                return -1;
        }
        out = dcerpc_alloc_data(pdu, actual);
        if (out == NULL) {
                return -1;
        }
        for (i = 0; i < actual; i++) {
                if (ndr_uint8_coder("Annotation", dce, pdu, iov, offset,
                                    (uint8_t *)&out[i])) {
                        return -1;
                }
        }
        out[actual - 1] = '\0';
        *ann = out;
        return 0;
}

/**********************
 * ept_entry_t
 **********************/
int
epm_entry_coder(char *name, struct dcerpc_context *dce,
                struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, int *offset,
                void *ptr)
{
        struct epm_entry_t *ent = ptr;
        void *tower_ptr;

        if (epm_uuid_field_coder("Object", dce, pdu, iov, offset, &ent->object)) {
                return -1;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                tower_ptr = ent->tower_null ? NULL : &ent->tower;
        } else {
                tower_ptr = &ent->tower;
                ent->tower_null = 0;
        }
        if (dcerpc_ptr_coder("Tower", dce, pdu, iov, offset, tower_ptr,
                             PTR_UNIQUE, epm_twr_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE &&
            ent->tower.tower_length == 0 &&
            ent->tower.tower_octet_string == NULL) {
                /* May still be a present unique with empty tower; leave alone */
        }

        if (epm_annotation_coder("Annotation", dce, pdu, iov, offset,
                                 &ent->annotation)) {
                return -1;
        }
        return 0;
}

static int
epm_entry_STRUCT_coder(char *name, struct dcerpc_context *dce,
                       struct dcerpc_pdu *pdu,
                       struct dcerpc_iovec *iov, int *offset,
                       void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   epm_entry_coder);
}

/**********************
 * rpc_if_id_t
 **********************/
int
epm_rpc_if_id_coder(char *name, struct dcerpc_context *dce,
                    struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, int *offset,
                    void *ptr)
{
        struct epm_rpc_if_id *iid = ptr;

        if (epm_uuid_field_coder("Uuid", dce, pdu, iov, offset, &iid->uuid)) {
                return -1;
        }
        if (dcerpc_uint16_coder("VersMajor", dce, pdu, iov, offset,
                                &iid->vers_major)) {
                return -1;
        }
        if (dcerpc_uint16_coder("VersMinor", dce, pdu, iov, offset,
                                &iid->vers_minor)) {
                return -1;
        }
        return 0;
}

static int
epm_rpc_if_id_STRUCT_coder(char *name, struct dcerpc_context *dce,
                           struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov, int *offset,
                           void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   epm_rpc_if_id_coder);
}

static int
epm_context_handle_STRUCT_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct dcerpc_iovec *iov, int *offset,
                                void *ptr)
{
        return dcerpc_struct_coder(name, dce, pdu, iov, offset, ptr,
                                   dcerpc_context_handle_coder);
}

/*
 * Conformant array of ept_entry_t for Insert/Delete request.
 */
static int
epm_entries_carray_coder(char *name, struct dcerpc_context *dce,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov, int *offset,
                         void *ptr)
{
        return dcerpc_carray_coder("Entries", dce, pdu, iov, offset,
                                   dcerpc_get_size_is(pdu), ptr,
                                   sizeof(struct epm_entry_t),
                                   epm_entry_STRUCT_coder);
}

/*
 * Conformant-varying array of ept_entry_t for Lookup reply.
 * Wire: max_count, offset, actual_count, then actual_count elements.
 */
static int
epm_entries_cvarray_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          void *ptr)
{
        struct epm_Lookup_rep *rep = ptr;
        struct epm_Lookup_req *req;
        uint32_t max_count;
        uint32_t arr_offset = 0;
        uint32_t actual;
        uint32_t i;

        req = dcerpc_get_request(pdu);

        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE &&
                    rep->num_ents && rep->entries == NULL) {
                        rep->entries = dcerpc_alloc_data(
                                pdu,
                                (size_t)rep->num_ents * sizeof(struct epm_entry_t));
                        if (rep->entries == NULL) {
                                return -1;
                        }
                }
                return dcerpc_carray_coder("Entries", dce, pdu, iov, offset,
                                           rep->num_ents, rep->entries,
                                           sizeof(struct epm_entry_t),
                                           epm_entry_STRUCT_coder);
        }

        if (dcerpc_get_cr(pdu)) {
                return 0;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                max_count = req ? req->max_ents : rep->num_ents;
                actual = rep->num_ents;
        } else {
                max_count = 0;
                actual = 0;
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
                if (actual > max_count || actual > 0x10000) {
                        return -1;
                }
                rep->num_ents = actual;
                if (actual == 0) {
                        rep->entries = NULL;
                        return 0;
                }
                rep->entries = dcerpc_alloc_data(
                        pdu, (size_t)actual * sizeof(struct epm_entry_t));
                if (rep->entries == NULL) {
                        return -1;
                }
                memset(rep->entries, 0, (size_t)actual * sizeof(struct epm_entry_t));
        }
        for (i = 0; i < actual; i++) {
                if (epm_entry_STRUCT_coder("Entry", dce, pdu, iov, offset,
                                           &rep->entries[i])) {
                        return -1;
                }
        }
        return 0;
}

/*
 * Array element for Map reply: unique pointer to twr_t.
 * ptr is &towers[i] (struct epm_twr_t *).
 */
static int
epm_twr_unique_elem_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          void *ptr)
{
        return dcerpc_ptr_coder("Tower", dce, pdu, iov, offset, ptr,
                                PTR_UNIQUE, epm_twr_STRUCT_coder);
}

/*
 * Conformant-varying array of twr_p_t for Map reply.
 * Wire: max_count, offset, actual_count, then actual_count unique
 * referents (pointees deferred when top_level is 0).
 */
static int
epm_towers_cvarray_coder(char *name, struct dcerpc_context *dce,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov, int *offset,
                         void *ptr)
{
        struct epm_Map_rep *rep = ptr;
        struct epm_Map_req *req;
        uint32_t max_count;
        uint32_t arr_offset = 0;
        uint32_t actual;
        uint32_t i;

        req = dcerpc_get_request(pdu);

        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE &&
                    rep->num_towers && rep->towers == NULL) {
                        rep->towers = dcerpc_alloc_data(
                                pdu,
                                (size_t)rep->num_towers * sizeof(struct epm_twr_t));
                        if (rep->towers == NULL) {
                                return -1;
                        }
                        memset(rep->towers, 0,
                               (size_t)rep->num_towers * sizeof(struct epm_twr_t));
                }
                return dcerpc_carray_coder("Towers", dce, pdu, iov, offset,
                                           rep->num_towers, rep->towers,
                                           sizeof(struct epm_twr_t),
                                           epm_twr_unique_elem_coder);
        }

        if (dcerpc_get_cr(pdu)) {
                return 0;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                max_count = req ? req->max_towers : rep->num_towers;
                actual = rep->num_towers;
        } else {
                max_count = 0;
                actual = 0;
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
                if (actual > max_count || actual > 0x10000) {
                        return -1;
                }
                rep->num_towers = actual;
                if (actual == 0) {
                        rep->towers = NULL;
                        return 0;
                }
                rep->towers = dcerpc_alloc_data(
                        pdu, (size_t)actual * sizeof(struct epm_twr_t));
                if (rep->towers == NULL) {
                        return -1;
                }
                memset(rep->towers, 0, (size_t)actual * sizeof(struct epm_twr_t));
        }
        for (i = 0; i < actual; i++) {
                if (epm_twr_unique_elem_coder("Tower", dce, pdu, iov, offset,
                                              &rep->towers[i])) {
                        return -1;
                }
        }
        return 0;
}

/**********************
 * ept_Insert
 **********************/
int
epm_Insert_req_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        struct epm_Insert_req *req = ptr;
        void *entries_ptr;

        if (dcerpc_uint32_coder("NumEnts", dce, pdu, iov, offset, &req->num_ents)) {
                return -1;
        }
        dcerpc_set_size_is(pdu, req->num_ents);

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && req->num_ents) {
                if (req->entries == NULL) {
                        req->entries = dcerpc_alloc_data(
                                pdu,
                                (size_t)req->num_ents * sizeof(struct epm_entry_t));
                        if (req->entries == NULL) {
                                return -1;
                        }
                        memset(req->entries, 0,
                               (size_t)req->num_ents * sizeof(struct epm_entry_t));
                }
        }
        entries_ptr = req->entries;
        if (entries_ptr == NULL) {
                entries_ptr = &req->entries;
        }
        if (dcerpc_ptr_coder("Entries", dce, pdu, iov, offset, entries_ptr,
                             PTR_REF, epm_entries_carray_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Replace", dce, pdu, iov, offset, &req->replace)) {
                return -1;
        }
        return 0;
}

int
epm_Insert_rep_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        struct epm_Insert_rep *rep = ptr;

        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }
        return 0;
}

/**********************
 * ept_Delete
 **********************/
int
epm_Delete_req_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        struct epm_Delete_req *req = ptr;
        void *entries_ptr;

        if (dcerpc_uint32_coder("NumEnts", dce, pdu, iov, offset, &req->num_ents)) {
                return -1;
        }
        dcerpc_set_size_is(pdu, req->num_ents);

        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE && req->num_ents) {
                if (req->entries == NULL) {
                        req->entries = dcerpc_alloc_data(
                                pdu,
                                (size_t)req->num_ents * sizeof(struct epm_entry_t));
                        if (req->entries == NULL) {
                                return -1;
                        }
                        memset(req->entries, 0,
                               (size_t)req->num_ents * sizeof(struct epm_entry_t));
                }
        }
        entries_ptr = req->entries;
        if (entries_ptr == NULL) {
                entries_ptr = &req->entries;
        }
        if (dcerpc_ptr_coder("Entries", dce, pdu, iov, offset, entries_ptr,
                             PTR_REF, epm_entries_carray_coder)) {
                return -1;
        }
        return 0;
}

int
epm_Delete_rep_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        struct epm_Delete_rep *rep = ptr;

        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }
        return 0;
}

/**********************
 * ept_Lookup
 **********************/
/*
 * Optional unique UUID: on text decode, missing key keeps *_null = 1.
 * On NDR decode, a null referent leaves storage zeroed and *_null = 1.
 */
static int
epm_opt_uuid_unique_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          dcerpc_uuid_t *uuid, uint32_t *is_null)
{
        void *obj_ptr;

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                obj_ptr = (*is_null) ? NULL : uuid;
                return dcerpc_ptr_coder(name, dce, pdu, iov, offset, obj_ptr,
                                        PTR_UNIQUE, epm_uuid_field_coder);
        }

        /* DECODE: assume null until a non-null unique fills the field */
        *is_null = 1;
        memset(uuid, 0, sizeof(*uuid));
        if (dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                /*
                 * Text: PTR_UNIQUE with non-NULL dest always invokes the
                 * nested coder; missing key returns 0 without changing
                 * *is_null.
                 */
                if (dcerpc_ptr_coder(name, dce, pdu, iov, offset, uuid,
                                     PTR_UNIQUE, epm_uuid_field_coder)) {
                        return -1;
                }
                /* If any field non-zero, treat as present */
                if (uuid->v1 || uuid->v2 || uuid->v3 ||
                    memcmp(uuid->v4, "\0\0\0\0\0\0\0\0", 8) != 0) {
                        *is_null = 0;
                }
                return 0;
        }
        /*
         * NDR: pass storage; null unique leaves zeros. We cannot
         * distinguish null unique from unique-to-nil-UUID after the
         * fact; treat remaining all-zero as null (common for Lookup).
         */
        if (dcerpc_ptr_coder(name, dce, pdu, iov, offset, uuid,
                             PTR_UNIQUE, epm_uuid_field_coder)) {
                return -1;
        }
        if (uuid->v1 || uuid->v2 || uuid->v3 ||
            memcmp(uuid->v4, "\0\0\0\0\0\0\0\0", 8) != 0) {
                *is_null = 0;
        }
        return 0;
}

int
epm_Lookup_req_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        struct epm_Lookup_req *req = ptr;
        void *if_ptr;

        if (dcerpc_uint32_coder_pp("InquiryType", dce, pdu, iov, offset,
                                   &req->inquiry_type, &inquiry_type_pp)) {
                return -1;
        }

        if (epm_opt_uuid_unique_coder("Object", dce, pdu, iov, offset,
                                      &req->object, &req->object_null)) {
                return -1;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                if_ptr = req->interface_id_null ? NULL : &req->interface_id;
        } else {
                if_ptr = &req->interface_id;
                req->interface_id_null = 1;
                memset(&req->interface_id, 0, sizeof(req->interface_id));
        }
        if (dcerpc_ptr_coder("InterfaceId", dce, pdu, iov, offset, if_ptr,
                             PTR_UNIQUE, epm_rpc_if_id_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                if (req->interface_id.vers_major ||
                    req->interface_id.vers_minor ||
                    req->interface_id.uuid.v1 ||
                    req->interface_id.uuid.v2 ||
                    req->interface_id.uuid.v3 ||
                    memcmp(req->interface_id.uuid.v4, "\0\0\0\0\0\0\0\0",
                           8) != 0) {
                        req->interface_id_null = 0;
                }
        }

        if (dcerpc_uint32_coder_pp("VersOption", dce, pdu, iov, offset,
                                   &req->vers_option, &vers_option_pp)) {
                return -1;
        }
        if (dcerpc_ptr_coder("EntryHandle", dce, pdu, iov, offset,
                             &req->entry_handle,
                             PTR_REF, epm_context_handle_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MaxEnts", dce, pdu, iov, offset, &req->max_ents)) {
                return -1;
        }
        return 0;
}

int
epm_Lookup_rep_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr)
{
        struct epm_Lookup_rep *rep = ptr;

        if (dcerpc_ptr_coder("EntryHandle", dce, pdu, iov, offset,
                             &rep->entry_handle,
                             PTR_REF, epm_context_handle_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("NumEnts", dce, pdu, iov, offset, &rep->num_ents)) {
                return -1;
        }
        /*
         * Top-level conformant-varying array: wrap with PTR_REF so
         * top_level is cleared for element coding and unique tower
         * pointees are deferred until after the array.
         */
        if (dcerpc_ptr_coder("Entries", dce, pdu, iov, offset, rep,
                             PTR_REF, epm_entries_cvarray_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }
        return 0;
}

/**********************
 * ept_Map
 **********************/
int
epm_Map_req_coder(char *name, struct dcerpc_context *dce,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, int *offset,
                  void *ptr)
{
        struct epm_Map_req *req = ptr;
        void *tower_ptr;

        if (epm_opt_uuid_unique_coder("Object", dce, pdu, iov, offset,
                                      &req->object, &req->object_null)) {
                return -1;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                tower_ptr = req->map_tower_null ? NULL : &req->map_tower;
        } else {
                tower_ptr = &req->map_tower;
                req->map_tower_null = 0;
        }
        if (dcerpc_ptr_coder("MapTower", dce, pdu, iov, offset, tower_ptr,
                             PTR_UNIQUE, epm_twr_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_ptr_coder("EntryHandle", dce, pdu, iov, offset,
                             &req->entry_handle,
                             PTR_REF, epm_context_handle_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("MaxTowers", dce, pdu, iov, offset,
                                &req->max_towers)) {
                return -1;
        }
        return 0;
}

int
epm_Map_rep_coder(char *name, struct dcerpc_context *dce,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, int *offset,
                  void *ptr)
{
        struct epm_Map_rep *rep = ptr;

        if (dcerpc_ptr_coder("EntryHandle", dce, pdu, iov, offset,
                             &rep->entry_handle,
                             PTR_REF, epm_context_handle_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("NumTowers", dce, pdu, iov, offset,
                                &rep->num_towers)) {
                return -1;
        }
        if (dcerpc_ptr_coder("Towers", dce, pdu, iov, offset, rep,
                             PTR_REF, epm_towers_cvarray_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }
        return 0;
}

/**********************
 * ept_LookupHandleFree
 **********************/
int
epm_LookupHandleFree_req_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr)
{
        struct epm_LookupHandleFree_req *req = ptr;

        if (dcerpc_ptr_coder("EntryHandle", dce, pdu, iov, offset,
                             &req->entry_handle,
                             PTR_REF, epm_context_handle_STRUCT_coder)) {
                return -1;
        }
        return 0;
}

int
epm_LookupHandleFree_rep_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr)
{
        struct epm_LookupHandleFree_rep *rep = ptr;

        if (dcerpc_ptr_coder("EntryHandle", dce, pdu, iov, offset,
                             &rep->entry_handle,
                             PTR_REF, epm_context_handle_STRUCT_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }
        return 0;
}

/**********************
 * ept_InqObject
 **********************/
int
epm_InqObject_req_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        void *ptr)
{
        (void)name;
        (void)dce;
        (void)pdu;
        (void)iov;
        (void)offset;
        (void)ptr;
        return 0;
}

int
epm_InqObject_rep_coder(char *name, struct dcerpc_context *dce,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        void *ptr)
{
        struct epm_InqObject_rep *rep = ptr;

        if (dcerpc_ptr_coder("EptObject", dce, pdu, iov, offset, &rep->ept_object,
                             PTR_REF, epm_uuid_field_coder)) {
                return -1;
        }
        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }
        return 0;
}

/**********************
 * ept_MgmtDelete
 **********************/
int
epm_MgmtDelete_req_coder(char *name, struct dcerpc_context *dce,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov, int *offset,
                         void *ptr)
{
        struct epm_MgmtDelete_req *req = ptr;
        void *obj_ptr;
        void *tower_ptr;

        if (dcerpc_uint32_coder("ObjectSpeced", dce, pdu, iov, offset,
                                &req->object_speced)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                obj_ptr = req->object_null ? NULL : &req->object;
        } else {
                obj_ptr = &req->object;
                req->object_null = 0;
        }
        if (dcerpc_ptr_coder("Object", dce, pdu, iov, offset, obj_ptr,
                             PTR_UNIQUE, epm_uuid_field_coder)) {
                return -1;
        }
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                tower_ptr = req->tower_null ? NULL : &req->tower;
        } else {
                tower_ptr = &req->tower;
                req->tower_null = 0;
        }
        if (dcerpc_ptr_coder("Tower", dce, pdu, iov, offset, tower_ptr,
                             PTR_UNIQUE, epm_twr_STRUCT_coder)) {
                return -1;
        }
        return 0;
}

int
epm_MgmtDelete_rep_coder(char *name, struct dcerpc_context *dce,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov, int *offset,
                         void *ptr)
{
        struct epm_MgmtDelete_rep *rep = ptr;

        if (dcerpc_uint32_coder("Status", dce, pdu, iov, offset, &rep->status)) {
                return -1;
        }
        return 0;
}

/**********************
 * Tower helpers (C706 Appendix L encoding, little-endian counts)
 **********************/
static void
epm_put_le16(uint8_t *p, uint16_t v)
{
        p[0] = (uint8_t)(v & 0xff);
        p[1] = (uint8_t)((v >> 8) & 0xff);
}

static uint16_t
epm_get_le16(const uint8_t *p)
{
        return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static void
epm_put_be16(uint8_t *p, uint16_t v)
{
        p[0] = (uint8_t)((v >> 8) & 0xff);
        p[1] = (uint8_t)(v & 0xff);
}

static uint16_t
epm_get_be16(const uint8_t *p)
{
        return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* NDR mixed-endian UUID into 16 bytes */
static void
epm_put_uuid(uint8_t *p, const dcerpc_uuid_t *u)
{
        p[0] = (uint8_t)(u->v1 & 0xff);
        p[1] = (uint8_t)((u->v1 >> 8) & 0xff);
        p[2] = (uint8_t)((u->v1 >> 16) & 0xff);
        p[3] = (uint8_t)((u->v1 >> 24) & 0xff);
        epm_put_le16(p + 4, u->v2);
        epm_put_le16(p + 6, u->v3);
        memcpy(p + 8, u->v4, 8);
}

static size_t
epm_floor_uuid_size(void)
{
        /* lhs=19 (1+16+2), rhs=2 */
        return 2 + 19 + 2 + 2;
}

static size_t
epm_write_floor_uuid(uint8_t *p, const dcerpc_uuid_t *u,
                     uint16_t major, uint16_t minor)
{
        epm_put_le16(p, 19);
        p[2] = EPM_PROTOCOL_UUID;
        epm_put_uuid(p + 3, u);
        epm_put_le16(p + 19, major);
        epm_put_le16(p + 21, 2);
        epm_put_le16(p + 23, minor);
        return epm_floor_uuid_size();
}

static size_t
epm_write_floor_proto(uint8_t *p, uint8_t proto, uint16_t rhs_val)
{
        epm_put_le16(p, 1);
        p[2] = proto;
        epm_put_le16(p + 3, 2);
        epm_put_le16(p + 5, rhs_val);
        return 7;
}

static size_t
epm_write_floor_tcp(uint8_t *p, uint16_t port)
{
        epm_put_le16(p, 1);
        p[2] = EPM_PROTOCOL_TCP;
        epm_put_le16(p + 3, 2);
        epm_put_be16(p + 5, port);
        return 7;
}

static size_t
epm_write_floor_ip(uint8_t *p, uint32_t addr_be)
{
        epm_put_le16(p, 1);
        p[2] = EPM_PROTOCOL_IP;
        epm_put_le16(p + 3, 4);
        memcpy(p + 5, &addr_be, 4);
        return 9;
}

static size_t
epm_write_floor_string(uint8_t *p, uint8_t proto, const char *s)
{
        size_t len = s ? strlen(s) + 1 : 1;
        size_t i;

        epm_put_le16(p, 1);
        p[2] = proto;
        epm_put_le16(p + 3, (uint16_t)len);
        if (s) {
                memcpy(p + 5, s, len);
        } else {
                p[5] = 0;
        }
        (void)i;
        return 5 + len;
}

int
epm_build_tower_ncacn_np(const dcerpc_uuid_t *iface,
                         uint16_t vers_major, uint16_t vers_minor,
                         const char *host,
                         struct epm_twr_t *out)
{
        size_t host_len = host ? strlen(host) + 1 : 1;
        size_t total;
        uint8_t *buf;
        size_t o = 0;

        if (iface == NULL || out == NULL) {
                return -1;
        }
        /* 2 + floors: uuid, ndr, ncacn, smb/pipe, netbios */
        total = 2 + epm_floor_uuid_size() + epm_floor_uuid_size() +
                7 + (5 + 1) + (5 + host_len);
        buf = calloc(1, total);
        if (buf == NULL) {
                return -1;
        }
        epm_put_le16(buf, 5);
        o = 2;
        o += epm_write_floor_uuid(buf + o, iface, vers_major, vers_minor);
        o += epm_write_floor_uuid(buf + o, &ndr_transfer_uuid, 2, 0);
        o += epm_write_floor_proto(buf + o, EPM_PROTOCOL_NCACN, 0);
        o += epm_write_floor_string(buf + o, EPM_PROTOCOL_SMB, "");
        o += epm_write_floor_string(buf + o, EPM_PROTOCOL_NETBIOS,
                                    host ? host : "");
        out->tower_octet_string = buf;
        out->tower_length = (uint32_t)o;
        return 0;
}

int
epm_build_tower_ncacn_ip_tcp(const dcerpc_uuid_t *iface,
                             uint16_t vers_major, uint16_t vers_minor,
                             const char *ipv4, uint16_t port,
                             struct epm_twr_t *out)
{
        size_t total;
        uint8_t *buf;
        size_t o = 0;
        uint32_t addr = 0;

        if (iface == NULL || out == NULL) {
                return -1;
        }
        if (ipv4 && ipv4[0]) {
                if (inet_pton(AF_INET, ipv4, &addr) != 1) {
                        return -1;
                }
        }
        total = 2 + epm_floor_uuid_size() + epm_floor_uuid_size() + 7 + 7 + 9;
        buf = calloc(1, total);
        if (buf == NULL) {
                return -1;
        }
        epm_put_le16(buf, 5);
        o = 2;
        o += epm_write_floor_uuid(buf + o, iface, vers_major, vers_minor);
        o += epm_write_floor_uuid(buf + o, &ndr_transfer_uuid, 2, 0);
        o += epm_write_floor_proto(buf + o, EPM_PROTOCOL_NCACN, 0);
        o += epm_write_floor_tcp(buf + o, port);
        o += epm_write_floor_ip(buf + o, addr);
        out->tower_octet_string = buf;
        out->tower_length = (uint32_t)o;
        return 0;
}

void
epm_free_tower(struct epm_twr_t *twr)
{
        if (twr == NULL) {
                return;
        }
        free(twr->tower_octet_string);
        twr->tower_octet_string = NULL;
        twr->tower_length = 0;
}

/*
 * Walk floors: each floor is lhs_count(2) + lhs + rhs_count(2) + rhs
 */
static int
epm_tower_floor_at(const uint8_t *data, uint32_t len, int index,
                   const uint8_t **lhs, uint16_t *lhs_len,
                   const uint8_t **rhs, uint16_t *rhs_len)
{
        uint16_t nfloors;
        uint32_t o = 0;
        int i;

        if (len < 2) {
                return -1;
        }
        nfloors = epm_get_le16(data);
        o = 2;
        for (i = 0; i < nfloors; i++) {
                uint16_t lh, rh;

                if (o + 2 > len) {
                        return -1;
                }
                lh = epm_get_le16(data + o);
                o += 2;
                if (o + lh + 2 > len) {
                        return -1;
                }
                if (i == index) {
                        *lhs = data + o;
                        *lhs_len = lh;
                        o += lh;
                        rh = epm_get_le16(data + o);
                        o += 2;
                        if (o + rh > len) {
                                return -1;
                        }
                        *rhs = data + o;
                        *rhs_len = rh;
                        return 0;
                }
                o += lh;
                rh = epm_get_le16(data + o);
                o += 2 + rh;
        }
        return -1;
}

int
epm_tower_get_ncacn_np(const struct epm_twr_t *twr,
                       char **pipe_out, char **host_out)
{
        const uint8_t *lhs, *rhs;
        uint16_t lh, rh;
        char *pipe = NULL, *host = NULL;

        if (twr == NULL || twr->tower_octet_string == NULL) {
                return -1;
        }
        /* Floor 3 (0-based index 3): SMB / pipe name */
        if (epm_tower_floor_at(twr->tower_octet_string, twr->tower_length,
                               3, &lhs, &lh, &rhs, &rh)) {
                return -1;
        }
        if (lh < 1 || (lhs[0] != EPM_PROTOCOL_SMB &&
                       lhs[0] != EPM_PROTOCOL_NAMED_PIPE)) {
                return -1;
        }
        pipe = malloc(rh ? rh : 1);
        if (pipe == NULL) {
                return -1;
        }
        if (rh) {
                memcpy(pipe, rhs, rh);
                pipe[rh - 1] = '\0';
        } else {
                pipe[0] = '\0';
        }
        /* Floor 4: NetBIOS host */
        if (epm_tower_floor_at(twr->tower_octet_string, twr->tower_length,
                               4, &lhs, &lh, &rhs, &rh) == 0 &&
            lh >= 1 && lhs[0] == EPM_PROTOCOL_NETBIOS) {
                host = malloc(rh ? rh : 1);
                if (host == NULL) {
                        free(pipe);
                        return -1;
                }
                if (rh) {
                        memcpy(host, rhs, rh);
                        host[rh - 1] = '\0';
                } else {
                        host[0] = '\0';
                }
        }
        if (pipe_out) {
                *pipe_out = pipe;
        } else {
                free(pipe);
        }
        if (host_out) {
                *host_out = host;
        } else {
                free(host);
        }
        return 0;
}

int
epm_tower_get_ncacn_ip_tcp(const struct epm_twr_t *twr,
                           char **ipv4_out, uint16_t *port_out)
{
        const uint8_t *lhs, *rhs;
        uint16_t lh, rh;
        uint16_t port;
        char ipbuf[INET_ADDRSTRLEN];

        if (twr == NULL || twr->tower_octet_string == NULL) {
                return -1;
        }
        if (epm_tower_floor_at(twr->tower_octet_string, twr->tower_length,
                               3, &lhs, &lh, &rhs, &rh)) {
                return -1;
        }
        if (lh < 1 || lhs[0] != EPM_PROTOCOL_TCP || rh < 2) {
                return -1;
        }
        port = epm_get_be16(rhs);
        if (port_out) {
                *port_out = port;
        }
        if (epm_tower_floor_at(twr->tower_octet_string, twr->tower_length,
                               4, &lhs, &lh, &rhs, &rh)) {
                return -1;
        }
        if (lh < 1 || lhs[0] != EPM_PROTOCOL_IP || rh < 4) {
                return -1;
        }
        if (inet_ntop(AF_INET, rhs, ipbuf, sizeof(ipbuf)) == NULL) {
                return -1;
        }
        if (ipv4_out) {
                *ipv4_out = strdup(ipbuf);
                if (*ipv4_out == NULL) {
                        return -1;
                }
        }
        return 0;
}

struct dcerpc_procedure epm_procs[] = {
        {EPM_INSERT, "Insert",
         epm_Insert_req_coder, sizeof(struct epm_Insert_req),
         epm_Insert_rep_coder, sizeof(struct epm_Insert_rep),
        },
        {EPM_DELETE, "Delete",
         epm_Delete_req_coder, sizeof(struct epm_Delete_req),
         epm_Delete_rep_coder, sizeof(struct epm_Delete_rep),
        },
        {EPM_LOOKUP, "Lookup",
         epm_Lookup_req_coder, sizeof(struct epm_Lookup_req),
         epm_Lookup_rep_coder, sizeof(struct epm_Lookup_rep),
        },
        {EPM_MAP, "Map",
         epm_Map_req_coder, sizeof(struct epm_Map_req),
         epm_Map_rep_coder, sizeof(struct epm_Map_rep),
        },
        {EPM_LOOKUP_HANDLE_FREE, "LookupHandleFree",
         epm_LookupHandleFree_req_coder, sizeof(struct epm_LookupHandleFree_req),
         epm_LookupHandleFree_rep_coder, sizeof(struct epm_LookupHandleFree_rep),
        },
        {EPM_INQ_OBJECT, "InqObject",
         epm_InqObject_req_coder, sizeof(struct epm_InqObject_req),
         epm_InqObject_rep_coder, sizeof(struct epm_InqObject_rep),
        },
        {EPM_MGMT_DELETE, "MgmtDelete",
         epm_MgmtDelete_req_coder, sizeof(struct epm_MgmtDelete_req),
         epm_MgmtDelete_rep_coder, sizeof(struct epm_MgmtDelete_rep),
        },
        {-1, NULL, NULL, 0, NULL, 0}
};
