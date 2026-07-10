/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2017 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   Portions of this code are copyright 2017 to Primary Data Inc.

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

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "compat.h"

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

#define DEC_VLEN(l) \
    do {                                                    \
        if (v.len < (l)) {                                  \
                smb2_set_error(smb2, "corrupted pdu");      \
                return NULL;                                \
        } else {                                            \
                v.len -= (l);                               \
        }                                                   \
    } while(0);

static struct smb2_sid *
decode_sid(struct smb2_context *smb2, void *memctx, struct smb2_iovec *v)
{
        struct smb2_sid *sid;
        uint8_t revision, sub_auth_count;
        int i;

        if (v->len < 8) {
                smb2_set_error(smb2, "SID must be at least 8 bytes");
                return NULL;
        }

        smb2_get_uint8(v, 0, &revision);
        if (revision != 1) {
                smb2_set_error(smb2, "can not decode sid with "
                               "revision %d", revision);
                return NULL;
        }
        smb2_get_uint8(v, 1, &sub_auth_count);

        if (v->len < 8 + sub_auth_count * sizeof(uint32_t)) {
                smb2_set_error(smb2, "SID is bigger than the buffer");
                return NULL;
        }

        sid = smb2_alloc_data(smb2, memctx,
                              offsetof(struct smb2_sid, sub_auth) +
                              sub_auth_count * sizeof(uint32_t));
        if (sid == NULL) {
                smb2_set_error(smb2, "failed to allocate sid.");
                return NULL;
        }

        sid->revision = revision;
        sid->sub_auth_count = sub_auth_count;
        memcpy(&sid->id_auth[0], &v->buf[2], SID_ID_AUTH_LEN);
        for (i = 0; i < sub_auth_count; i++) {
                smb2_get_uint32(v, 8 + i * sizeof(uint32_t),
                                &sid->sub_auth[i]);
        }

        v->len -= 8 + sub_auth_count * sizeof(uint32_t);
        v->buf += 8 + sub_auth_count * sizeof(uint32_t);

        return sid;
}

static struct smb2_ace *
decode_ace(struct smb2_context *smb2, void *memctx, struct smb2_iovec *vec)
{
        struct smb2_iovec v = *vec;
        uint8_t ace_type, ace_flags;
        uint16_t ace_size;
        struct smb2_ace *ace;

        if (v.len < 4) {
                smb2_set_error(smb2, "not enough data for ace header.");
                return NULL;
        }

        smb2_get_uint8(&v, 0, &ace_type);
        smb2_get_uint8(&v, 1, &ace_flags);
        smb2_get_uint16(&v, 2, &ace_size);

        ace = smb2_alloc_data(smb2, memctx, sizeof(struct smb2_ace));
        if (ace == NULL) {
                smb2_set_error(smb2, "failed to allocate ace.");
                return NULL;
        }

        ace->ace_type  = ace_type;
        ace->ace_flags = ace_flags;
        ace->ace_size  = ace_size;
        
        /* Skip past the header */
        if (ace_size < 4) {
                smb2_set_error(smb2, "not enough data for ace data.");
                return NULL;
        }
        if (v.len < ace_size) {
                smb2_set_error(smb2, "not enough data for ace data.");
                return NULL;
        }
        DEC_VLEN(4);
        v.buf = &v.buf[4];

        /* decode the content of the ace */
        /* TODO: have a default case where we just keep the raw blob */
        switch (ace_type) {
        case SMB2_ACCESS_ALLOWED_ACE_TYPE:
        case SMB2_ACCESS_DENIED_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_ACE_TYPE:
        case SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        case SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                smb2_get_uint32(&v, 0, &ace->mask);
                
                DEC_VLEN(4);
                v.buf = &v.buf[4];
                ace->sid = decode_sid(smb2, memctx, &v);
                break;
        case SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                if (v.len < 40) {
                        smb2_set_error(smb2, "not enough data for ace data.");
                        return NULL;
                }
                smb2_get_uint32(&v, 0, &ace->mask);

                DEC_VLEN(4);
                v.buf = &v.buf[4];
                smb2_get_uint32(&v, 0, &ace->flags);

                DEC_VLEN(4);
                v.buf = &v.buf[4];
                memcpy(ace->object_type, v.buf, SMB2_OBJECT_TYPE_SIZE);

                DEC_VLEN(SMB2_OBJECT_TYPE_SIZE);
                v.buf = &v.buf[SMB2_OBJECT_TYPE_SIZE];
                memcpy(ace->inherited_object_type, v.buf,
                       SMB2_OBJECT_TYPE_SIZE);

                DEC_VLEN(SMB2_OBJECT_TYPE_SIZE);
                v.buf = &v.buf[SMB2_OBJECT_TYPE_SIZE];
                ace->sid = decode_sid(smb2, memctx, &v);
                break;
        case SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        case SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                smb2_get_uint32(&v, 0, &ace->mask);

                if (v.len < 4) {
                        smb2_set_error(smb2, "not enough data for ace data.");
                        return NULL;
                }
                DEC_VLEN(4);
                v.buf = &v.buf[4];
                ace->sid = decode_sid(smb2, memctx, &v);

                ace->ad_len = v.len;
                ace->ad_data = smb2_alloc_data(smb2, memctx, ace->ad_len);
                if (ace->ad_data == NULL) {
                        return NULL;
                }
                memcpy(ace->ad_data, v.buf, v.len);
                break;
        default:
                ace->raw_len = v.len;
                ace->raw_data = smb2_alloc_data(smb2, memctx, ace->raw_len);
                if (ace->raw_data == NULL) {
                        return NULL;
                }
                memcpy(ace->raw_data, v.buf, v.len);
        }

        return ace;
}

static struct smb2_acl *
decode_acl(struct smb2_context *smb2, void *memctx, struct smb2_iovec *vec)
{
        struct smb2_iovec v = *vec;
        struct smb2_acl *acl;
        uint8_t revision;
        uint16_t acl_size, ace_count;
        int i;

        if (v.len < 8) {
                smb2_set_error(smb2, "not enough data for acl header.");
                return NULL;
        }

        smb2_get_uint8(&v, 0, &revision);
        smb2_get_uint16(&v, 2, &acl_size);
        smb2_get_uint16(&v, 4, &ace_count);

        switch (revision) {
        case SMB2_ACL_REVISION:
        case SMB2_ACL_REVISION_DS:
                break;
        default:
                smb2_set_error(smb2, "can not decode acl with "
                               "revision %d", revision);
                return NULL;
        }
        if (v.len > acl_size) {
                v.len = acl_size;
        }
        if (v.len < acl_size) {
                smb2_set_error(smb2, "not enough data for acl");
                return NULL;
        }

        acl = smb2_alloc_data(smb2, memctx, sizeof(struct smb2_acl));
        if (acl == NULL) {
                smb2_set_error(smb2, "failed to allocate acl.");
                return NULL;
        }

        acl->revision  = revision;
        acl->ace_count = ace_count;

        /* Skip past the ACL header to the first ace. */
        DEC_VLEN(8);
        v.buf = &v.buf[8];

        for (i = 0; i < ace_count; i++) {
                struct smb2_ace *ace = decode_ace(smb2, memctx, &v);

                if (ace == NULL) {
                        smb2_set_error(smb2, "failed to decode ace # %d: %s",
                                       i, smb2_get_error(smb2));
                        return NULL;
                }
                /* skip to the next ace */
                if (ace->ace_size > v.len) {
                        smb2_set_error(smb2, "not enough data for ace %s",
                                       smb2_get_error(smb2));
                        return NULL;
                }
                DEC_VLEN(ace->ace_size);
                v.buf = &v.buf[ace->ace_size];

                SMB2_LIST_ADD_END(&acl->aces, ace);
        }

        return acl;
}

int
smb2_decode_security_descriptor(struct smb2_context *smb2,
                                void *memctx,
                                struct smb2_security_descriptor *sd,
                                struct smb2_iovec *vec)
{
        struct smb2_iovec v;
        uint32_t offset_owner, offset_group, offset_sacl, offset_dacl;

        if (vec->len < 20) {
                return -1;
        }

        v.buf = &vec->buf[0];
        v.len = 20;

        smb2_get_uint8(&v, 0, &sd->revision);
        if (sd->revision != 1) {
                smb2_set_error(smb2, "can not decode security descriptor with "
                               "revision %d", sd->revision);
                return -1;
        }
        smb2_get_uint16(&v, 2, &sd->control);

        smb2_get_uint32(&v, 4, &offset_owner);
        smb2_get_uint32(&v, 8, &offset_group);
        smb2_get_uint32(&v, 12, &offset_sacl);
        smb2_get_uint32(&v, 16, &offset_dacl);

        /* Owner */
        if (offset_owner > 0 && offset_owner < vec->len &&
            vec->len - offset_owner >= 2 + SID_ID_AUTH_LEN) {
                v.buf = &vec->buf[offset_owner];
                v.len = vec->len - offset_owner;

                sd->owner = decode_sid(smb2, memctx, &v);
                if (sd->owner == NULL) {
                        smb2_set_error(smb2, "failed to decode owner sid: %s",
                                       smb2_get_error(smb2));
                        return -1;
                }
        }

        /* Group */
        if (offset_group > 0 && offset_group < vec->len &&
            vec->len - offset_group >= 2 + SID_ID_AUTH_LEN) {
                v.buf = &vec->buf[offset_group];
                v.len = vec->len - offset_group;

                sd->group = decode_sid(smb2, sd, &v);
                if (sd->group == NULL) {
                        smb2_set_error(smb2, "failed to decode group sid: %s",
                                       smb2_get_error(smb2));
                        return -1;
                }
        }

        /* DACL */
        if (offset_dacl > 0 && offset_dacl < vec->len &&
            vec->len - offset_dacl >= 8) {
                v.buf = &vec->buf[offset_dacl];
                v.len = vec->len - offset_dacl;

                sd->dacl = decode_acl(smb2, sd, &v);
                if (sd->dacl == NULL) {
                        smb2_set_error(smb2, "failed to decode dacl: %s",
                                       smb2_get_error(smb2));
                        return -1;
                }
        }

        return 0;
}

static int
smb2_sid_size(struct smb2_sid *sid)
{
        if (sid == NULL) {
                return 0;
        }
        return 8 + sid->sub_auth_count * 4;
}

static int
smb2_ace_size(struct smb2_ace *ace)
{
        switch (ace->ace_type) {
        case SMB2_ACCESS_ALLOWED_ACE_TYPE:
        case SMB2_ACCESS_DENIED_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_ACE_TYPE:
        case SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        case SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                return 4 + 4 + smb2_sid_size(ace->sid);
        case SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                return 4 + 4 + 4 + SMB2_OBJECT_TYPE_SIZE * 2 +
                        smb2_sid_size(ace->sid);
        case SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        case SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                return 4 + 4 + smb2_sid_size(ace->sid) + (int)ace->ad_len;
        default:
                return 4 + (int)ace->raw_len;
        }
}

static int
smb2_acl_size(struct smb2_acl *acl)
{
        struct smb2_ace *ace;
        int size = 8;

        for (ace = acl->aces; ace; ace = ace->next) {
                size += smb2_ace_size(ace);
        }
        return size;
}

int
smb2_security_descriptor_size(struct smb2_security_descriptor *sd)
{
        int size = 20;

        size += smb2_sid_size(sd->owner);
        size += smb2_sid_size(sd->group);
        if (sd->dacl) {
                size += smb2_acl_size(sd->dacl);
        }
        return size;
}

static void
encode_sid(struct smb2_sid *sid, struct smb2_iovec *iov, int offset)
{
        int i;

        smb2_set_uint8(iov, offset, sid->revision);
        smb2_set_uint8(iov, offset + 1, sid->sub_auth_count);
        memcpy(iov->buf + offset + 2, sid->id_auth, SID_ID_AUTH_LEN);
        for (i = 0; i < sid->sub_auth_count; i++) {
                smb2_set_uint32(iov, offset + 8 + i * 4, sid->sub_auth[i]);
        }
}

static int
encode_ace(struct smb2_context *smb2, struct smb2_ace *ace,
          struct smb2_iovec *iov, int offset)
{
        int size = smb2_ace_size(ace);

        smb2_set_uint8(iov, offset, ace->ace_type);
        smb2_set_uint8(iov, offset + 1, ace->ace_flags);
        smb2_set_uint16(iov, offset + 2, size);

        switch (ace->ace_type) {
        case SMB2_ACCESS_ALLOWED_ACE_TYPE:
        case SMB2_ACCESS_DENIED_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_ACE_TYPE:
        case SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        case SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                if (ace->sid == NULL) {
                        smb2_set_error(smb2, "ace is missing a sid");
                        return -1;
                }
                smb2_set_uint32(iov, offset + 4, ace->mask);
                encode_sid(ace->sid, iov, offset + 8);
                break;
        case SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                if (ace->sid == NULL) {
                        smb2_set_error(smb2, "ace is missing a sid");
                        return -1;
                }
                smb2_set_uint32(iov, offset + 4, ace->mask);
                smb2_set_uint32(iov, offset + 8, ace->flags);
                memcpy(iov->buf + offset + 12, ace->object_type,
                       SMB2_OBJECT_TYPE_SIZE);
                memcpy(iov->buf + offset + 12 + SMB2_OBJECT_TYPE_SIZE,
                       ace->inherited_object_type, SMB2_OBJECT_TYPE_SIZE);
                encode_sid(ace->sid, iov,
                          offset + 12 + SMB2_OBJECT_TYPE_SIZE * 2);
                break;
        case SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        case SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                if (ace->sid == NULL) {
                        smb2_set_error(smb2, "ace is missing a sid");
                        return -1;
                }
                smb2_set_uint32(iov, offset + 4, ace->mask);
                encode_sid(ace->sid, iov, offset + 8);
                if (ace->ad_len) {
                        memcpy(iov->buf + offset + 8 +
                               smb2_sid_size(ace->sid),
                               ace->ad_data, ace->ad_len);
                }
                break;
        default:
                if (ace->raw_len) {
                        memcpy(iov->buf + offset + 4, ace->raw_data,
                               ace->raw_len);
                }
                break;
        }

        return size;
}

static int
encode_acl(struct smb2_context *smb2, struct smb2_acl *acl,
          struct smb2_iovec *iov, int offset)
{
        struct smb2_ace *ace;
        int pos = offset + 8;

        smb2_set_uint8(iov, offset, acl->revision);
        smb2_set_uint8(iov, offset + 1, 0); /* Sbz1 */
        smb2_set_uint16(iov, offset + 2, smb2_acl_size(acl));
        smb2_set_uint16(iov, offset + 4, acl->ace_count);
        smb2_set_uint16(iov, offset + 6, 0); /* Sbz2 */

        for (ace = acl->aces; ace; ace = ace->next) {
                int ace_size = encode_ace(smb2, ace, iov, pos);

                if (ace_size < 0) {
                        return -1;
                }
                pos += ace_size;
        }

        return 0;
}

int
smb2_encode_security_descriptor(struct smb2_context *smb2,
                                struct smb2_security_descriptor *sd,
                                struct smb2_iovec *vec)
{
        int pos = 20;
        uint32_t offset_owner = 0, offset_group = 0, offset_dacl = 0;

        smb2_set_uint8(vec, 0, sd->revision ? sd->revision : 1);
        smb2_set_uint8(vec, 1, 0); /* Sbz1 */
        smb2_set_uint16(vec, 2, sd->control | SMB2_SD_CONTROL_SR);

        if (sd->owner) {
                offset_owner = pos;
                encode_sid(sd->owner, vec, pos);
                pos += smb2_sid_size(sd->owner);
        }
        if (sd->group) {
                offset_group = pos;
                encode_sid(sd->group, vec, pos);
                pos += smb2_sid_size(sd->group);
        }
        if (sd->dacl) {
                offset_dacl = pos;
                if (encode_acl(smb2, sd->dacl, vec, pos) < 0) {
                        smb2_set_error(smb2, "failed to encode dacl: %s",
                                       smb2_get_error(smb2));
                        return -1;
                }
                pos += smb2_acl_size(sd->dacl);
        }

        smb2_set_uint32(vec, 4, offset_owner);
        smb2_set_uint32(vec, 8, offset_group);
        smb2_set_uint32(vec, 12, 0); /* Sacl: not supported */
        smb2_set_uint32(vec, 16, offset_dacl);

        return 0;
}
