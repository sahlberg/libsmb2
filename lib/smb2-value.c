/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2025 by André Guilherme <andregui17@outlook.com>

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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "compat.h"

#include "portable-endian.h"

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"
#include "smb3-seal.h"
#include "smb2-signing.h"
#include "smb2-process.h"

int
smb2_set_uint8(struct smb2_iovec *iov, int offset, uint8_t value)
{
        if (offset + sizeof(uint8_t) > iov->len) {
                return -1;
        }
        iov->buf[offset] = value;
        return 0;
}

int
smb2_set_uint16(struct smb2_iovec *iov, int offset, uint16_t value)
{
        if (offset + sizeof(uint16_t) > iov->len) {
                return -1;
        }
        *(uint16_t *)(void *)(iov->buf + offset) = htole16(value);
        return 0;
}

int
smb2_set_uint32(struct smb2_iovec *iov, int offset, uint32_t value)
{
        if (offset + sizeof(uint32_t) > iov->len) {
                return -1;
        }
        *(uint32_t *)(void *)(iov->buf + offset) = htole32(value);
        return 0;
}

int
smb2_set_uint64(struct smb2_iovec *iov, int offset, uint64_t value)
{
        if (offset + sizeof(uint64_t) > iov->len) {
                return -1;
        }
        value = htole64(value);
        memcpy(iov->buf + offset, &value, 8);
        return 0;
}

int
smb2_get_uint8(struct smb2_iovec *iov, int offset, uint8_t *value)
{
        if (offset + sizeof(uint8_t) > iov->len) {
                return -1;
        }
        *value = iov->buf[offset];
        return 0;
}

int
smb2_get_uint16(struct smb2_iovec *iov, int offset, uint16_t *value)
{
        uint16_t tmp;

        if (offset + sizeof(uint16_t) > iov->len) {
                return -1;
        }
        memcpy(&tmp, iov->buf + offset, sizeof(uint16_t));
        *value = le16toh(tmp);
        return 0;
}

int
smb2_get_uint32(struct smb2_iovec *iov, int offset, uint32_t *value)
{
        uint32_t tmp;

        if (offset + sizeof(uint32_t) > iov->len) {
                return -1;
        }
        memcpy(&tmp, iov->buf + offset, sizeof(uint32_t));
        *value = le32toh(tmp);
        return 0;
}

int
smb2_get_uint64(struct smb2_iovec *iov, int offset, uint64_t *value)
{
        uint64_t tmp;

        if (offset + sizeof(uint64_t) > iov->len) {
                return -1;
        }
        memcpy(&tmp, iov->buf + offset, sizeof(uint64_t));
        *value = le64toh(tmp);
        return 0;
}