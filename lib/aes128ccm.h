/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2019 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
#ifndef LIBSMB2_AES128CCM_H
#define LIBSMB2_AES128CCM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The nonce leaves L = 15 - nlen bytes for a length or block counter. */
static inline int ccm_valid_lengths(size_t nlen, size_t plen, size_t mlen)
{
        size_t width;

        if (nlen < 7 || nlen > 13 || mlen < 4 || mlen > 16 || (mlen & 1)) {
                return 0;
        }
        width = 15 - nlen;
        return width >= sizeof(plen) || (plen >> (width * 8)) == 0;
}

static inline void ccm_format_block(unsigned char block[16], const unsigned char *nonce,
                                    size_t nlen, unsigned char flags, uint64_t value)
{
        size_t i;

        block[0] = flags | (unsigned char)(14 - nlen);
        memcpy(block + 1, nonce, nlen);
        for (i = 16; i > 1 + nlen; i--) {
                block[i - 1] = (unsigned char)value;
                value >>= 8;
        }
}

/* Prefix the first AAD block with its length as specified by RFC 3610 section 2.2. */
static inline size_t ccm_encode_aad_length(unsigned char *buf, uint64_t alen)
{
        size_t end, start = 0, pos;

        if (alen < 0xff00) {
                end = 2;
        } else {
                buf[0] = 0xff;
                buf[1] = alen <= UINT32_MAX ? 0xfe : 0xff;
                start = 2;
                end = alen <= UINT32_MAX ? 6 : 10;
        }
        for (pos = end; pos > start; pos--) {
                buf[pos - 1] = (unsigned char)alen;
                alen >>= 8;
        }
        return end;
}

int aes128ccm_encrypt(unsigned char *key,
		       unsigned char *nonce, size_t nlen,
		       unsigned char *aad, size_t alen,
		       unsigned char *p, size_t plen,
		       unsigned char *m, size_t mlen);

int aes128ccm_decrypt(unsigned char *key,
		      unsigned char *nonce, size_t nlen,
		      unsigned char *aad, size_t alen,
		      unsigned char *p, size_t plen,
		      unsigned char *m, size_t mlen);

#endif
