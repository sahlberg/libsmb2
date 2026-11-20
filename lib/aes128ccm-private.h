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
/* Each backend provides its AES block and CBC-MAC operations and target attribute.
 * Keeping the block operation visible here lets the compiler inline each AES round. */
#ifndef LIBSMB2_AES128CCM_PRIVATE_H
#define LIBSMB2_AES128CCM_PRIVATE_H

#include "portable-endian.h"

CCM_TARGET static inline void
aes_ccm_generate_b0(unsigned char *nonce, size_t nlen,
                    size_t alen, size_t plen, size_t mlen,
                    unsigned char *buf)
{
        uint32_t len;

        memset(buf, 0, 16);
        if (alen) {
                buf[0] |= 0x40;                   /* Adata */
        }
        buf[0] |= (((mlen - 2) / 2) << 3) & 0x38; /* M' */
        buf[0] |= (15 - nlen - 1) & 0x07;         /* L' */

        len = htobe32((uint32_t)plen);
        memcpy(&buf[12], &len, 4);
        memcpy(&buf[1], nonce, nlen);
}

CCM_TARGET static inline void
bxory(unsigned char *b, unsigned char *y, size_t num)
{
        int i;

        for (i = 0; i < (int)num; i++) {
                b[i] = b[i] ^ y[i];
        }
}

CCM_TARGET static inline void
ccm_generate_T(const ccm_key *key,
               unsigned char *nonce, size_t nlen,
               unsigned char *aad, size_t alen,
               unsigned char *p, size_t plen,
               unsigned char *m, size_t mlen)
{
        unsigned char b[16], y[16];
        uint16_t l;

        aes_ccm_generate_b0(nonce, nlen, alen, plen, mlen, &b[0]);
        ccm_encrypt_block(key, b, y);

        /* Create Aad */
        if (alen) {
                /* First block */
                memset(b, 0, 16);
                l = htobe16((uint16_t)alen);
                memcpy(b, &l, 2);

                l = (alen > 14) ? 14 : (uint16_t)alen;
                memcpy(&b[2], aad, l);
                aad  += l;
                alen -= l;

                ccm_mac_block(key, b, y);

                while (alen) {
                        memset(b, 0, 16);
                        l = (alen > 16) ? 16 : (uint16_t)alen;
                        memcpy(b, aad, l);
                        aad  += l;
                        alen -= l;

                        ccm_mac_block(key, b, y);
                }
        }

        while (plen >= sizeof(b)) {
                ccm_mac_block(key, p, y);
                p += sizeof(b);
                plen -= sizeof(b);
        }
        if (plen) {
                memset(b, 0, sizeof(b));
                memcpy(b, p, plen);
                ccm_mac_block(key, b, y);
        }

        memcpy(m, y, mlen);
}

CCM_TARGET static inline void
ccm_generate_s(const ccm_key *key, unsigned char *nonce, size_t nlen,
               int i, unsigned char *s)
{
        uint32_t l;

        memset(s, 0, 16);
        s[0] |= (15 - nlen - 1) & 0x07;

        l = htobe32(i);
        memcpy(&s[12], &l, 4);

        memcpy(&s[1], nonce, nlen);

        ccm_encrypt_block(key, s, s);
}

CCM_TARGET static inline void
aes_ccm_crypt(const ccm_key *key,
              unsigned char *nonce, size_t nlen,
              unsigned char *p, size_t plen)
{
        int j;
        size_t l;
        unsigned char s[16];

        j = 0;
        while (plen) {
                l = (plen > 16) ? 16 : plen;
                ccm_generate_s(key, nonce, nlen, j + 1, &s[0]);
                bxory(&p[j * 16], &s[0], l);

                j++;
                plen -= l;
        }
}

CCM_TARGET static inline int
ccm_encrypt(const ccm_key *key,
            unsigned char *nonce, size_t nlen,
            unsigned char *aad, size_t alen,
            unsigned char *p, size_t plen,
            unsigned char *m, size_t mlen)
{
        unsigned char s[16];

        ccm_generate_T(key, nonce, nlen, aad, alen, p, plen, m, mlen);
        ccm_generate_s(key, nonce, nlen, 0, &s[0]);
        bxory(m, &s[0], mlen);

        aes_ccm_crypt(key, nonce, nlen, p, plen);

        return 0;
}

CCM_TARGET static inline int
ccm_decrypt(const ccm_key *key,
            unsigned char *nonce, size_t nlen,
            unsigned char *aad, size_t alen,
            unsigned char *p, size_t plen,
            unsigned char *m, size_t mlen)
{
        unsigned char s[16];
        unsigned char tmp[16];

        aes_ccm_crypt(key, nonce, nlen, p, plen);

        ccm_generate_T(key, nonce, nlen, aad, alen, p, plen, tmp, mlen);
        ccm_generate_s(key, nonce, nlen, 0, &s[0]);
        bxory(tmp, &s[0], mlen);

        return memcmp(tmp, m, mlen);
}

#endif
