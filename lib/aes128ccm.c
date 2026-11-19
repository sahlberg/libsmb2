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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif 

#include <stdio.h>
#include <string.h>

#include "compat.h"

#include "aes.h"
#include "aes128ccm.h"

#ifndef HAVE_OPENSSL

static void aes_ccm_generate_b0(unsigned char *nonce, size_t nlen,
                                size_t alen, size_t plen, size_t mlen,
                                unsigned char *buf)
{
        unsigned char flags = (unsigned char)(((mlen - 2) / 2) << 3);

        ccm_format_block(buf, nonce, nlen, flags | (alen ? 0x40 : 0), plen);
}

static inline void bxory(unsigned char *b, unsigned char *y, size_t num)
{
        int i;

        for(i = 0; i < (int)num; i++) {
                b[i] = b[i] ^ y[i];
        }
}

static void ccm_generate_T(unsigned char *key,
                           unsigned char *nonce, size_t nlen,
                           unsigned char *aad, size_t alen,
                           unsigned char *p, size_t plen,
                           unsigned char *m, size_t mlen)
{
        unsigned char b[16] _U_, y[16]_U_;
        size_t l;

        aes_ccm_generate_b0(nonce, nlen, alen, plen, mlen, &b[0]);
        AES128_ECB_encrypt(b, key, y);

        /* Create Aad */
        if (alen) {
                size_t prefix = ccm_encode_aad_length(b, alen);

                l = alen < 16 - prefix ? alen : 16 - prefix;
                memcpy(b + prefix, aad, l);
                memset(b + prefix + l, 0, 16 - prefix - l);
                aad  += l;
                alen -= l;

                bxory(b, y, 16);
                AES128_ECB_encrypt(b, key, y);

                while (alen) {
                        memset(b, 0, 16);
                        l = (alen > 16) ? 16 : alen;
                        memcpy(b, aad, l);
                        aad  += l;
                        alen -= l;

                        bxory(b, y, 16);
                        AES128_ECB_encrypt(b, key, y);
                }
        }

        /* Create Payload */
        while (plen) {
                memset(b, 0, 16);
                l = (plen > 16) ? 16 : plen;
                memcpy(b, p, l);
                p    += l;
                plen -= l;

                bxory(b, y, 16);
                AES128_ECB_encrypt(b, key, y);
        }

        memcpy(m, y, mlen);
}

static void ccm_generate_s(unsigned char *key, unsigned char *nonce, size_t nlen,
                           uint64_t counter, unsigned char *s)
{
        ccm_format_block(s, nonce, nlen, 0, counter);

        AES128_ECB_encrypt(s, key, s);
}

static void aes_ccm_crypt(unsigned char *key,
                          unsigned char *nonce, size_t nlen,
                          unsigned char *p, size_t plen)
{
        uint64_t counter = 1;
        size_t l;
        unsigned char s[16] _U_;

        while (plen) {
                l = (plen > 16) ? 16 : plen;
                ccm_generate_s(key, nonce, nlen, counter, &s[0]);
                bxory(p, &s[0], l);

                counter++;
                p += l;
                plen -= l;
        }
}

int aes128ccm_encrypt(unsigned char *key,
                       unsigned char *nonce, size_t nlen,
                       unsigned char *aad, size_t alen,
                       unsigned char *p, size_t plen,
                       unsigned char *m, size_t mlen)
{
        unsigned char s[16] _U_;

        if (!ccm_valid_lengths(nlen, plen, mlen)) {
                return -1;
        }
        ccm_generate_T(key, nonce, nlen, aad, alen, p, plen, m, mlen);
        ccm_generate_s(key, nonce, nlen, 0, &s[0]);
        bxory(m, &s[0], mlen);

        aes_ccm_crypt(key, nonce, nlen, p, plen);

        return 0;
}

int aes128ccm_decrypt(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
        unsigned char s[16] _U_;
        unsigned char tmp[16];

        if (!ccm_valid_lengths(nlen, plen, mlen)) {
                return -1;
        }
        aes_ccm_crypt(key, nonce, nlen, p, plen);

        ccm_generate_T(key, nonce, nlen, aad, alen, p, plen, tmp, mlen);
        ccm_generate_s(key, nonce, nlen, 0, &s[0]);
        bxory(tmp, &s[0], mlen);

        return memcmp(tmp, m, mlen);
}

#else /* HAVE_OPENSSL */

#include <limits.h>
#include <openssl/evp.h>

static int aes128ccm_openssl(int enc, unsigned char *key,
                             unsigned char *nonce, size_t nlen,
                             unsigned char *aad, size_t alen,
                             unsigned char *p, size_t plen,
                             unsigned char *m, size_t mlen)
{
        EVP_CIPHER_CTX *ctx;
        int outl, rc = -1;

        if (plen > INT_MAX || alen > INT_MAX) {
                return -1;
        }
        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
                return -1;
        }
        if (EVP_CipherInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL, enc) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nlen, NULL) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)mlen, enc ? NULL : m) != 1 ||
            EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, enc) != 1 ||
            EVP_CipherUpdate(ctx, NULL, &outl, NULL, (int)plen) != 1 ||
            EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)alen) != 1 ||
            EVP_CipherUpdate(ctx, p, &outl, p, (int)plen) != 1) {
                goto out;
        }
        if (enc && (EVP_CipherFinal_ex(ctx, p + outl, &outl) != 1 ||
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)mlen, m) != 1)) {
                goto out;
        }
        rc = 0;
 out:
        EVP_CIPHER_CTX_free(ctx);
        return rc;
}

int aes128ccm_encrypt(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
        return aes128ccm_openssl(1, key, nonce, nlen, aad, alen, p, plen, m, mlen);
}

int aes128ccm_decrypt(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
        return aes128ccm_openssl(0, key, nonce, nlen, aad, alen, p, plen, m, mlen);
}

#endif /* HAVE_OPENSSL */
