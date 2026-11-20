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
#include "aes-armv8.h"

#ifndef HAVE_OPENSSL

typedef uint8_t ccm_key;

static inline void ccm_encrypt_block(const ccm_key *key, uint8_t in[16], uint8_t out[16])
{
        AES128_ECB_encrypt(in, key, out);
}

static inline void ccm_mac_block(const ccm_key *key, const uint8_t b[16], uint8_t y[16])
{
        unsigned i;

        for (i = 0; i < 16; i++) {
                y[i] ^= b[i];
        }
        AES128_ECB_encrypt(y, key, y);
}

#define CCM_TARGET
#include "aes128ccm-private.h"

int aes128ccm_encrypt(unsigned char *key,
                       unsigned char *nonce, size_t nlen,
                       unsigned char *aad, size_t alen,
                       unsigned char *p, size_t plen,
                       unsigned char *m, size_t mlen)
{
#if SMB2_ARMV8_AES
        if (smb2_armv8_available()) {
                return aes128ccm_armv8_encrypt(key, nonce, nlen, aad, alen, p, plen, m, mlen);
        }
#endif
        return ccm_encrypt(key, nonce, nlen, aad, alen, p, plen, m, mlen);
}

int aes128ccm_decrypt(unsigned char *key,
                      unsigned char *nonce, size_t nlen,
                      unsigned char *aad, size_t alen,
                      unsigned char *p, size_t plen,
                      unsigned char *m, size_t mlen)
{
#if SMB2_ARMV8_AES
        if (smb2_armv8_available()) {
                return aes128ccm_armv8_decrypt(key, nonce, nlen, aad, alen, p, plen, m, mlen);
        }
#endif
        return ccm_decrypt(key, nonce, nlen, aad, alen, p, plen, m, mlen);
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
