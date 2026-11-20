/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
#ifndef _LIBSMB2_AES_ARMV8_H_
#define _LIBSMB2_AES_ARMV8_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * AES-128 using the ARMv8 Cryptography Extension instructions
 * (AESE/AESMC), the arm64 counterpart of the x86 AES-NI paths.
 */

/*
 * The intrinsics need an arm_neon.h that declares the crypto wrappers
 * even when the translation unit is not built with the extension, and a
 * compiler that lets a function switch it on with
 * __attribute__((target("+crypto"))).  Clang declares the wrappers
 * unconditionally (checking the target at the call site) since 16, and
 * GCC's arm_neon.h has declared them in pragma sections with the
 * per-function target attribute working since at least GCC 9.  Older
 * clangs hide the wrappers behind __ARM_FEATURE_CRYPTO, so there only a
 * translation unit already built for the extension qualifies.
 */
#if !defined(HAVE_OPENSSL) && defined(__aarch64__) && (defined(__ARM_FEATURE_CRYPTO) || \
    (defined(__clang__) && __clang_major__ >= 16) || \
    (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
#define SMB2_ARMV8_AES 1
#else
#define SMB2_ARMV8_AES 0
#endif

#if SMB2_ARMV8_AES
#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>

int smb2_armv8_available(void);

/* Eleven round keys in AESE convention. */
struct smb2_aes128_keys {
        uint8_t rk[11][16];
};

/*
 * AESE(V, K) is ShiftRows(SubBytes(V ^ K)): the round key is added
 * *before* SubBytes, so the standard FIPS-197 key schedule is used as
 * is — no InvMixColumns anywhere — and the sequence is nine
 * AESMC(AESE(b, rk[i])) rounds over rk[0..8], a final AESE with
 * rk[9] (the last round has no MixColumns), and one closing XOR with
 * rk[10].  The attribute lets it inline into callers' loops without
 * their whole translation unit being built for +crypto.
 */
static inline __attribute__((target("+crypto"))) uint8x16_t
smb2_armv8_aes128_encrypt(uint8x16_t b, const struct smb2_aes128_keys *keys)
{
        int i;

        for (i = 0; i < 9; i++) {
                b = vaesmcq_u8(vaeseq_u8(b, vld1q_u8(keys->rk[i])));
        }
        b = vaeseq_u8(b, vld1q_u8(keys->rk[9]));
        return veorq_u8(b, vld1q_u8(keys->rk[10]));
}

static inline void
smb2_armv8_aes128_encrypt_block(const uint8_t in[16],
                                const struct smb2_aes128_keys *keys,
                                uint8_t out[16])
{
        vst1q_u8(out, smb2_armv8_aes128_encrypt(vld1q_u8(in), keys));
}

void smb2_armv8_aes128_expand_key(const uint8_t key[16],
                                  struct smb2_aes128_keys *keys);

int aes128ccm_armv8_encrypt(unsigned char *key,
                            unsigned char *nonce, size_t nlen,
                            unsigned char *aad, size_t alen,
                            unsigned char *p, size_t plen,
                            unsigned char *m, size_t mlen);
int aes128ccm_armv8_decrypt(unsigned char *key,
                            unsigned char *nonce, size_t nlen,
                            unsigned char *aad, size_t alen,
                            unsigned char *p, size_t plen,
                            unsigned char *m, size_t mlen);

#endif /* SMB2_ARMV8_AES */
#endif /* _LIBSMB2_AES_ARMV8_H_ */
