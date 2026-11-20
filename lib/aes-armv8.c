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
#include "aes-armv8.h"

#if SMB2_ARMV8_AES

#include <string.h>

#include "compat.h"

#define SMB2_ARMV8 __attribute__((target("+crypto")))

#if defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

int smb2_armv8_available(void)
{
#if defined(__APPLE__)
        return 1;
#elif defined(__linux__)
        static int known = -1;
        int v = __atomic_load_n(&known, __ATOMIC_RELAXED);

        if (v < 0) {
                v = (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
                __atomic_store_n(&known, v, __ATOMIC_RELAXED);
        }
        return v;
#else
        return 0;
#endif
}

/* AES-128 SubWord(RotWord(last column)) with no key-indexed loads. */
SMB2_ARMV8 void smb2_armv8_aes128_expand_key(const uint8_t key[16],
                                             struct smb2_aes128_keys *keys)
{
        /* After AESE's ShiftRows these lanes hold S(k13), S(k14),
         * S(k15), S(k12). Broadcast that word to all four columns. */
        static const uint8_t lanes[16] = {9,6,3,12, 9,6,3,12, 9,6,3,12, 9,6,3,12};
        static const uint8_t first_byte[16] = {255,0,0,0, 255,0,0,0, 255,0,0,0, 255,0,0,0};
        uint8x16_t zero = vdupq_n_u8(0);
        uint8x16_t rk = vld1q_u8(key);
        uint8_t rcon = 1;
        int round;

        vst1q_u8(keys->rk[0], rk);
        for (round = 1; round <= 10; round++) {
                uint8x16_t word = vqtbl1q_u8(vaeseq_u8(rk, zero), vld1q_u8(lanes));
                word = veorq_u8(word, vandq_u8(vdupq_n_u8(rcon), vld1q_u8(first_byte)));
                /* Prefix XOR of the four words of the old round key. */
                rk = veorq_u8(rk, vextq_u8(zero, rk, 12));
                rk = veorq_u8(rk, vextq_u8(zero, rk, 8));
                rk = veorq_u8(rk, word);
                vst1q_u8(keys->rk[round], rk);
                rcon = (uint8_t)((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0));
        }
}

typedef struct smb2_aes128_keys ccm_key;

SMB2_ARMV8 static inline void ccm_encrypt_block(const ccm_key *key, uint8_t in[16], uint8_t out[16])
{
        vst1q_u8(out, smb2_armv8_aes128_encrypt(vld1q_u8(in), key));
}

SMB2_ARMV8 static inline void ccm_mac_block(const ccm_key *key, const uint8_t b[16], uint8_t y[16])
{
        uint8x16_t block = veorq_u8(vld1q_u8(b), vld1q_u8(y));
        vst1q_u8(y, smb2_armv8_aes128_encrypt(block, key));
}

#define CCM_TARGET SMB2_ARMV8
#include "aes128ccm-private.h"

SMB2_ARMV8 int aes128ccm_armv8_encrypt(unsigned char *key,
                                       unsigned char *nonce, size_t nlen,
                                       unsigned char *aad, size_t alen,
                                       unsigned char *p, size_t plen,
                                       unsigned char *m, size_t mlen)
{
        struct smb2_aes128_keys keys;

        smb2_armv8_aes128_expand_key(key, &keys);
        return ccm_encrypt(&keys, nonce, nlen, aad, alen, p, plen, m, mlen);
}

SMB2_ARMV8 int aes128ccm_armv8_decrypt(unsigned char *key,
                                       unsigned char *nonce, size_t nlen,
                                       unsigned char *aad, size_t alen,
                                       unsigned char *p, size_t plen,
                                       unsigned char *m, size_t mlen)
{
        struct smb2_aes128_keys keys;

        smb2_armv8_aes128_expand_key(key, &keys);
        return ccm_decrypt(&keys, nonce, nlen, aad, alen, p, plen, m, mlen);
}

#endif /* SMB2_ARMV8_AES */
