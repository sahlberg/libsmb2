/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 * AES Netlogon secure channel. MD4, SHA-256, HMAC-SHA256 and AES-128
 * live here so a build without libsmb2 can use them. The names are
 * internal; libsmb2 has its own copies under different names.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dcerpc/schannel.h>
#include "dcerpc-private.h"

struct dcerpc_schannel {
        uint8_t session_key[16];
        uint8_t client_credential[8];
        uint8_t server_credential[8];
        /* Running authenticator seed. Starts as the client credential. */
        uint8_t seed[8];
        /*
         * One sequence number for the channel, as Samba keeps it: taken
         * by every message sent and every message received, so a reply
         * carries the number after its request's (and each fragment
         * its own).
         */
        uint64_t seq;
        /*
         * A check of something the server sent failed. The channel can
         * no longer be trusted (and a forger would otherwise get any
         * number of tries at the same sequence number or seed), so every
         * call fails from then on.
         */
        int failed;
        /*
         * The server's credential has been checked, and these are the
         * flags it negotiated; nothing else works before that.
         */
        int verified;
        uint32_t negotiated_flags;
};

/*
 * Clear memory that held a key, a password or plaintext. Through a
 * volatile pointer, so the compiler can not drop it as a dead store
 * before free() or the end of a function, as it may a memset().
 */
static void
wipe(void *p, size_t n)
{
        volatile uint8_t *v = p;

        while (n--) {
                *v++ = 0;
        }
}

/* ---------------------------------------------------------------- AES */

static const uint8_t aes_sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t aes_rcon[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t
xtime(uint8_t x)
{
        return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

/* 11 round keys of 16 bytes, AES-128. */
static void
aes128_expand(const uint8_t key[16], uint8_t rk[11][16])
{
        uint8_t t[4];
        int i, r;

        memcpy(rk[0], key, 16);
        for (r = 1; r <= 10; r++) {
                memcpy(t, rk[r - 1] + 12, 4);
                {
                        uint8_t tmp = t[0];

                        t[0] = aes_sbox[t[1]] ^ aes_rcon[r - 1];
                        t[1] = aes_sbox[t[2]];
                        t[2] = aes_sbox[t[3]];
                        t[3] = aes_sbox[tmp];
                }
                for (i = 0; i < 4; i++) {
                        rk[r][i] = rk[r - 1][i] ^ t[i];
                }
                for (i = 4; i < 16; i++) {
                        rk[r][i] = rk[r - 1][i] ^ rk[r][i - 4];
                }
        }
}

static void
aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16],
                     uint8_t out[16])
{
        uint8_t rk[11][16];
        uint8_t s[16], t[16];
        int r, c, i;

        aes128_expand(key, rk);
        for (i = 0; i < 16; i++) {
                s[i] = in[i] ^ rk[0][i];
        }
        for (r = 1; r <= 10; r++) {
                for (i = 0; i < 16; i++) {
                        s[i] = aes_sbox[s[i]];
                }
                /* ShiftRows. State is column-major: index = row + 4*col. */
                memcpy(t, s, 16);
                for (c = 0; c < 4; c++) {
                        s[1 + 4 * c] = t[1 + 4 * ((c + 1) & 3)];
                        s[2 + 4 * c] = t[2 + 4 * ((c + 2) & 3)];
                        s[3 + 4 * c] = t[3 + 4 * ((c + 3) & 3)];
                }
                if (r != 10) {
                        for (c = 0; c < 4; c++) {
                                uint8_t a0 = s[4 * c];
                                uint8_t a1 = s[4 * c + 1];
                                uint8_t a2 = s[4 * c + 2];
                                uint8_t a3 = s[4 * c + 3];

                                t[4 * c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
                                t[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
                                t[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
                                t[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
                        }
                        memcpy(s, t, 16);
                }
                for (i = 0; i < 16; i++) {
                        s[i] ^= rk[r][i];
                }
        }
        memcpy(out, s, 16);
        /* rk[0] is the key itself */
        wipe(rk, sizeof(rk));
        wipe(s, sizeof(s));
        wipe(t, sizeof(t));
}

/* AES-128-CFB8. enc is non-zero to encrypt. iv is updated. */
static void
aes_cfb8(const uint8_t key[16], uint8_t iv[16],
         const uint8_t *in, uint8_t *out, size_t n, int enc)
{
        size_t i;

        for (i = 0; i < n; i++) {
                uint8_t block[16];
                uint8_t ct;

                aes128_encrypt_block(key, iv, block);
                if (enc) {
                        ct = in[i] ^ block[0];
                        out[i] = ct;
                } else {
                        ct = in[i];
                        out[i] = ct ^ block[0];
                }
                memmove(iv, iv + 1, 15);
                iv[15] = ct;
        }
}

static void
aes_cfb8_iv(const uint8_t key[16], const uint8_t iv0[16],
            const uint8_t *in, uint8_t *out, size_t n, int enc)
{
        uint8_t iv[16];

        memcpy(iv, iv0, 16);
        aes_cfb8(key, iv, in, out, n, enc);
}

/* ---------------------------------------------------------------- MD4 */

static uint32_t
md4_rol(uint32_t x, int n)
{
        return (x << n) | (x >> (32 - n));
}

static int
md4(const uint8_t *msg, size_t len, uint8_t out[16])
{
        uint32_t h0 = 0x67452301, h1 = 0xefcdab89;
        uint32_t h2 = 0x98badcfe, h3 = 0x10325476;
        size_t nblocks, i, b;
        uint8_t *buf;
        uint64_t bits = (uint64_t)len * 8;

        /* len + 1 + pad + 8, pad so the total is a multiple of 64. */
        nblocks = ((len + 8) / 64) + 1;
        buf = calloc(nblocks, 64);
        if (buf == NULL) {
                return -1;
        }
        memcpy(buf, msg, len);
        buf[len] = 0x80;
        for (i = 0; i < 8; i++) {
                buf[nblocks * 64 - 8 + i] = (uint8_t)(bits >> (8 * i));
        }
        for (b = 0; b < nblocks; b++) {
                uint32_t w[16], a, c, d, e;
                const uint8_t *bp = buf + b * 64;

                for (i = 0; i < 16; i++) {
                        w[i] = (uint32_t)bp[4 * i] |
                               ((uint32_t)bp[4 * i + 1] << 8) |
                               ((uint32_t)bp[4 * i + 2] << 16) |
                               ((uint32_t)bp[4 * i + 3] << 24);
                }
                a = h0;
                c = h1;
                d = h2;
                e = h3;
#define MD4S(A, B, C, D, X, S) \
                A = md4_rol(A + (((B) & (C)) | (~(B) & (D))) + (X), S)
                MD4S(a, c, d, e, w[0], 3);  MD4S(e, a, c, d, w[1], 7);
                MD4S(d, e, a, c, w[2], 11); MD4S(c, d, e, a, w[3], 19);
                MD4S(a, c, d, e, w[4], 3);  MD4S(e, a, c, d, w[5], 7);
                MD4S(d, e, a, c, w[6], 11); MD4S(c, d, e, a, w[7], 19);
                MD4S(a, c, d, e, w[8], 3);  MD4S(e, a, c, d, w[9], 7);
                MD4S(d, e, a, c, w[10], 11); MD4S(c, d, e, a, w[11], 19);
                MD4S(a, c, d, e, w[12], 3); MD4S(e, a, c, d, w[13], 7);
                MD4S(d, e, a, c, w[14], 11); MD4S(c, d, e, a, w[15], 19);
#undef MD4S
#define MD4G(A, B, C, D, X, S) \
                A = md4_rol(A + (((B) & (C)) | ((B) & (D)) | ((C) & (D))) + (X) + 0x5a827999u, S)
                MD4G(a, c, d, e, w[0], 3);  MD4G(e, a, c, d, w[4], 5);
                MD4G(d, e, a, c, w[8], 9);  MD4G(c, d, e, a, w[12], 13);
                MD4G(a, c, d, e, w[1], 3);  MD4G(e, a, c, d, w[5], 5);
                MD4G(d, e, a, c, w[9], 9);  MD4G(c, d, e, a, w[13], 13);
                MD4G(a, c, d, e, w[2], 3);  MD4G(e, a, c, d, w[6], 5);
                MD4G(d, e, a, c, w[10], 9); MD4G(c, d, e, a, w[14], 13);
                MD4G(a, c, d, e, w[3], 3);  MD4G(e, a, c, d, w[7], 5);
                MD4G(d, e, a, c, w[11], 9); MD4G(c, d, e, a, w[15], 13);
#undef MD4G
#define MD4H(A, B, C, D, X, S) \
                A = md4_rol(A + ((B) ^ (C) ^ (D)) + (X) + 0x6ed9eba1u, S)
                MD4H(a, c, d, e, w[0], 3);  MD4H(e, a, c, d, w[8], 9);
                MD4H(d, e, a, c, w[4], 11); MD4H(c, d, e, a, w[12], 15);
                MD4H(a, c, d, e, w[2], 3);  MD4H(e, a, c, d, w[10], 9);
                MD4H(d, e, a, c, w[6], 11); MD4H(c, d, e, a, w[14], 15);
                MD4H(a, c, d, e, w[1], 3);  MD4H(e, a, c, d, w[9], 9);
                MD4H(d, e, a, c, w[5], 11); MD4H(c, d, e, a, w[13], 15);
                MD4H(a, c, d, e, w[3], 3);  MD4H(e, a, c, d, w[11], 9);
                MD4H(d, e, a, c, w[7], 11); MD4H(c, d, e, a, w[15], 15);
#undef MD4H
                h0 += a;
                h1 += c;
                h2 += d;
                h3 += e;
        }
        /* the message is the UTF-16 machine password */
        wipe(buf, nblocks * 64);
        free(buf);
        for (i = 0; i < 4; i++) {
                out[i] = (uint8_t)(h0 >> (8 * i));
                out[4 + i] = (uint8_t)(h1 >> (8 * i));
                out[8 + i] = (uint8_t)(h2 >> (8 * i));
                out[12 + i] = (uint8_t)(h3 >> (8 * i));
        }
        return 0;
}


/* ------------------------------------------------------------- SHA-256 */

static const uint32_t sha256_k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t
rotr(uint32_t x, int n)
{
        return (x >> n) | (x << (32 - n));
}

static int
sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
        uint32_t st[8] = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        size_t nblocks, b, i;
        uint8_t *buf;
        uint64_t bits = (uint64_t)len * 8;

        nblocks = ((len + 8) / 64) + 1;
        buf = calloc(nblocks, 64);
        if (buf == NULL) {
                return -1;
        }
        memcpy(buf, msg, len);
        buf[len] = 0x80;
        for (i = 0; i < 8; i++) {
                buf[nblocks * 64 - 1 - i] = (uint8_t)(bits >> (8 * i));
        }
        for (b = 0; b < nblocks; b++) {
                uint32_t w[64];
                uint32_t a, bb, c, d, e, f, g, h;
                const uint8_t *bp = buf + b * 64;

                for (i = 0; i < 16; i++) {
                        w[i] = ((uint32_t)bp[4 * i] << 24) |
                               ((uint32_t)bp[4 * i + 1] << 16) |
                               ((uint32_t)bp[4 * i + 2] << 8) |
                               (uint32_t)bp[4 * i + 3];
                }
                for (i = 16; i < 64; i++) {
                        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
                                      (w[i - 15] >> 3);
                        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^
                                      (w[i - 2] >> 10);

                        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }
                a = st[0];
                bb = st[1];
                c = st[2];
                d = st[3];
                e = st[4];
                f = st[5];
                g = st[6];
                h = st[7];
                for (i = 0; i < 64; i++) {
                        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                        uint32_t ch = (e & f) ^ (~e & g);
                        uint32_t t1 = h + S1 + ch + sha256_k[i] + w[i];
                        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                        uint32_t maj = (a & bb) ^ (a & c) ^ (bb & c);
                        uint32_t t2 = S0 + maj;

                        h = g;
                        g = f;
                        f = e;
                        e = d + t1;
                        d = c;
                        c = bb;
                        bb = a;
                        a = t1 + t2;
                }
                st[0] += a;
                st[1] += bb;
                st[2] += c;
                st[3] += d;
                st[4] += e;
                st[5] += f;
                st[6] += g;
                st[7] += h;
        }
        /* HMAC's inner message starts with the key ^ ipad */
        wipe(buf, nblocks * 64);
        free(buf);
        for (i = 0; i < 8; i++) {
                out[4 * i] = (uint8_t)(st[i] >> 24);
                out[4 * i + 1] = (uint8_t)(st[i] >> 16);
                out[4 * i + 2] = (uint8_t)(st[i] >> 8);
                out[4 * i + 3] = (uint8_t)st[i];
        }
        return 0;
}


static int
hmac_sha256(const uint8_t *key, size_t key_len,
            const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
        uint8_t k[64], ipad[64], opad[64];
        uint8_t inner_hash[32], outer[96];
        uint8_t *inner;
        size_t i;
        int rc;

        memset(k, 0, 64);
        if (key_len > 64) {
                if (sha256(key, key_len, k) < 0) {
                        return -1;
                }
        } else if (key_len) {
                memcpy(k, key, key_len);
        }
        for (i = 0; i < 64; i++) {
                ipad[i] = k[i] ^ 0x36;
                opad[i] = k[i] ^ 0x5c;
        }
        wipe(k, sizeof(k));
        if (msg_len > SIZE_MAX - 64) {
                rc = -1;
                goto out;
        }
        inner = malloc(64 + msg_len);
        if (inner == NULL) {
                rc = -1;
                goto out;
        }
        memcpy(inner, ipad, 64);
        if (msg_len) {
                memcpy(inner + 64, msg, msg_len);
        }
        rc = sha256(inner, 64 + msg_len, inner_hash);
        wipe(inner, 64 + msg_len);
        free(inner);
        if (rc < 0) {
                goto out;
        }
        memcpy(outer, opad, 64);
        memcpy(outer + 64, inner_hash, 32);
        rc = sha256(outer, 96, out);
 out:
        /* the pads are the key xor a constant */
        wipe(ipad, sizeof(ipad));
        wipe(opad, sizeof(opad));
        wipe(inner_hash, sizeof(inner_hash));
        wipe(outer, sizeof(outer));
        return rc;
}


/* ------------------------------------------------------- session math */

/* memcmp() for secrets: the time taken does not depend on the data */
static int
ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
        uint8_t diff = 0;
        size_t i;

        for (i = 0; i < n; i++) {
                diff |= a[i] ^ b[i];
        }
        return diff != 0;
}

static void
cred_add(uint8_t cred[8], uint32_t n)
{
        uint32_t v = (uint32_t)cred[0] | ((uint32_t)cred[1] << 8) |
                     ((uint32_t)cred[2] << 16) | ((uint32_t)cred[3] << 24);

        v += n;
        cred[0] = (uint8_t)v;
        cred[1] = (uint8_t)(v >> 8);
        cred[2] = (uint8_t)(v >> 16);
        cred[3] = (uint8_t)(v >> 24);
}

static void
credential(const uint8_t session_key[16], const uint8_t in[8], uint8_t out[8])
{
        uint8_t iv[16];

        memset(iv, 0, 16);
        aes_cfb8_iv(session_key, iv, in, out, 8, 1);
}

/* Big-endian halves. The initiator sets the top bit of the high half. */
static void
sequence_bytes(uint64_t seq, int initiator, uint8_t out[8])
{
        uint32_t lo = (uint32_t)seq;
        uint32_t hi = (uint32_t)(seq >> 32);

        out[0] = (uint8_t)(lo >> 24);
        out[1] = (uint8_t)(lo >> 16);
        out[2] = (uint8_t)(lo >> 8);
        out[3] = (uint8_t)lo;
        out[4] = (uint8_t)(hi >> 24);
        out[5] = (uint8_t)(hi >> 16);
        out[6] = (uint8_t)(hi >> 8);
        out[7] = (uint8_t)hi;
        if (initiator) {
                out[4] |= 0x80;
        }
}

/*
 * Random bytes for confounders, read straight from /dev/urandom: no
 * stdio buffer filled with 4 KB of it per call, and no descriptor left
 * to a child that execs while we read.
 */
static int
random_bytes(uint8_t *p, size_t n)
{
        size_t got = 0;
        int fd;

        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                return -1;
        }
        while (got < n) {
                ssize_t r = read(fd, p + got, n - got);

                if (r < 0 && errno == EINTR) {
                        continue;
                }
                if (r <= 0) {
                        break;
                }
                got += (size_t)r;
        }
        close(fd);
        return got == n ? 0 : -1;
}

/*
 * [MS-NRPC] 3.1.4.1, since CVE-2020-1472 (Zerologon): a server refuses a
 * client challenge whose first five bytes are all the same. Such a
 * challenge makes an all-zero credential likely enough to be guessed.
 */
static int
challenge_is_weak(const uint8_t challenge[8])
{
        int i;

        for (i = 1; i < 5; i++) {
                if (challenge[i] != challenge[0]) {
                        return 0;
                }
        }
        return 1;
}

int
dcerpc_schannel_client_challenge(uint8_t challenge[8])
{
        if (challenge == NULL) {
                return -1;
        }
        do {
                if (random_bytes(challenge, 8)) {
                        return -1;
                }
        } while (challenge_is_weak(challenge));
        return 0;
}

struct dcerpc_schannel *
dcerpc_schannel_create(const uint8_t client_challenge[8],
                       const uint8_t server_challenge[8],
                       const char *machine_password,
                       uint32_t negotiate_flags)
{
        struct dcerpc_schannel *sch;
        struct dcerpc_utf16_buf *pw;
        uint8_t nthash[16], mac[32], material[16];
        static const uint8_t zeros[8] = { 0 };

        if (client_challenge == NULL || server_challenge == NULL ||
            machine_password == NULL ||
            (negotiate_flags & DCERPC_SCHANNEL_AES) == 0 ||
            challenge_is_weak(client_challenge)) {
                return NULL;
        }
        pw = dcerpc_utf8_to_utf16(machine_password);
        if (pw == NULL) {
                return NULL;
        }
        if (md4((const uint8_t *)pw->val, (size_t)pw->len * 2, nthash) < 0) {
                wipe(pw->val, (size_t)pw->len * 2);
                free(pw);
                return NULL;
        }
        wipe(pw->val, (size_t)pw->len * 2);
        free(pw);
        memcpy(material, client_challenge, 8);
        memcpy(material + 8, server_challenge, 8);
        if (hmac_sha256(nthash, 16, material, 16, mac) < 0) {
                wipe(nthash, sizeof(nthash));
                return NULL;
        }
        wipe(nthash, sizeof(nthash));

        sch = calloc(1, sizeof(*sch));
        if (sch == NULL) {
                wipe(mac, sizeof(mac));
                return NULL;
        }
        memcpy(sch->session_key, mac, 16);
        wipe(mac, sizeof(mac));
        credential(sch->session_key, client_challenge, sch->client_credential);
        credential(sch->session_key, server_challenge, sch->server_credential);
        if (memcmp(sch->client_credential, zeros, 8) == 0) {
                dcerpc_schannel_destroy(sch);
                return NULL;
        }
        memcpy(sch->seed, sch->client_credential, 8);
        return sch;
}

void
dcerpc_schannel_destroy(struct dcerpc_schannel *sch)
{
        if (sch != NULL) {
                wipe(sch, sizeof(*sch));
                free(sch);
        }
}

void
dcerpc_schannel_client_credential(const struct dcerpc_schannel *sch,
                                  uint8_t cred[8])
{
        if (sch != NULL && cred != NULL) {
                memcpy(cred, sch->client_credential, 8);
        }
}

void
dcerpc_schannel_server_credential(const struct dcerpc_schannel *sch,
                                  uint8_t cred[8])
{
        if (sch != NULL && cred != NULL) {
                memcpy(cred, sch->server_credential, 8);
        }
}

int
dcerpc_schannel_check_server_credential(struct dcerpc_schannel *sch,
                                        const uint8_t cred[8],
                                        uint32_t negotiated_flags)
{
        if (sch == NULL || cred == NULL || sch->failed || sch->verified) {
                return -1;
        }
        /*
         * A server that does not know the machine password can not
         * produce this. Without AES, the server dropped what the session
         * is computed with.
         */
        if (ct_memcmp(cred, sch->server_credential, 8) != 0 ||
            (negotiated_flags & DCERPC_SCHANNEL_AES) == 0) {
                sch->failed = 1;
                return -1;
        }
        sch->verified = 1;
        sch->negotiated_flags = negotiated_flags;
        return 0;
}

int
dcerpc_schannel_check_capabilities(struct dcerpc_schannel *sch,
                                   uint32_t capabilities)
{
        if (sch == NULL || !sch->verified || sch->failed) {
                return -1;
        }
        if (capabilities != sch->negotiated_flags) {
                sch->failed = 1;
                return -1;
        }
        return 0;
}

int
dcerpc_schannel_authenticator(struct dcerpc_schannel *sch,
                              uint32_t timestamp, uint8_t cred[8])
{
        if (sch == NULL || cred == NULL || sch->failed ||
            !sch->verified) {
                return -1;
        }
        cred_add(sch->seed, timestamp);
        credential(sch->session_key, sch->seed, cred);
        return 0;
}

int
dcerpc_schannel_check_authenticator(struct dcerpc_schannel *sch,
                                    const uint8_t cred[8])
{
        uint8_t next[8], got[8];

        if (sch == NULL || cred == NULL || sch->failed ||
            !sch->verified) {
                return -1;
        }
        memcpy(next, sch->seed, 8);
        cred_add(next, 1);
        credential(sch->session_key, next, got);
        if (ct_memcmp(got, cred, 8) != 0) {
                sch->failed = 1;
                return -1;
        }
        memcpy(sch->seed, next, 8);
        return 0;
}

int
dcerpc_schannel_encrypt_trust_password(const struct dcerpc_schannel *sch,
                                       uint8_t password[516])
{
        uint8_t iv[16];

        if (sch == NULL || password == NULL || sch->failed ||
            !sch->verified) {
                return -1;
        }
        memset(iv, 0, 16);
        aes_cfb8_iv(sch->session_key, iv, password, password, 516, 1);
        return 0;
}

static void
seal_key(const uint8_t session_key[16], uint8_t out[16])
{
        int i;

        for (i = 0; i < 16; i++) {
                out[i] = session_key[i] ^ 0xf0;
        }
}

/*
 * NL_AUTH_SHA2_SIGNATURE header: SignatureAlgorithm HMAC-SHA256 (0x0013),
 * SealAlgorithm AES-128 (0x001a) or none (0xffff), Pad 0xffff, Flags 0.
 */
static void
sign_header(int seal, uint8_t hdr[8])
{
        hdr[0] = 0x13;
        hdr[1] = 0x00;
        hdr[2] = seal ? 0x1a : 0xff;
        hdr[3] = seal ? 0x00 : 0xff;
        hdr[4] = 0xff;
        hdr[5] = 0xff;
        hdr[6] = 0x00;
        hdr[7] = 0x00;
}

/*
 * HMAC-SHA256(session key, header || confounder || message), first 8
 * bytes. A signed-only message has no confounder.
 */
static int
checksum8(const uint8_t session_key[16], const uint8_t hdr[8],
          const uint8_t *confounder, const uint8_t *msg, size_t len,
          uint8_t out[8])
{
        size_t pre = confounder ? 16 : 8;
        uint8_t *buf;
        uint8_t mac[32];

        if (len > SIZE_MAX - pre) {
                return -1;
        }
        buf = malloc(pre + len);
        if (buf == NULL) {
                return -1;
        }
        memcpy(buf, hdr, 8);
        if (confounder) {
                memcpy(buf + 8, confounder, 8);
        }
        if (len) {
                memcpy(buf + pre, msg, len);
        }
        if (hmac_sha256(session_key, 16, buf, pre + len, mac) < 0) {
                wipe(buf, pre + len);
                free(buf);
                return -1;
        }
        wipe(buf, pre + len);
        free(buf);
        memcpy(out, mac, 8);
        wipe(mac, sizeof(mac));
        return 0;
}

/*
 * AES-128-CFB8 under the sealing key over confounder || data, one stream
 * with IV seq || seq. enc is non-zero to encrypt. Both are done in place.
 */
static int
seal_stream(const uint8_t session_key[16], const uint8_t seq[8],
            uint8_t confounder[8], uint8_t *data, size_t len, int enc)
{
        uint8_t key[16], iv[16];
        uint8_t *body;

        if (len > SIZE_MAX - 8) {
                return -1;
        }
        body = malloc(8 + len);
        if (body == NULL) {
                return -1;
        }
        memcpy(body, confounder, 8);
        if (len) {
                memcpy(body + 8, data, len);
        }
        seal_key(session_key, key);
        memcpy(iv, seq, 8);
        memcpy(iv + 8, seq, 8);
        aes_cfb8_iv(key, iv, body, body, 8 + len, enc);
        wipe(key, sizeof(key));
        memcpy(confounder, body, 8);
        if (len) {
                memcpy(data, body + 8, len);
        }
        wipe(body, 8 + len);
        free(body);
        return 0;
}

int
dcerpc_schannel_protect(struct dcerpc_schannel *sch, int seal,
                        uint8_t *data, size_t data_len,
                        const uint8_t *sign, size_t sign_len,
                        const uint8_t *confounder,
                        uint8_t token[DCERPC_SCHANNEL_TOKEN_LEN])
{
        uint8_t seq[8], conf[8], sum[8], iv[16];

        if (sch == NULL || token == NULL || sch->failed || !sch->verified ||
            (seal && data_len > 0 && data == NULL) ||
            (sign_len > 0 && sign == NULL)) {
                return -1;
        }
        if (seal) {
                if (confounder != NULL) {
                        memcpy(conf, confounder, 8);
                } else if (random_bytes(conf, 8)) {
                        return -1;
                }
        }
        memset(token, 0, DCERPC_SCHANNEL_TOKEN_LEN);
        sign_header(seal, token);
        sequence_bytes(sch->seq, 1, seq);

        /* Sign the plaintext: data, if it is inside sign, is not sealed yet */
        if (checksum8(sch->session_key, token, seal ? conf : NULL,
                      sign, sign_len, sum) < 0) {
                return -1;
        }
        memcpy(token + 16, sum, 8);

        if (seal) {
                if (seal_stream(sch->session_key, seq, conf, data, data_len,
                                1) < 0) {
                        return -1;
                }
                memcpy(token + 24, conf, 8);
        }

        memcpy(iv, sum, 8);
        memcpy(iv + 8, sum, 8);
        aes_cfb8_iv(sch->session_key, iv, seq, token + 8, 8, 1);
        sch->seq++;
        return 0;
}

int
dcerpc_schannel_unprotect(struct dcerpc_schannel *sch, int seal,
                          uint8_t *data, size_t data_len,
                          const uint8_t *sign, size_t sign_len,
                          const uint8_t *token, size_t token_len)
{
        uint8_t expect[8], got_seq[8], sum[8], conf[8], iv[16];
        uint8_t hdr[8];

        if (sch == NULL || token == NULL || sch->failed || !sch->verified ||
            (seal && data_len > 0 && data == NULL) ||
            (sign_len > 0 && sign == NULL)) {
                return -1;
        }
        /* A signed-only token ends before the confounder */
        if (token_len < (seal ? DCERPC_SCHANNEL_TOKEN_LEN :
                         DCERPC_SCHANNEL_SIGN_TOKEN_LEN)) {
                sch->failed = 1;
                return -1;
        }
        sign_header(seal, hdr);
        if (memcmp(token, hdr, 8) != 0) {
                sch->failed = 1;
                return -1;
        }
        sequence_bytes(sch->seq, 0, expect);
        memcpy(iv, token + 16, 8);
        memcpy(iv + 8, token + 16, 8);
        aes_cfb8_iv(sch->session_key, iv, token + 8, got_seq, 8, 0);
        if (ct_memcmp(got_seq, expect, 8) != 0) {
                sch->failed = 1;
                return -1;
        }

        /* Unseal first: the signature is over the plaintext */
        if (seal) {
                memcpy(conf, token + 24, 8);
                if (seal_stream(sch->session_key, expect, conf, data,
                                data_len, 0) < 0) {
                        return -1;
                }
        }
        if (checksum8(sch->session_key, hdr, seal ? conf : NULL,
                      sign, sign_len, sum) < 0) {
                return -1;
        }
        if (ct_memcmp(sum, token + 16, 8) != 0) {
                /* the plaintext of a forged message is nobody's to use */
                if (seal && data_len > 0) {
                        wipe(data, data_len);
                }
                sch->failed = 1;
                return -1;
        }
        sch->seq++;
        return 0;
}
