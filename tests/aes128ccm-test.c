/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../lib/aes128ccm.h"

static void test_aad_length(void)
{
        static const struct {
                uint64_t length;
                size_t size;
                unsigned char bytes[10];
        } cases[] = {
                {0xfeff, 2, {0xfe, 0xff}},
                {0xff00, 6, {0xff, 0xfe, 0, 0, 0xff, 0}},
                {UINT32_MAX, 6, {0xff, 0xfe, 0xff, 0xff, 0xff, 0xff}},
                {UINT64_C(0x100000000), 10, {0xff, 0xff, 0, 0, 0, 1, 0, 0, 0, 0}},
                {UINT64_MAX, 10, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
        };
        unsigned char buf[10];
        size_t i;

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                if (ccm_encode_aad_length(buf, cases[i].length) != cases[i].size ||
                    memcmp(buf, cases[i].bytes, cases[i].size) != 0) {
                        fprintf(stderr, "Invalid CCM AAD length prefix in case %zu\n", i);
                        exit(1);
                }
        }
}

static void test_payload_size(void)
{
        unsigned char nonce[7] = {1, 2, 3, 4, 5, 6, 7};
        unsigned char block[16];
        const unsigned char expected[16] = {7, 1, 2, 3, 4, 5, 6, 7,
                                            0, 0, 0, 1, 0, 0, 0, 1};

        ccm_format_block(block, nonce, sizeof(nonce), 0, UINT64_C(0x100000001));
        if (memcmp(block, expected, sizeof(block)) ||
            !ccm_valid_lengths(11, UINT32_C(0x80000001), 16) ||
            ccm_valid_lengths(13, 65536, 16)) {
                exit(1);
        }
}

static void check_vector(unsigned char *key, unsigned char *nonce, size_t nlen,
                         unsigned char *aad, size_t alen, const unsigned char *plain,
                         size_t plen, size_t tag_len, const unsigned char *expected)
{
        unsigned char buf[64];
        if (plen + tag_len > sizeof(buf)) {
                exit(1);
        }
        memcpy(buf, plain, plen);
        if (aes128ccm_encrypt(key, nonce, nlen, aad, alen, buf, plen, buf + plen, tag_len) ||
            memcmp(buf, expected, plen + tag_len)) {
                fprintf(stderr, "CCM ciphertext or tag differs from the test vector\n");
                exit(1);
        }
        if (aes128ccm_decrypt(key, nonce, nlen, aad, alen, buf, plen, buf + plen, tag_len) ||
            memcmp(buf, plain, plen)) {
                fprintf(stderr, "CCM decryption failed the test vector\n");
                exit(1);
        }
}

static void test_1(void)
{
  unsigned char key[16]  = {0x40, 0x41, 0x42, 0x43,  0x44, 0x45, 0x46, 0x47,
			    0x48, 0x49, 0x4a, 0x4b,  0x4c, 0x4d, 0x4e, 0x4f};
  unsigned char nonce[7] = {0x10, 0x11, 0x12, 0x13,  0x14, 0x15, 0x16 };
  unsigned char aad[8]   = {0x00, 0x01, 0x02, 0x03,  0x04, 0x05, 0x06, 0x07};
  unsigned char p[4]     = {0x20, 0x21, 0x22, 0x23};
  int mlen = 4;
  unsigned char exp[8]   = {0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d};

  check_vector(key, nonce, sizeof(nonce), aad, sizeof(aad), p, sizeof(p), mlen, exp);
}

static void test_2(void)
{
  unsigned char key[16]  = {0x40, 0x41, 0x42, 0x43,  0x44, 0x45, 0x46, 0x47,
			    0x48, 0x49, 0x4a, 0x4b,  0x4c, 0x4d, 0x4e, 0x4f};
  unsigned char nonce[] = {0x10, 0x11, 0x12, 0x13,  0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1a, 0x1b};
  unsigned char aad[]   = {0x00, 0x01, 0x02, 0x03,  0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b,  0x0c, 0x0d, 0x0e, 0x0f,
                            0x10, 0x11, 0x12, 0x13};
  unsigned char p[]     = {0x20, 0x21, 0x22, 0x23,  0x24, 0x25, 0x26, 0x27,
                            0x28, 0x29, 0x2a, 0x2b,  0x2c, 0x2d, 0x2e, 0x2f,
                            0x30, 0x31, 0x32, 0x33,  0x34, 0x35, 0x36, 0x37};
  int mlen = 8;
  unsigned char exp[]   = {0xe3, 0xb2, 0x01, 0xa9,  0xf5, 0xb7, 0x1a, 0x7a,
                           0x9b, 0x1c, 0xea, 0xec,  0xcd, 0x97, 0xe7, 0x0b,
                           0x61, 0x76, 0xaa, 0xd9,  0xa4, 0x42, 0x8a, 0xa5,
                           0x48, 0x43, 0x92, 0xfb,  0xc1, 0xb0, 0x99, 0x51};
  check_vector(key, nonce, sizeof(nonce), aad, sizeof(aad), p, sizeof(p), mlen, exp);
}

/* NIST SP 800-38C, Appendix C.4: the AAD spans all 65536 bytes. */
static void test_extended_aad(void)
{
        static unsigned char aad[65536];
        unsigned char key[16], nonce[13], plain[32];
        static const unsigned char expected[] = {
                0x69, 0x91, 0x5d, 0xad, 0x1e, 0x84, 0xc6, 0x37,
                0x6a, 0x68, 0xc2, 0x96, 0x7e, 0x4d, 0xab, 0x61,
                0x5a, 0xe0, 0xfd, 0x1f, 0xae, 0xc4, 0x4c, 0xc4,
                0x84, 0x82, 0x85, 0x29, 0x46, 0x3c, 0xcf, 0x72,
                0xb4, 0xac, 0x6b, 0xec, 0x93, 0xe8, 0x59, 0x8e,
                0x7f, 0x0d, 0xad, 0xbc, 0xea, 0x5b
        };
        size_t i;

        for (i = 0; i < sizeof(aad); i++) aad[i] = (unsigned char)i;
        for (i = 0; i < sizeof(key); i++) key[i] = (unsigned char)(0x40 + i);
        for (i = 0; i < sizeof(nonce); i++) nonce[i] = (unsigned char)(0x10 + i);
        for (i = 0; i < sizeof(plain); i++) plain[i] = (unsigned char)(0x20 + i);
        check_vector(key, nonce, sizeof(nonce), aad, sizeof(aad), plain,
                     sizeof(plain), 14, expected);
}

int main(void)
{
        test_extended_aad();
        test_aad_length();
        test_payload_size();
        test_1();
        test_2();
        return 0;
}
