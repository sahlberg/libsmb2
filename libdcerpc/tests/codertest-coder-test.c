/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Coder tests for NDR layouts that the real interfaces do not exercise,
 * using the test-only interface in codertest.idl. See coder-test.h for
 * the tests run per case.
 *
 * The known-good NDR here is derived from the NDR rules ([C706] 14,
 * [MS-RPCE] 2.2.5), not captured from a server: nothing implements this
 * interface. Every flavor, NDR64 big-endian included, has a known-good
 * stub.
 */

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <dcerpc/dcerpc.h>

#include "codertest_coder.h"
#include "coder-test.h"

/*
 * EmbeddedTail: TAIL_OUTER { TAIL_INNER { hyper Big; uint8 Small; } Inner;
 *                            uint8 After; }
 * Big = 0x0102030405060708, Small = 0x11, After = 0x22.
 *
 * Both structures are 8-aligned (Big). NDR32 does not pad structures at
 * the end, so After follows Small at offset 9. NDR64 pads TAIL_INNER to a
 * multiple of 8 (16 bytes), putting After at offset 16, and pads
 * TAIL_OUTER to 24 bytes.
 */
static const uint8_t embedded_tail_ndr32_le[] = {
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x11, 0x22,
};
static const uint8_t embedded_tail_ndr32_be[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x22,
};
static const uint8_t embedded_tail_ndr64_le[] = {
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t embedded_tail_ndr64_be[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/*
 * EmbeddedHead: HEAD_OUTER { uint8 Before; HEAD_INNER { uint16 Short;
 *                            uint32 Long; } Inner; }
 * Before = 0x33, Short = 0x4455, Long = 0x66778899.
 *
 * HEAD_INNER is 4-aligned (Long), so it starts at offset 4 although its
 * first member is a uint16: Short at 4, Long at 8. 12 bytes is a multiple
 * of 4, so NDR64 adds no padding and both transfer syntaxes agree.
 */
static const uint8_t embedded_head_le[] = {
        0x33, 0x00, 0x00, 0x00, 0x55, 0x44, 0x00, 0x00,
        0x99, 0x88, 0x77, 0x66,
};
static const uint8_t embedded_head_be[] = {
        0x33, 0x00, 0x00, 0x00, 0x44, 0x55, 0x00, 0x00,
        0x66, 0x77, 0x88, 0x99,
};

/* Known-good YAML */
static const char embedded_tail_yaml[] =
        "EmbeddedTail: Request\n"
        "  Outer: \n"
        "    Inner: \n"
        "      Big: 72623859790382856\n"
        "      Small: 17\n"
        "    After: 34\n";

static const char embedded_head_yaml[] =
        "EmbeddedHead: Request\n"
        "  Outer: \n"
        "    Before: 51\n"
        "    Inner: \n"
        "      Short: 17493\n"
        "      Long: 1719109785\n";

#define BLOB(b) { b, sizeof(b) }

/*
 * UnionArm: ARM_LEVEL Level; [switch_is(Level)] ARM_UNION Union;
 * uint16 After. ARM_UNION has a 2-aligned arm (SMALL_ARM { uint16 Short; })
 * and an 8-aligned one (WIDE_ARM { hyper Big; }).
 *
 * NDR32: Level and the discriminant are 16 bits; the arm is aligned to its
 * own alignment ([C706] 14.3.2), so Short follows the discriminant at
 * offset 4, while Big is at offset 8. NDR64: Level and the discriminant
 * are 32 bits; the union and its arm are 8-aligned (the largest arm,
 * [MS-RPCE] 2.2.5.3.4.4), so the discriminant is at 8 and either arm at
 * 16. Neither pads the union at the end.
 *
 * Small: Short = 0x1122, After = 0x3344.
 * Wide: Big = 0x0102030405060708, After = 0x3344.
 */
static const uint8_t union_arm_small_ndr32_le[] = {
        0x01, 0x00, 0x01, 0x00, 0x22, 0x11, 0x44, 0x33,
};
static const uint8_t union_arm_small_ndr32_be[] = {
        0x00, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44,
};
static const uint8_t union_arm_small_ndr64_le[] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x22, 0x11, 0x44, 0x33,
};
static const uint8_t union_arm_small_ndr64_be[] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x11, 0x22, 0x33, 0x44,
};
static const uint8_t union_arm_wide_ndr32_le[] = {
        0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x44, 0x33,
};
static const uint8_t union_arm_wide_ndr32_be[] = {
        0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x33, 0x44,
};
static const uint8_t union_arm_wide_ndr64_le[] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x44, 0x33,
};
static const uint8_t union_arm_wide_ndr64_be[] = {
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x33, 0x44,
};

static const char union_arm_small_yaml[] =
        "UnionArm: Request\n"
        "  Level: ArmSmall\n"
        "  Union:\n"
        "    Small: \n"
        "      Short: 4386\n"
        "  After: 13124\n";
static const char union_arm_wide_yaml[] =
        "UnionArm: Request\n"
        "  Level: ArmWide\n"
        "  Union:\n"
        "    Wide: \n"
        "      Big: 72623859790382856\n"
        "  After: 13124\n";

/*
 * FixedBytes: FIXED_BYTES { uint8 Before; uint8 Data[8]; uint32 After; }
 * Before = 0x11, Data = 01..08, After = 0x22334455.
 *
 * Data has no count and is 1-aligned, so it is at offset 1; After is
 * padded to offset 12. The structure is 4-aligned and 16 bytes, so NDR64
 * adds no padding.
 */
static const uint8_t fixed_bytes_le[] = {
        0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x00, 0x00, 0x00, 0x55, 0x44, 0x33, 0x22,
};
static const uint8_t fixed_bytes_be[] = {
        0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x00, 0x00, 0x00, 0x22, 0x33, 0x44, 0x55,
};

static const char fixed_bytes_yaml[] =
        "FixedBytes: Request\n"
        "  Fixed: \n"
        "    Before: 17\n"
        "    Data: 0102030405060708\n"
        "    After: 573785173\n";

static const struct test_case test_cases[] = {
        { "EmbeddedTail request: NDR64 trailing padding of an embedded structure",
          "EmbeddedTail",
          codertest_EmbeddedTail_req_coder,
          sizeof(struct codertest_EmbeddedTail_req),
          NULL, embedded_tail_yaml,
          { BLOB(embedded_tail_ndr32_le), BLOB(embedded_tail_ndr32_be),
            BLOB(embedded_tail_ndr64_le), BLOB(embedded_tail_ndr64_be) },
          0, NULL },
        { "EmbeddedHead request: start alignment of an embedded structure",
          "EmbeddedHead",
          codertest_EmbeddedHead_req_coder,
          sizeof(struct codertest_EmbeddedHead_req),
          NULL, embedded_head_yaml,
          { BLOB(embedded_head_le), BLOB(embedded_head_be),
            BLOB(embedded_head_le), BLOB(embedded_head_be) },
          0, NULL },
        { "UnionArm request, 2-aligned arm: NDR32 aligns the arm to itself",
          "UnionArm",
          codertest_UnionArm_req_coder,
          sizeof(struct codertest_UnionArm_req),
          NULL, union_arm_small_yaml,
          { BLOB(union_arm_small_ndr32_le), BLOB(union_arm_small_ndr32_be),
            BLOB(union_arm_small_ndr64_le), BLOB(union_arm_small_ndr64_be) },
          0, NULL },
        { "UnionArm request, 8-aligned arm",
          "UnionArm",
          codertest_UnionArm_req_coder,
          sizeof(struct codertest_UnionArm_req),
          NULL, union_arm_wide_yaml,
          { BLOB(union_arm_wide_ndr32_le), BLOB(union_arm_wide_ndr32_be),
            BLOB(union_arm_wide_ndr64_le), BLOB(union_arm_wide_ndr64_be) },
          0, NULL },
        { "FixedBytes request: a fixed-size byte array",
          "FixedBytes",
          codertest_FixedBytes_req_coder,
          sizeof(struct codertest_FixedBytes_req),
          NULL, fixed_bytes_yaml,
          { BLOB(fixed_bytes_le), BLOB(fixed_bytes_be),
            BLOB(fixed_bytes_le), BLOB(fixed_bytes_be) },
          0, NULL },
};

/*
 * dcerpc_allocate_pdu() flags: every valid combination gives a PDU, and
 * reserved bits, unknown encodings and NDR flavor bits on a text encoding
 * are rejected.
 */
static int test_pdu_flags(void)
{
        static const uint32_t valid[] = {
                DCERPC_DECODE | ENCODING_NDR,
                DCERPC_ENCODE | ENCODING_NDR | DCERPC_NDR64,
                DCERPC_ENCODE | ENCODING_NDR | DCERPC_BIG_ENDIAN,
                DCERPC_DECODE | ENCODING_NDR | DCERPC_NDR64 |
                        DCERPC_BIG_ENDIAN,
                DCERPC_ENCODE | ENCODING_YAML,
                DCERPC_DECODE | ENCODING_JSON,
        };
        static const uint32_t invalid[] = {
                DCERPC_ENCODE | ENCODING_NDR | 0x00000100U,
                DCERPC_DECODE | ENCODING_NDR | 0x10000000U,
                DCERPC_ENCODE | 3,
                DCERPC_ENCODE | ENCODING_YAML | DCERPC_NDR64,
                DCERPC_DECODE | ENCODING_JSON | DCERPC_BIG_ENDIAN,
        };
        struct dcerpc_context *dce;
        struct dcerpc_pdu *pdu;
        int failed = 0;
        size_t i;

        printf("dcerpc_allocate_pdu() flags\n");
        dce = dcerpc_create_context(NULL);
        if (dce == NULL) {
                return 1;
        }
        for (i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
                pdu = dcerpc_allocate_pdu(dce, valid[i], 16);
                if (pdu == NULL) {
                        printf("  0x%08x: rejected: %s\n", valid[i],
                               dcerpc_get_error(dce));
                        failed = 1;
                        continue;
                }
                dcerpc_free_pdu(dce, pdu);
        }
        for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
                pdu = dcerpc_allocate_pdu(dce, invalid[i], 16);
                if (pdu != NULL) {
                        printf("  0x%08x: accepted\n", invalid[i]);
                        dcerpc_free_pdu(dce, pdu);
                        failed = 1;
                }
        }
        printf("  %s\n", failed ? "FAIL" : "PASS");
        dcerpc_destroy_context(dce);
        return failed;
}

/* Encode len bytes of a pattern as a byte array; returns the coder result */
static int encode_bytes(struct dcerpc_context *dce, uint32_t flags,
                        struct dcerpc_iovec *iov, uint32_t len)
{
        struct dcerpc_pdu *pdu;
        struct dcerpc_bytes b;
        uint32_t i;
        int ret;

        b.len = len;
        b.data = malloc(len ? len : 1);
        if (b.data == NULL) {
                return -1;
        }
        for (i = 0; i < len; i++) {
                b.data[i] = (uint8_t)(i * 7);
        }
        pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE | flags, 16);
        if (pdu == NULL) {
                free(b.data);
                return -1;
        }
        ret = dcerpc_bytes_coder("Data", dce, pdu, iov, &b);
        dcerpc_free_pdu(dce, pdu);
        free(b.data);
        return ret;
}

/*
 * Growable iovecs: buf == NULL grows (and sets .free = free) up to
 * DCERPC_IOVEC_MAX_SIZE, as does a caller's buffer with .free = free; any
 * other buffer has a fixed size.
 */
static int test_growable_iovec(void)
{
        struct dcerpc_context *dce;
        struct dcerpc_iovec iov = {0};
        uint8_t fixed[16];
        uint32_t i;
        int failed = 0;

        printf("growable struct dcerpc_iovec\n");
        dce = dcerpc_create_context(NULL);
        if (dce == NULL) {
                return 1;
        }

        /* NDR32: max_count, then the bytes; 1 KiB doubled to 4 MiB */
        if (encode_bytes(dce, ENCODING_NDR, &iov, 3 * 1024 * 1024) ||
            iov.free != free || iov.offset != 4 + 3 * 1024 * 1024 ||
            iov.max_offset != 4 * 1024 * 1024) {
                printf("  3 MiB NDR: failed (offset %zu, max_offset %zu): "
                       "%s\n", iov.offset, iov.max_offset,
                       dcerpc_get_error(dce));
                failed = 1;
        } else {
                for (i = 0; i < 3 * 1024 * 1024; i++) {
                        if (iov.buf[4 + i] != (uint8_t)(i * 7)) {
                                printf("  3 MiB NDR: byte %u differs\n", i);
                                failed = 1;
                                break;
                        }
                }
        }
        dcerpc_free_iovec(&iov);

        /* YAML: a hex string, twice the size */
        if (encode_bytes(dce, ENCODING_YAML, &iov, 1024 * 1024) ||
            iov.offset < 2 * 1024 * 1024 ||
            strlen((char *)iov.buf) != iov.offset) {
                printf("  1 MiB YAML: failed (offset %zu): %s\n",
                       iov.offset, dcerpc_get_error(dce));
                failed = 1;
        }
        dcerpc_free_iovec(&iov);

        /* More than DCERPC_IOVEC_MAX_SIZE is refused */
        if (encode_bytes(dce, ENCODING_NDR, &iov,
                         DCERPC_IOVEC_MAX_SIZE + 1) == 0 ||
            iov.max_offset > DCERPC_IOVEC_MAX_SIZE) {
                printf("  over the limit: accepted (max_offset %zu)\n",
                       iov.max_offset);
                failed = 1;
        }
        dcerpc_free_iovec(&iov);

        /* A caller's buffer without .free = free does not grow */
        iov.buf = fixed;
        iov.max_offset = sizeof(fixed);
        if (encode_bytes(dce, ENCODING_NDR, &iov, 100) == 0 ||
            iov.buf != fixed || iov.max_offset != sizeof(fixed)) {
                printf("  fixed buffer: grew\n");
                failed = 1;
        }
        memset(&iov, 0, sizeof(iov));

        /* A caller's malloc()ed buffer with .free = free grows */
        iov.buf = malloc(16);
        iov.max_offset = 16;
        iov.free = free;
        if (iov.buf == NULL ||
            encode_bytes(dce, ENCODING_NDR, &iov, 100) ||
            iov.offset != 4 + 100 || iov.max_offset < 104) {
                printf("  malloc()ed buffer: did not grow: %s\n",
                       dcerpc_get_error(dce));
                failed = 1;
        }
        dcerpc_free_iovec(&iov);

        printf("  %s\n", failed ? "FAIL" : "PASS");
        dcerpc_destroy_context(dce);
        return failed;
}

/*
 * A context created without an smb2 context encodes and decodes (all the
 * other tests use one), and refuses to connect or call.
 */
static int test_no_smb2(void)
{
        struct dcerpc_context *dce;
        int failed = 0;
        int ret;

        printf("dcerpc context without an smb2 context\n");
        dce = dcerpc_create_context(NULL);
        if (dce == NULL) {
                printf("  dcerpc_create_context(NULL) failed\n");
                return 1;
        }
        if (dcerpc_get_smb2_context(dce) != NULL) {
                printf("  dcerpc_get_smb2_context() is not NULL\n");
                failed = 1;
        }
        ret = dcerpc_connect_context_async(dce, "srvsvc", NULL, NULL, NULL);
        if (ret != -EINVAL) {
                printf("  dcerpc_connect_context_async() returned %d\n", ret);
                failed = 1;
        }
        ret = dcerpc_call_async(dce, 0, NULL, NULL, NULL, 0, NULL, NULL);
        if (ret != -EINVAL) {
                printf("  dcerpc_call_async() returned %d\n", ret);
                failed = 1;
        }
        ret = dcerpc_connect_context(dce, "srvsvc", NULL);
        if (ret != -EINVAL) {
                printf("  dcerpc_connect_context() returned %d\n", ret);
                failed = 1;
        }
        if (dcerpc_call(dce, 0, NULL, NULL, NULL, 0) != NULL) {
                printf("  dcerpc_call() did not fail\n");
                failed = 1;
        }
        if (strstr(dcerpc_get_error(dce), "No smb2 context") == NULL) {
                printf("  unexpected error \"%s\"\n", dcerpc_get_error(dce));
                failed = 1;
        }
        printf("  %s\n", failed ? "FAIL" : "PASS");
        dcerpc_destroy_context(dce);
        return failed;
}

/*
 * RPC_UNICODE_STRING Length counts UTF-16 bytes: "a\xc3\xa5\xf0\x9f\x8c\x8e"
 * (a, a-ring, an emoji that is a surrogate pair) is 7 bytes of UTF-8 but
 * 4 UTF-16 code units, so Length is 8. Windows faults a request whose
 * Length does not match the string (it did, as 2 * strlen()).
 */
static int test_unicode_string_length(void)
{
        static const uint32_t flavors[] = {
                0, DCERPC_BIG_ENDIAN, DCERPC_NDR64,
                DCERPC_NDR64 | DCERPC_BIG_ENDIAN,
        };
        const char *str = "a\xc3\xa5\xf0\x9f\x8c\x8e";
        struct dcerpc_context *dce;
        int failed = 0;
        size_t i;

        printf("RPC_UNICODE_STRING Length of a non-ASCII string\n");
        dce = dcerpc_create_context(NULL);
        if (dce == NULL) {
                return 1;
        }
        for (i = 0; i < sizeof(flavors) / sizeof(flavors[0]); i++) {
                struct dcerpc_iovec iov = {0}, in;
                struct dcerpc_pdu *pdu;
                char *in_str = (char *)str, *out_str = NULL;
                uint16_t len;

                pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE | ENCODING_NDR |
                                          flavors[i], sizeof(char *));
                if (pdu == NULL ||
                    dcerpc_do_coder("s", dce, pdu, &iov, &in_str,
                                    dcerpc_RPC_UNICODE_STRING_coder)) {
                        printf("  0x%08x: encode failed\n", flavors[i]);
                        failed = 1;
                        goto next;
                }
                len = (flavors[i] & DCERPC_BIG_ENDIAN) ?
                        (uint16_t)(iov.buf[0] << 8 | iov.buf[1]) :
                        (uint16_t)(iov.buf[1] << 8 | iov.buf[0]);
                if (len != 8) {
                        printf("  0x%08x: Length %u, expected 8\n",
                               flavors[i], len);
                        failed = 1;
                }
                dcerpc_free_pdu(dce, pdu);
                pdu = dcerpc_allocate_pdu(dce, DCERPC_DECODE | ENCODING_NDR |
                                          flavors[i], sizeof(char *));
                in = (struct dcerpc_iovec){ .buf = iov.buf,
                                            .max_offset = iov.offset };
                if (pdu == NULL ||
                    dcerpc_do_coder("s", dce, pdu, &in, &out_str,
                                    dcerpc_RPC_UNICODE_STRING_coder) ||
                    out_str == NULL || strcmp(out_str, str)) {
                        printf("  0x%08x: did not decode back\n", flavors[i]);
                        failed = 1;
                }
        next:
                if (pdu) {
                        dcerpc_free_pdu(dce, pdu);
                }
                dcerpc_free_iovec(&iov);
        }
        printf("  %s\n", failed ? "FAIL" : "PASS");
        dcerpc_destroy_context(dce);
        return failed;
}

int main(void)
{
        int ret = test_pdu_flags();

        ret |= test_unicode_string_length();

        ret |= test_growable_iovec();
        ret |= test_no_smb2();
        return run_coder_tests(test_cases,
                               sizeof(test_cases) / sizeof(test_cases[0])) |
                ret;
}
