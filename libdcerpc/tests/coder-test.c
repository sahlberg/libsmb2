/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dcerpc/dcerpc.h>

#include "coder-test.h"

/* Referent ids libdcerpc writes for unique and ref pointers */
#define UPTR 0x5570747272747055ULL
#define RPTR 0x5270747272747052ULL

#define BUF_SIZE 65536

struct flavor {
        const char *name;
        uint32_t flags; /* DCERPC_NDR64, DCERPC_BIG_ENDIAN */
};

static const struct flavor flavors[NUM_FLAVORS] = {
        [NDR32_LE] = { "NDR32 LE", 0 },
        [NDR32_BE] = { "NDR32 BE", DCERPC_BIG_ENDIAN },
        [NDR64_LE] = { "NDR64 LE", DCERPC_NDR64 },
        [NDR64_BE] = { "NDR64 BE", DCERPC_NDR64 | DCERPC_BIG_ENDIAN },
};

#define FLAVOR_NDR64(f) (((f)->flags & DCERPC_NDR64) != 0)
#define FLAVOR_LITTLE_ENDIAN(f) (((f)->flags & DCERPC_BIG_ENDIAN) == 0)

static int failures;

static void hexdump(const char *label, const uint8_t *buf, int len)
{
        int i;

        printf("%s (%d bytes):\n", label, len);
        for (i = 0; i < len; i++) {
                printf("%02x%s", buf[i], i % 16 == 15 ? "\n" : " ");
        }
        printf("\n");
}

/*
 * NDR -> struct. The struct lives in the returned pdu's payload.
 *
 * buf is the const known-good stub, in read-only memory: decoding must
 * never write its input.
 */
static struct dcerpc_pdu *ndr_decode(struct dcerpc_context *dce,
                                     const struct test_case *tc,
                                     const struct flavor *f,
                                     const uint8_t *buf, int len,
                                     void **ptr)
{
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov;

        pdu = dcerpc_allocate_pdu(dce, DCERPC_DECODE | ENCODING_NDR |
                                  f->flags, tc->size);
        if (pdu == NULL) {
                printf("  %s: %s\n", f->name, dcerpc_get_error(dce));
                return NULL;
        }
        dcerpc_set_request(pdu, tc->req);
        *ptr = dcerpc_get_pdu_payload(pdu);

        iov = (struct dcerpc_iovec){
                .buf = discard_const(buf),
                .max_offset = len,
        };
        if (tc->coder(tc->req ? "Response" : "Request", dce, pdu, &iov,
                      *ptr)) {
                printf("  %s: NDR decode failed\n", f->name);
                dcerpc_free_pdu(dce, pdu);
                return NULL;
        }
        if (iov.offset != (size_t)len) {
                printf("  %s: NDR decode consumed %d of %d bytes\n",
                       f->name, (int)iov.offset, len);
                dcerpc_free_pdu(dce, pdu);
                return NULL;
        }
        return pdu;
}

/*
 * struct -> NDR, into buf. Returns the encoded length or -1. Encodes into
 * a growable iovec, so every case also tests growing the buffer.
 */
static int ndr_encode(struct dcerpc_context *dce, const struct test_case *tc,
                      const struct flavor *f, void *ptr, uint8_t *buf)
{
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov = {0};
        int ret;

        pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE | ENCODING_NDR |
                                  f->flags, tc->size);
        if (pdu == NULL) {
                printf("  %s: %s\n", f->name, dcerpc_get_error(dce));
                return -1;
        }
        dcerpc_set_request(pdu, tc->req);
        /* a reply's full pointers continue after its request's */
        dcerpc_set_full_pointer_id(pdu, tc->full_ptr_base);

        if (tc->coder(tc->req ? "Response" : "Request", dce, pdu, &iov,
                      ptr)) {
                printf("  %s: NDR encode failed\n", f->name);
                ret = -1;
        } else if (iov.offset > BUF_SIZE) {
                printf("  %s: NDR encoded to %d bytes\n", f->name,
                       (int)iov.offset);
                ret = -1;
        } else {
                memset(buf, 0, BUF_SIZE);
                memcpy(buf, iov.buf, iov.offset);
                ret = (int)iov.offset;
        }
        dcerpc_free_iovec(&iov);
        dcerpc_free_pdu(dce, pdu);
        return ret;
}

/*
 * YAML -> struct. The struct lives in the returned pdu's payload. Like
 * ndr_decode(), it decodes the const YAML directly.
 */
static struct dcerpc_pdu *yaml_decode(struct dcerpc_context *dce,
                                      const struct test_case *tc,
                                      const char *yaml, void **ptr)
{
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov;

        pdu = dcerpc_allocate_pdu(dce, DCERPC_DECODE | ENCODING_YAML,
                                  tc->size);
        if (pdu == NULL) {
                printf("  %s\n", dcerpc_get_error(dce));
                return NULL;
        }
        dcerpc_set_request(pdu, tc->req);
        *ptr = dcerpc_get_pdu_payload(pdu);

        iov = (struct dcerpc_iovec){
                .buf = discard_const(yaml),
                .max_offset = strlen(yaml) + 1,
        };
        if (dcerpc_do_coder(discard_const(tc->proc), dce, pdu, &iov,
                            *ptr, tc->coder)) {
                printf("  YAML decode failed\n");
                dcerpc_free_pdu(dce, pdu);
                return NULL;
        }
        return pdu;
}

/*
 * struct -> YAML, into buf (NUL terminated). Returns 0 on success. Like
 * ndr_encode(), it encodes into a growable iovec.
 */
static int yaml_encode(struct dcerpc_context *dce, const struct test_case *tc,
                       void *ptr, char *buf)
{
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov = {0};
        int ret = 0;

        pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE | ENCODING_YAML,
                                  tc->size);
        if (pdu == NULL) {
                printf("  %s\n", dcerpc_get_error(dce));
                return -1;
        }
        dcerpc_set_request(pdu, tc->req);

        if (dcerpc_do_coder(discard_const(tc->proc), dce, pdu, &iov,
                            ptr, tc->coder)) {
                printf("  YAML encode failed\n");
                ret = -1;
        } else if (iov.offset >= BUF_SIZE) {
                printf("  YAML encoded to %d bytes\n", (int)iov.offset);
                ret = -1;
        } else {
                memset(buf, 0, BUF_SIZE);
                memcpy(buf, iov.buf, iov.offset);
        }
        dcerpc_free_iovec(&iov);
        dcerpc_free_pdu(dce, pdu);
        return ret;
}

static int yaml_compare(const struct flavor *f, const char *got,
                        const char *expected)
{
        if (strcmp(got, expected)) {
                printf("  %s: YAML mismatch\n--- expected\n%s--- got\n%s---\n",
                       f->name, expected, got);
                return -1;
        }
        return 0;
}

static uint64_t get_word(const uint8_t *p, int size, int little_endian)
{
        uint64_t v = 0;
        int i;

        for (i = 0; i < size; i++) {
                v = (v << 8) | p[little_endian ? size - 1 - i : i];
        }
        return v;
}

/*
 * Compare our NDR encoding with a known-good one. Implementations pick
 * their own referent ids, so where we wrote UPTR/RPTR any non-zero
 * referent in the known-good stub matches.
 */
static int ndr_compare(const struct flavor *f, const struct blob *good,
                       const uint8_t *got, int len)
{
        int size = FLAVOR_NDR64(f) ? 8 : 4;
        uint64_t mask = FLAVOR_NDR64(f) ? ~0ULL : 0xffffffffULL;
        int i;

        if (len != good->len) {
                printf("  %s: NDR length %d, expected %d\n",
                       f->name, len, good->len);
                hexdump("expected", good->data, good->len);
                hexdump("got", got, len);
                return -1;
        }
        for (i = 0; i < len; i += size) {
                int n = i + size <= len ? size : len - i;

                if (n == size) {
                        uint64_t g = get_word(&got[i], size, FLAVOR_LITTLE_ENDIAN(f));

                        if ((g == (UPTR & mask) || g == (RPTR & mask)) &&
                            get_word(&good->data[i], size, FLAVOR_LITTLE_ENDIAN(f))) {
                                continue;
                        }
                }
                if (memcmp(&got[i], &good->data[i], n)) {
                        printf("  %s: NDR mismatch at offset %d\n",
                               f->name, i);
                        hexdump("expected", good->data, good->len);
                        hexdump("got", got, len);
                        return -1;
                }
        }
        return 0;
}

/*
 * Test 1: known-good NDR -> YAML -> NDR. Returns 0 on success, -2 when
 * only the final comparison with the known-good NDR differs, -1 on any
 * other failure.
 */
static int test_ndr_yaml_ndr(struct dcerpc_context *dce,
                             const struct test_case *tc,
                             const struct flavor *f, const struct blob *good)
{
        static uint8_t ndr[BUF_SIZE];
        static char yaml[BUF_SIZE];
        struct dcerpc_pdu *pdu;
        void *ptr;
        int len;

        pdu = ndr_decode(dce, tc, f, good->data, good->len, &ptr);
        if (pdu == NULL) {
                return -1;
        }
        if (yaml_encode(dce, tc, ptr, yaml)) {
                dcerpc_free_pdu(dce, pdu);
                return -1;
        }
        dcerpc_free_pdu(dce, pdu);
        if (yaml_compare(f, yaml, tc->yaml)) {
                return -1;
        }

        pdu = yaml_decode(dce, tc, yaml, &ptr);
        if (pdu == NULL) {
                return -1;
        }
        len = ndr_encode(dce, tc, f, ptr, ndr);
        dcerpc_free_pdu(dce, pdu);
        if (len < 0) {
                return -1;
        }
        if (ndr_compare(f, good, ndr, len)) {
                return -2;
        }
        return 0;
}

/* Test 2: known-good YAML -> NDR -> YAML */
static int test_yaml_ndr_yaml(struct dcerpc_context *dce,
                              const struct test_case *tc,
                              const struct flavor *f)
{
        static uint8_t ndr[BUF_SIZE];
        static char yaml[BUF_SIZE];
        struct dcerpc_pdu *pdu;
        void *ptr;
        int len;

        pdu = yaml_decode(dce, tc, tc->yaml, &ptr);
        if (pdu == NULL) {
                return -1;
        }
        len = ndr_encode(dce, tc, f, ptr, ndr);
        dcerpc_free_pdu(dce, pdu);
        if (len < 0) {
                return -1;
        }

        pdu = ndr_decode(dce, tc, f, ndr, len, &ptr);
        if (pdu == NULL) {
                hexdump("NDR", ndr, len);
                return -1;
        }
        if (yaml_encode(dce, tc, ptr, yaml)) {
                dcerpc_free_pdu(dce, pdu);
                return -1;
        }
        dcerpc_free_pdu(dce, pdu);
        if (yaml_compare(f, yaml, tc->yaml)) {
                hexdump("NDR", ndr, len);
                return -1;
        }
        return 0;
}

static void report(const char *test, const struct flavor *f, int ret)
{
        printf("  %-16s %s: %s\n", test, f->name, ret ? "FAIL" : "PASS");
        if (ret) {
                failures++;
        }
}

/* Only a difference in the final NDR comparison counts as expected. */
static void report_xfail(const char *test, const struct flavor *f, int ret,
                         const char *reason)
{
        if (ret == -2) {
                printf("  %-16s %s: XFAIL (%s)\n", test, f->name, reason);
                return;
        }
        if (ret) {
                report(test, f, ret);
                return;
        }
        printf("  %-16s %s: XPASS, remove the xfail marker (%s)\n",
               test, f->name, reason);
        failures++;
}

int run_coder_tests(const struct test_case *cases, int num_cases)
{
        struct dcerpc_context *dce;
        int i, f;

        /* The coders do not need libsmb2 */
        dce = dcerpc_create_context(NULL);
        if (dce == NULL) {
                printf("Failed to create dcerpc context\n");
                return 1;
        }

        for (i = 0; i < num_cases; i++) {
                const struct test_case *tc = &cases[i];

                printf("%s\n", tc->name);
                for (f = 0; f < NUM_FLAVORS; f++) {
                        int ret;

                        if (tc->ndr[f].data == NULL) {
                                continue;
                        }
                        ret = test_ndr_yaml_ndr(dce, tc, &flavors[f],
                                                &tc->ndr[f]);
                        if (tc->xfail & (1u << f)) {
                                report_xfail("NDR->YAML->NDR", &flavors[f],
                                             ret, tc->xfail_reason);
                        } else {
                                report("NDR->YAML->NDR", &flavors[f], ret);
                        }
                }
                for (f = 0; f < NUM_FLAVORS; f++) {
                        report("YAML->NDR->YAML", &flavors[f],
                               test_yaml_ndr_yaml(dce, tc, &flavors[f]));
                }
        }

        dcerpc_destroy_context(dce);

        if (failures) {
                printf("%d test(s) failed\n", failures);
                return 1;
        }
        printf("All tests passed\n");
        return 0;
}
