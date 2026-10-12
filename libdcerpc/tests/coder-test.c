/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <dcerpc/dcerpc.h>

#include "coder-test.h"

/* libdcerpc test hooks: force the transfer syntax and byte order */
void ndr_set_tctx(struct dcerpc_context *ctx, int tctx);
void ndr_set_endian(struct dcerpc_pdu *pdu, int little_endian);

/* Referent ids libdcerpc writes for unique and ref pointers */
#define UPTR 0x5570747272747055ULL
#define RPTR 0x5270747272747052ULL

#define BUF_SIZE 65536

struct flavor {
        const char *name;
        int ndr64;
        int little_endian;
};

static const struct flavor flavors[NUM_FLAVORS] = {
        [NDR32_LE] = { "NDR32 LE", 0, 1 },
        [NDR32_BE] = { "NDR32 BE", 0, 0 },
        [NDR64_LE] = { "NDR64 LE", 1, 1 },
        [NDR64_BE] = { "NDR64 BE", 1, 0 },
};

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
 * The decoder byte-swaps big-endian UTF-16 strings in place, so it gets a
 * writable copy of buf.
 */
static struct dcerpc_pdu *ndr_decode(struct dcerpc_context *dce,
                                     const struct test_case *tc,
                                     const struct flavor *f,
                                     const uint8_t *buf, int len,
                                     void **ptr)
{
        static uint8_t copy[BUF_SIZE];
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov;
        int offset = 0;

        if (len > BUF_SIZE) {
                printf("  %s: NDR stub too large\n", f->name);
                return NULL;
        }
        memcpy(copy, buf, len);

        ndr_set_tctx(dce, f->ndr64);
        pdu = dcerpc_allocate_pdu(dce, ENCODING_NDR, DCERPC_DECODE,
                                  tc->size);
        ndr_set_endian(pdu, f->little_endian);
        dcerpc_set_request(pdu, tc->req);
        *ptr = dcerpc_get_pdu_payload(pdu);

        iov.buf = copy;
        iov.len = len;
        iov.free = NULL;
        if (tc->coder(tc->req ? "Response" : "Request", dce, pdu, &iov,
                      &offset, *ptr)) {
                printf("  %s: NDR decode failed\n", f->name);
                dcerpc_free_pdu(dce, pdu);
                return NULL;
        }
        if (offset != len) {
                printf("  %s: NDR decode consumed %d of %d bytes\n",
                       f->name, offset, len);
                dcerpc_free_pdu(dce, pdu);
                return NULL;
        }
        return pdu;
}

/* struct -> NDR. Returns the encoded length or -1. */
static int ndr_encode(struct dcerpc_context *dce, const struct test_case *tc,
                      const struct flavor *f, void *ptr, uint8_t *buf)
{
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov;
        int offset = 0;

        ndr_set_tctx(dce, f->ndr64);
        pdu = dcerpc_allocate_pdu(dce, ENCODING_NDR, DCERPC_ENCODE,
                                  tc->size);
        ndr_set_endian(pdu, f->little_endian);
        dcerpc_set_request(pdu, tc->req);

        memset(buf, 0, BUF_SIZE);
        iov.buf = buf;
        iov.len = BUF_SIZE;
        iov.free = NULL;
        if (tc->coder(tc->req ? "Response" : "Request", dce, pdu, &iov,
                      &offset, ptr)) {
                printf("  %s: NDR encode failed\n", f->name);
                offset = -1;
        }
        dcerpc_free_pdu(dce, pdu);
        return offset;
}

/* YAML -> struct. The struct lives in the returned pdu's payload. */
static struct dcerpc_pdu *yaml_decode(struct dcerpc_context *dce,
                                      const struct test_case *tc,
                                      const char *yaml, void **ptr)
{
        static uint8_t buf[BUF_SIZE];
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov;
        int offset = 0;

        pdu = dcerpc_allocate_pdu(dce, ENCODING_YAML, DCERPC_DECODE,
                                  tc->size);
        dcerpc_set_request(pdu, tc->req);
        *ptr = dcerpc_get_pdu_payload(pdu);

        memset(buf, 0, sizeof(buf));
        strcpy((char *)buf, yaml);
        iov.buf = buf;
        iov.len = strlen(yaml) + 1;
        iov.free = NULL;
        if (dcerpc_do_coder(discard_const(tc->proc), dce, pdu, &iov, &offset,
                            *ptr, tc->coder)) {
                printf("  YAML decode failed\n");
                dcerpc_free_pdu(dce, pdu);
                return NULL;
        }
        return pdu;
}

/* struct -> YAML, into buf (NUL terminated). Returns 0 on success. */
static int yaml_encode(struct dcerpc_context *dce, const struct test_case *tc,
                       void *ptr, char *buf)
{
        struct dcerpc_pdu *pdu;
        struct dcerpc_iovec iov;
        int offset = 0;
        int ret = 0;

        pdu = dcerpc_allocate_pdu(dce, ENCODING_YAML, DCERPC_ENCODE,
                                  tc->size);
        dcerpc_set_request(pdu, tc->req);

        memset(buf, 0, BUF_SIZE);
        iov.buf = (uint8_t *)buf;
        iov.len = BUF_SIZE - 1;
        iov.free = NULL;
        if (dcerpc_do_coder(discard_const(tc->proc), dce, pdu, &iov, &offset,
                            ptr, tc->coder)) {
                printf("  YAML encode failed\n");
                ret = -1;
        }
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
        int size = f->ndr64 ? 8 : 4;
        uint64_t mask = f->ndr64 ? ~0ULL : 0xffffffffULL;
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
                        uint64_t g = get_word(&got[i], size, f->little_endian);

                        if ((g == (UPTR & mask) || g == (RPTR & mask)) &&
                            get_word(&good->data[i], size, f->little_endian)) {
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
        struct smb2_context *smb2;
        struct dcerpc_context *dce;
        int i, f;

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                printf("Failed to create smb2 context\n");
                return 1;
        }
        dce = dcerpc_create_context(smb2);
        if (dce == NULL) {
                printf("Failed to create dcerpc context: %s\n",
                       smb2_get_error(smb2));
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
        smb2_destroy_context(smb2);

        if (failures) {
                printf("%d test(s) failed\n", failures);
                return 1;
        }
        printf("All tests passed\n");
        return 0;
}
