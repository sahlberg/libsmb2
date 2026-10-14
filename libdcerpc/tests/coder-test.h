/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */

/*
 * Shared engine for the coder transcoding tests. Each test program holds
 * the known-good NDR and YAML for one interface in a struct test_case
 * table and calls run_coder_tests().
 *
 * Test 1, NDR -> YAML -> NDR: decode a known-good NDR stub, check that it
 * transcodes to the known-good YAML, then transcode that YAML back to NDR
 * and check it is identical to the original stub.
 *
 * Test 2, YAML -> NDR -> YAML: start from the known-good YAML, transcode
 * it to NDR and back, and check the YAML is identical. This runs for every
 * case in all four flavors: NDR32/NDR64, little-endian/big-endian.
 */

#ifndef _CODER_TEST_H_
#define _CODER_TEST_H_

#include <stdint.h>
#include <dcerpc/dcerpc.h>

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

enum {
        NDR32_LE,
        NDR32_BE,
        NDR64_LE,
        NDR64_BE,
        NUM_FLAVORS
};

struct blob {
        const uint8_t *data;
        int len;
};

struct test_case {
        const char *name;
        const char *proc;
        dcerpc_coder coder;
        int size;
        /*
         * For a reply: its request. The YAML coders print "Response" when
         * the PDU has one, and GetInfo replies take their union switch
         * (Level) from it. NULL for a request.
         */
        void *req;
        const char *yaml;
        /* known-good NDR stub per flavor, NULL where there is none */
        struct blob ndr[NUM_FLAVORS];
        /*
         * Flavors whose NDR->YAML->NDR test is known to re-encode to
         * different NDR, as a bitmask of (1 << flavor), and why. Only that
         * final comparison may differ: they are reported as XFAIL, as a
         * failure if anything else fails, and as a failure if they
         * unexpectedly pass.
         */
        unsigned int xfail;
        const char *xfail_reason;
        /*
         * For a reply: the highest full pointer id of its request, which
         * the reply's full pointers continue after. 0 when it has none.
         */
        uint64_t full_ptr_base;
};

int run_coder_tests(const struct test_case *cases, int num_cases);

#endif /* !_CODER_TEST_H_ */
