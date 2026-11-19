/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef SMB2_IOP_ENTROPY_H
#define SMB2_IOP_ENTROPY_H
#include <stddef.h>
#include <stdint.h>

struct iop_rng {
    uint8_t key[32], value[32];
    uint32_t reseed_counter;
};

int iop_rng_seed(struct iop_rng *rng, const void *seed, size_t len);
int iop_rng_generate(struct iop_rng *rng, void *buf, size_t len);
#endif
