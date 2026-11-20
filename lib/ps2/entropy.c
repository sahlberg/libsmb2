/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* HMAC_DRBG with SHA-256, SP 800-90A Rev. 1 sections 10.1.2.2-5.
 * The driver serializes access. The EE supplies both entropy and nonce. */
#include "entropy.h"
#include "ps2smb2.h"
#include "../sha.h"
#include <errno.h>
#include <string.h>

static int mac(struct iop_rng *rng, const uint8_t *input, size_t len, uint8_t *result)
{
    return hmac(SHA256, input, len, rng->key, sizeof(rng->key), result);
}

static int update(struct iop_rng *rng, const void *seed, size_t len)
{
    uint8_t input[32 + 1 + SMB2_ENTROPY_SEED_SIZE];
    unsigned int round;

    if (len) {
        memcpy(input + 33, seed, len);
    }
    for (round = 0; round < (len ? 2u : 1u); round++) {
        memcpy(input, rng->value, 32);
        input[32] = (uint8_t)round;
        if (mac(rng, input, 33 + len, rng->key) ||
            mac(rng, rng->value, 32, rng->value)) {
            memset(rng, 0, sizeof(*rng));
            return EIO;
        }
    }
    return 0;
}

int iop_rng_seed(struct iop_rng *rng, const void *seed, size_t len)
{
    int rc;
    if (!seed || len != SMB2_ENTROPY_SEED_SIZE) {
        return EINVAL;
    }
    if (!rng->reseed_counter) {
        memset(rng->key, 0, sizeof(rng->key));
        memset(rng->value, 1, sizeof(rng->value));
    }
    rc = update(rng, seed, len);
    if (!rc) {
        rng->reseed_counter = 1;
    }
    return rc;
}

int iop_rng_generate(struct iop_rng *rng, void *buf, size_t len)
{
    uint8_t *out = buf;

    if (!rng->reseed_counter || rng->reseed_counter == UINT32_MAX) {
        return EAGAIN;
    }
    if (len > 65536 || (!buf && len)) {
        return EINVAL;
    }
    while (len) {
        size_t n = len < sizeof(rng->value) ? len : sizeof(rng->value);
        if (mac(rng, rng->value, sizeof(rng->value), rng->value)) {
            memset(rng, 0, sizeof(*rng));
            return EIO;
        }
        memcpy(out, rng->value, n);
        out += n;
        len -= n;
    }
    rng->reseed_counter++;
    return update(rng, NULL, 0);
}
