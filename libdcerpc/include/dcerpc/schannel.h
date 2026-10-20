/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _DCERPC_SCHANNEL_H_
#define _DCERPC_SCHANNEL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * AES Netlogon secure channel, [MS-NRPC] 3.1.4.3.1 through 3.3.4.2.1.
 * The caller owns the connection. These functions produce credentials,
 * authenticators, the encrypted trust password, and sealed buffers.
 *
 * NEG_SUPPORTS_AES (0x01000000) is required. RC4 is not implemented.
 * A client credential of eight zero bytes is refused.
 */
#define DCERPC_SCHANNEL_AES 0x01000000u

/* Bytes in an NL_AUTH_SHA2_SIGNATURE token, which is auth_length. */
#define DCERPC_SCHANNEL_TOKEN_LEN 56

struct dcerpc_schannel;

/*
 * machine_password is the clear machine password, UTF-8. The session key
 * is the first 16 bytes of HMAC-SHA256(MD4(UTF-16LE password),
 * client_challenge || server_challenge).
 * Returns NULL on allocation failure, a missing AES flag, or a zero
 * client credential.
 */
struct dcerpc_schannel *dcerpc_schannel_create(
        const uint8_t client_challenge[8],
        const uint8_t server_challenge[8],
        const char *machine_password,
        uint32_t negotiate_flags);
void dcerpc_schannel_destroy(struct dcerpc_schannel *sch);

/* Credentials exchanged by ServerAuthenticate3. */
void dcerpc_schannel_client_credential(const struct dcerpc_schannel *sch,
                                       uint8_t cred[8]);
void dcerpc_schannel_server_credential(const struct dcerpc_schannel *sch,
                                       uint8_t cred[8]);

/*
 * Check the ServerAuthenticate3 reply: the server's credential, which
 * only a server knowing the machine password can produce, and the flags
 * it negotiated, which must keep AES. Until this succeeds every call
 * below fails; if it fails, the session is unusable.
 */
int dcerpc_schannel_check_server_credential(struct dcerpc_schannel *sch,
                                            const uint8_t cred[8],
                                            uint32_t negotiated_flags);

/*
 * [MS-NRPC] 3.4.5.2.10: the ServerCapabilities LogonGetCapabilities
 * returns over the secure channel must equal the flags negotiated in
 * the clear; anything else means the negotiation was tampered with, and
 * the session is unusable.
 */
int dcerpc_schannel_check_capabilities(struct dcerpc_schannel *sch,
                                       uint32_t capabilities);

/*
 * Next client authenticator. timestamp is seconds since the Unix epoch.
 * The low 4 bytes of the stored seed are increased by timestamp, with no
 * carry into the high 4, and the result is encrypted.
 */
int dcerpc_schannel_authenticator(struct dcerpc_schannel *sch,
                                  uint32_t timestamp,
                                  uint8_t cred[8]);

/*
 * Check the server's return authenticator for the authenticator() just
 * sent. On success the seed advances by one.
 *
 * A failed check, here or in unseal(), means the channel can no longer
 * be trusted: every call on sch fails from then on, and the caller must
 * set up a new secure channel.
 */
int dcerpc_schannel_check_authenticator(struct dcerpc_schannel *sch,
                                        const uint8_t cred[8]);

/*
 * Encrypt a 516-byte NL_TRUST_PASSWORD in place: 512-byte buffer, then
 * the length as a little-endian uint32. AES-128-CFB8, session key, zero IV.
 */
int dcerpc_schannel_encrypt_trust_password(const struct dcerpc_schannel *sch,
                                           uint8_t password[516]);

/*
 * Seal plain[0..len) into crypt[0..len). token receives the 56-byte
 * signature. confounder is 8 bytes, or NULL to read them from /dev/urandom.
 * crypt and plain may be the same buffer. This is the initiator direction.
 */
int dcerpc_schannel_seal(struct dcerpc_schannel *sch,
                         const uint8_t *plain, size_t len,
                         const uint8_t *confounder,
                         uint8_t *crypt,
                         uint8_t token[DCERPC_SCHANNEL_TOKEN_LEN]);

/*
 * Unseal a token written by the acceptor (no initiator bit in the
 * sequence). crypt and plain may be the same buffer.
 */
int dcerpc_schannel_unseal(struct dcerpc_schannel *sch,
                           const uint8_t *crypt, size_t len,
                           const uint8_t token[DCERPC_SCHANNEL_TOKEN_LEN],
                           uint8_t *plain);

#ifdef __cplusplus
}
#endif

#endif /* _DCERPC_SCHANNEL_H_ */
