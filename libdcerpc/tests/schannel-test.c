/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Known answers for the AES Netlogon secure channel. Password "password",
 * client challenge 0102030405060708, server challenge 1122334455667788.
 * No network. The client credential is AES-128-CFB8 of the client
 * challenge; the server credential is AES-128-CFB8 of the server challenge.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <dcerpc/schannel.h>

static int failures;

#define CHECK(cond) do {                                                \
                if (!(cond)) {                                          \
                        printf("  FAIL %s:%d: %s\n", __FILE__,          \
                               __LINE__, #cond);                        \
                        failures++;                                     \
                }                                                       \
        } while (0)

static const uint8_t client_challenge[8] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};
static const uint8_t server_challenge[8] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

/* 512 bytes of 0x11 followed by a little-endian length of 8. */
static const char trust_ct[] =
        "d3556d3ca5116ec82951acf17f16d5d96f27c9b15456572afd4db47cd069000b"
        "de8695c9687cd45d013164abfee7b6568ce2d65363e3426fdc45a865aa45b739"
        "b59fc2bac3f7b10e160aeb25d458bbf567eb244885ceee35a471816ea8e15675"
        "06f847700d54b4f893b0dc7356646a08da17f27df0f37f58534ff6be8630dae8"
        "49b4e00be457c6cdc7eddd37aec23358ffdb7fff31176c2a56b62f6b8430be97"
        "7888aa991bb647167998c3dda239c6db880c94d8e2e02d58aa201897bb3dc9da"
        "3b29d72067def7967735d985e8c379dbc11e5140e2bc71bcb1ed0c2e0d9ec7f3"
        "c429d68395887302f4b6d29ab7e4a99c104d1a2cd8d4f18a3f422b13c5ede219"
        "66e68e457093d1a500b3d4947c6ae11c7d7feb8004978e0ec7825887441d097d"
        "7b9c43b8f3d867b68898d45c44ea27f88a8f6fd49ad5ba2660bdf935eb10fcd6"
        "d632de38e15ac1bd309a50f8b805903bf7c4dbfd8f29ff7e9f27d324fc4405bb"
        "48c280793853764c45d3e1b5893e903c828c2dc10364bb724ecf7163121c06ba"
        "099ad2afe2ab7717833dfaae41458cc0ce468ae0d8f922c5c8130e7fdac1a22e"
        "6858778df747dd13e33d57c6c5e52742d864f2644b993f2ae8b29f72bb5cea65"
        "7783a5d970a75780657a22ac742f7e9b3162491628000d25ac735e79c161229b"
        "321b4545dde585bce79b2d6795a21c08f59a91e3b1b9e42b421dd64716835f72"
        "7d7d5f44";

static int
from_hex(const char *hex, uint8_t *out, size_t n)
{
        size_t i;

        for (i = 0; i < n; i++) {
                unsigned int b;
                int v;

                v = hex[2 * i];
                if (v >= '0' && v <= '9') {
                        b = (unsigned int)(v - '0');
                } else if (v >= 'a' && v <= 'f') {
                        b = (unsigned int)(v - 'a' + 10);
                } else {
                        return -1;
                }
                v = hex[2 * i + 1];
                b <<= 4;
                if (v >= '0' && v <= '9') {
                        b |= (unsigned int)(v - '0');
                } else if (v >= 'a' && v <= 'f') {
                        b |= (unsigned int)(v - 'a' + 10);
                } else {
                        return -1;
                }
                out[i] = (uint8_t)b;
        }
        return hex[2 * n] == '\0' ? 0 : -1;
}

/* The server credential for these challenges and password */
static const char server_cred[] = "d366d0ea4659d79d";
#define NEGOTIATED (DCERPC_SCHANNEL_AES | 0x00004000u)

static struct dcerpc_schannel *
open_session(void)
{
        struct dcerpc_schannel *sch;
        uint8_t cred[8];

        sch = dcerpc_schannel_create(client_challenge, server_challenge,
                                     "password", DCERPC_SCHANNEL_AES);
        if (sch == NULL) {
                return NULL;
        }
        from_hex(server_cred, cred, 8);
        if (dcerpc_schannel_check_server_credential(sch, cred,
                                                    NEGOTIATED)) {
                dcerpc_schannel_destroy(sch);
                return NULL;
        }
        return sch;
}

static void
test_server_check(void)
{
        struct dcerpc_schannel *sch;
        uint8_t cred[8];
        uint8_t good[8];

        from_hex(server_cred, good, 8);

        /* Nothing works before the server credential is checked */
        sch = dcerpc_schannel_create(client_challenge, server_challenge,
                                     "password", DCERPC_SCHANNEL_AES);
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }
        CHECK(dcerpc_schannel_authenticator(sch, 1, cred) != 0);
        CHECK(dcerpc_schannel_check_server_credential(sch, good,
                                                      NEGOTIATED) == 0);
        CHECK(dcerpc_schannel_authenticator(sch, 1, cred) == 0);
        /* Capabilities over the channel must match what was negotiated */
        CHECK(dcerpc_schannel_check_capabilities(sch, NEGOTIATED) == 0);
        CHECK(dcerpc_schannel_check_capabilities(sch,
                                                 NEGOTIATED & ~0x4000u) != 0);
        CHECK(dcerpc_schannel_authenticator(sch, 1, cred) != 0);
        dcerpc_schannel_destroy(sch);

        /* A wrong server credential */
        sch = dcerpc_schannel_create(client_challenge, server_challenge,
                                     "password", DCERPC_SCHANNEL_AES);
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }
        memcpy(cred, good, 8);
        cred[7] ^= 1;
        CHECK(dcerpc_schannel_check_server_credential(sch, cred,
                                                      NEGOTIATED) != 0);
        CHECK(dcerpc_schannel_check_server_credential(sch, good,
                                                      NEGOTIATED) != 0);
        dcerpc_schannel_destroy(sch);

        /* A server that dropped AES */
        sch = dcerpc_schannel_create(client_challenge, server_challenge,
                                     "password", DCERPC_SCHANNEL_AES);
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }
        CHECK(dcerpc_schannel_check_server_credential(sch, good,
                                                      0x00004000u) != 0);
        dcerpc_schannel_destroy(sch);
}

static void
test_credentials(void)
{
        struct dcerpc_schannel *sch;
        uint8_t cred[8];
        uint8_t want[8];
        uint8_t bad[8];

        CHECK(dcerpc_schannel_create(client_challenge, server_challenge,
                                      "password", 0) == NULL);
        CHECK(dcerpc_schannel_create(NULL, server_challenge, "password",
                                      DCERPC_SCHANNEL_AES) == NULL);
        {
                /* first five bytes the same: refused, as by servers */
                uint8_t weak[8] = { 7, 7, 7, 7, 7, 1, 2, 3 };
                uint8_t chal[8];
                int i, same = 1;

                CHECK(dcerpc_schannel_create(weak, server_challenge,
                                             "password",
                                             DCERPC_SCHANNEL_AES) == NULL);
                CHECK(dcerpc_schannel_client_challenge(chal) == 0);
                for (i = 1; i < 5; i++) {
                        if (chal[i] != chal[0]) {
                                same = 0;
                        }
                }
                CHECK(!same);
        }

        sch = open_session();
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }

        from_hex("c3884ad84aa4a079", want, 8);
        dcerpc_schannel_client_credential(sch, cred);
        CHECK(memcmp(cred, want, 8) == 0);

        from_hex("d366d0ea4659d79d", want, 8);
        dcerpc_schannel_server_credential(sch, cred);
        CHECK(memcmp(cred, want, 8) == 0);

        CHECK(dcerpc_schannel_authenticator(sch, 1, cred) == 0);
        from_hex("062e3572dfffbe88", want, 8);
        CHECK(memcmp(cred, want, 8) == 0);

        from_hex("0764724c74f9792a", want, 8);
        CHECK(dcerpc_schannel_check_authenticator(sch, want) == 0);
        /* A replay fails, and ends the session */
        CHECK(dcerpc_schannel_check_authenticator(sch, want) != 0);
        CHECK(dcerpc_schannel_authenticator(sch, 1, cred) != 0);
        dcerpc_schannel_destroy(sch);

        /* A wrong authenticator ends the session: no second try */
        sch = open_session();
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }
        CHECK(dcerpc_schannel_authenticator(sch, 1, cred) == 0);
        memset(bad, 0xff, 8);
        CHECK(dcerpc_schannel_check_authenticator(sch, bad) != 0);
        from_hex("0764724c74f9792a", want, 8);
        CHECK(dcerpc_schannel_check_authenticator(sch, want) != 0);
        dcerpc_schannel_destroy(sch);
}

static void
test_trust_password(void)
{
        struct dcerpc_schannel *sch;
        uint8_t buf[516];
        uint8_t want[516];
        int i;

        sch = open_session();
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }
        memset(buf, 0x11, 512);
        buf[512] = 8;
        buf[513] = 0;
        buf[514] = 0;
        buf[515] = 0;
        CHECK(from_hex(trust_ct, want, 516) == 0);
        CHECK(dcerpc_schannel_encrypt_trust_password(sch, buf) == 0);
        CHECK(memcmp(buf, want, 516) == 0);
        for (i = 0; i < 516; i++) {
                if (buf[i] != want[i]) {
                        printf("  trust differs at %d\n", i);
                        break;
                }
        }
        dcerpc_schannel_destroy(sch);
}

/*
 * A fake request (tag 0) or response (tag 2) PDU: 24 header bytes, then
 * the 8 bytes sealed (stub "hello" and 3 pad), then an 8-byte
 * sec_trailer. The whole PDU is signed, as with header signing.
 */
#define DATA_OFS 24
#define DATA_LEN 8
#define PDU_LEN 40

static void
fake_pdu(uint8_t tag, uint8_t pdu[PDU_LEN])
{
        static const uint8_t trailer[8] = { 68, 6, 3, 0, 0, 0, 0, 0 };

        memset(pdu, 0, PDU_LEN);
        pdu[0] = 5;
        pdu[2] = tag;
        pdu[3] = 3;
        memcpy(pdu + DATA_OFS, "hello", 5);
        memcpy(pdu + DATA_OFS + DATA_LEN, trailer, 8);
}

/*
 * From an independent Python model of Samba's netsec_outgoing_packet():
 * one sequence number for the channel, client messages 0 (sealed) and 1
 * (signed), then server replies 2 (sealed) and 3 (signed).
 */
static const char c0_tok[] =
        "13001a00ffff00001ea81e2c5cd2f379ad6f1bf65526477f10eb4a54182477fe";
static const char c0_data[] = "4cfb96b27f4838b6";
static const char c1_tok[] =
        "1300ffffffff0000a7f30b887f1db1836c463601579c1859";
static const char s2_tok[] =
        "13001a00ffff00005b9fce2141cfde8db1c29b1ea0bd284860a4a677778ed546";
static const char s2_data[] = "caee32be5d855c3b";
static const char s3_tok[] =
        "1300ffffffff00009d12098a2e426c45e7e677571070412f";

/* The two requests a session sends before the tests' replies */
static void
send_requests(struct dcerpc_schannel *sch, uint8_t token[56])
{
        static const uint8_t confounder[8] = {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        };
        uint8_t pdu[PDU_LEN];
        uint8_t want[56];

        fake_pdu(0, pdu);
        CHECK(dcerpc_schannel_protect(sch, 1, pdu + DATA_OFS, DATA_LEN,
                                      pdu, PDU_LEN, confounder,
                                      token) == 0);
        memset(want, 0, sizeof(want));
        from_hex(c0_tok, want, 32);
        CHECK(memcmp(token, want, 56) == 0);
        from_hex(c0_data, want, DATA_LEN);
        CHECK(memcmp(pdu + DATA_OFS, want, DATA_LEN) == 0);

        fake_pdu(0, pdu);
        CHECK(dcerpc_schannel_protect(sch, 0, NULL, 0, pdu, PDU_LEN,
                                      NULL, token) == 0);
        memset(want, 0, sizeof(want));
        from_hex(c1_tok, want, 24);
        CHECK(memcmp(token, want, 56) == 0);
}

/* The sealed reply s2, as it arrives */
static void
sealed_reply(uint8_t pdu[PDU_LEN], uint8_t token[56])
{
        fake_pdu(2, pdu);
        from_hex(s2_data, pdu + DATA_OFS, DATA_LEN);
        memset(token, 0, 56);
        from_hex(s2_tok, token, 32);
}

static void
test_protect(void)
{
        struct dcerpc_schannel *sch;
        uint8_t token[56];
        uint8_t pdu[PDU_LEN];
        uint8_t plain[PDU_LEN];

        sch = open_session();
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }
        send_requests(sch, token);

        /* The sealed reply unseals to the plaintext PDU */
        sealed_reply(pdu, token);
        CHECK(dcerpc_schannel_unprotect(sch, 1, pdu + DATA_OFS, DATA_LEN,
                                        pdu, PDU_LEN, token, 56) == 0);
        fake_pdu(2, plain);
        CHECK(memcmp(pdu, plain, PDU_LEN) == 0);

        /* The signed reply, with its token cut after the checksum */
        fake_pdu(2, pdu);
        memset(token, 0, sizeof(token));
        from_hex(s3_tok, token, 24);
        CHECK(dcerpc_schannel_unprotect(sch, 0, NULL, 0, pdu, PDU_LEN,
                                        token, 48) == 0);

        /* A replay fails, and ends the session */
        CHECK(dcerpc_schannel_unprotect(sch, 0, NULL, 0, pdu, PDU_LEN,
                                        token, 48) != 0);
        CHECK(dcerpc_schannel_protect(sch, 0, NULL, 0, pdu, PDU_LEN,
                                      NULL, token) != 0);
        dcerpc_schannel_destroy(sch);

        /*
         * A change to a signed byte that is not sealed (the header)
         * fails, the forged plaintext is cleared, and the real reply is
         * not let in after.
         */
        sch = open_session();
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }
        send_requests(sch, token);
        sealed_reply(pdu, token);
        pdu[3] ^= 0x01;
        CHECK(dcerpc_schannel_unprotect(sch, 1, pdu + DATA_OFS, DATA_LEN,
                                        pdu, PDU_LEN, token, 56) != 0);
        memset(plain, 0, DATA_LEN);
        CHECK(memcmp(pdu + DATA_OFS, plain, DATA_LEN) == 0);
        sealed_reply(pdu, token);
        CHECK(dcerpc_schannel_unprotect(sch, 1, pdu + DATA_OFS, DATA_LEN,
                                        pdu, PDU_LEN, token, 56) != 0);
        dcerpc_schannel_destroy(sch);

        /* A sealed token is not a signed-only one, and the reverse */
        sch = open_session();
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }
        send_requests(sch, token);
        sealed_reply(pdu, token);
        CHECK(dcerpc_schannel_unprotect(sch, 0, NULL, 0, pdu, PDU_LEN,
                                        token, 56) != 0);
        dcerpc_schannel_destroy(sch);

        /* A token too short for its kind */
        sch = open_session();
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }
        send_requests(sch, token);
        sealed_reply(pdu, token);
        CHECK(dcerpc_schannel_unprotect(sch, 1, pdu + DATA_OFS, DATA_LEN,
                                        pdu, PDU_LEN, token, 48) != 0);
        dcerpc_schannel_destroy(sch);

        /* An initiator's token is not one this side can unprotect */
        sch = open_session();
        CHECK(sch != NULL);
        if (sch == NULL) {
                return;
        }
        fake_pdu(0, pdu);
        CHECK(dcerpc_schannel_protect(sch, 0, NULL, 0, pdu, PDU_LEN,
                                      NULL, token) == 0);
        CHECK(dcerpc_schannel_unprotect(sch, 0, NULL, 0, pdu, PDU_LEN,
                                        token, 56) != 0);
        dcerpc_schannel_destroy(sch);
}

int
main(void)
{
        test_credentials();
        test_server_check();
        test_trust_password();
        test_protect();
        if (failures) {
                printf("%d failures\n", failures);
                return 1;
        }
        return 0;
}
