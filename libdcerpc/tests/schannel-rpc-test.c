/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


/*
 * Schannel over the RPC layer, without a network: the test provides the
 * smb2_cmd_*_async() calls libdcerpc makes (it is linked with
 * --allow-multiple-definition) and plays the server. The secure channel
 * is that of schannel-test.c (password "password", client challenge
 * 0102030405060708, server challenge 1122334455667788), so the session
 * key is known.
 *
 * Checked: the auth trailer of the BIND and of the BIND_ACK, a signed
 * request byte for byte (with and without header signing) and the
 * shape of a sealed one, signed and sealed replies, and that a tampered
 * reply ends the channel. The expected requests and the replies come
 * from an independent model of Samba's netsec_outgoing_packet(): sign
 * before seal, one sequence number per channel (the request takes 0,
 * its reply 1). ad-adc (Windows Server 2016) accepted requests built
 * this way and its replies verified.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#include <dcerpc/dcerpc.h>
#include <dcerpc/schannel.h>

static int failures;

#define CHECK(cond) do {                                                \
                if (!(cond)) {                                          \
                        printf("  FAIL %s:%d: %s\n", __FILE__,          \
                               __LINE__, #cond);                        \
                        failures++;                                     \
                }                                                       \
        } while (0)

/* ---------------------------------------------------- fake transport */

static smb2_command_cb last_cb;
static void *last_priv;
static uint8_t sent[8192];
static size_t sent_len;
static int dummy_pdu;

struct smb2_pdu *
smb2_cmd_create_async(struct smb2_context *smb2 _U_,
                      struct smb2_create_request *req _U_,
                      smb2_command_cb cb, void *cb_data)
{
        last_cb = cb;
        last_priv = cb_data;
        return (struct smb2_pdu *)&dummy_pdu;
}

struct smb2_pdu *
smb2_cmd_ioctl_async(struct smb2_context *smb2 _U_,
                     struct smb2_ioctl_request *req,
                     smb2_command_cb cb, void *cb_data)
{
        last_cb = cb;
        last_priv = cb_data;
        sent_len = req->input_count < sizeof(sent) ? req->input_count : 0;
        memcpy(sent, req->input, sent_len);
        return (struct smb2_pdu *)&dummy_pdu;
}

struct smb2_pdu *
smb2_cmd_write_async(struct smb2_context *smb2 _U_,
                     struct smb2_write_request *req _U_, int flags _U_,
                     smb2_command_cb cb, void *cb_data)
{
        last_cb = cb;
        last_priv = cb_data;
        return (struct smb2_pdu *)&dummy_pdu;
}

struct smb2_pdu *
smb2_cmd_close_async(struct smb2_context *smb2 _U_,
                     struct smb2_close_request *req _U_,
                     smb2_command_cb cb _U_, void *cb_data _U_)
{
        return NULL;
}

void
smb2_queue_pdu(struct smb2_context *smb2 _U_, struct smb2_pdu *pdu _U_)
{
}

/* The replies the test hands over are malloc()ed */
void
smb2_free_data(struct smb2_context *smb2 _U_, void *ptr)
{
        free(ptr);
}

/* Answer the last command with an ioctl reply holding a copy of buf */
static void
reply(struct smb2_context *smb2, uint32_t status, const uint8_t *buf,
      size_t len)
{
        struct smb2_ioctl_reply rep;

        memset(&rep, 0, sizeof(rep));
        rep.output = malloc(len);
        memcpy(rep.output, buf, len);
        rep.output_count = (uint32_t)len;
        last_cb(smb2, status, &rep, last_priv);
}

/* ---------------------------------------------------- the vectors */

#include "schannel-rpc-vectors.h"

static p_syntax_id_t netlogon_syntax = {
        { 0x12345678, 0x1234, 0xabcd,
          { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb } }, 1, 0
};

static void
put16(uint8_t *b, uint16_t v)
{
        b[0] = (uint8_t)v;
        b[1] = (uint8_t)(v >> 8);
}

static void
put32(uint8_t *b, uint32_t v)
{
        b[0] = (uint8_t)v;
        b[1] = (uint8_t)(v >> 8);
        b[2] = (uint8_t)(v >> 16);
        b[3] = (uint8_t)(v >> 24);
}

/*
 * A BIND_ACK accepting NDR32 for call_id 2, shaped as ad-adc's: with
 * auth, a sec_trailer for our level and context id and a 12-byte
 * NL_AUTH_MESSAGE NEGOTIATE_RESPONSE.
 */
static size_t
bind_ack(uint8_t *b, int level, int hsign, int with_auth)
{
        static const uint8_t ndr32[20] = {
                0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
                0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
                0x02, 0x00, 0x00, 0x00
        };
        size_t o;

        memset(b, 0, 128);
        b[0] = 5;
        b[2] = 12;
        b[3] = 0x03 | (hsign ? 0x04 : 0);
        b[4] = 0x10;
        put32(b + 12, 2);
        put16(b + 16, 4280);
        put16(b + 18, 4280);
        put32(b + 20, 0x37a9);
        o = 28;                 /* no secondary address */
        b[o] = 1;               /* one result */
        o += 8;                 /* accepted, reason 0 */
        memcpy(b + o, ndr32, 20);
        o += 20;
        if (with_auth) {
                b[o] = 68;
                b[o + 1] = (uint8_t)level;
                put32(b + o + 4, 1);
                o += 8;
                put32(b + o, 1);
                o += 12;
        }
        put16(b + 8, (uint16_t)o);
        put16(b + 10, with_auth ? 12 : 0);
        return o;
}

static int cb_status;
static int cb_done;

static void
call_cb(struct dcerpc_context *dce _U_, int status, void *data,
        void *cb_data _U_)
{
        cb_status = status;
        cb_done = 1;
        if (data) {
                dcerpc_free_data(dce, data);
        }
}

/* The stubs: 20 bytes each, the request's i*7+1, the reply's i*13+5 */
#define STUB_LEN 20
static uint8_t got[STUB_LEN];

static int
req_coder(char *name _U_, struct dcerpc_context *dce,
          struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov, void *ptr _U_)
{
        uint8_t i, v;

        for (i = 0; i < STUB_LEN; i++) {
                v = (uint8_t)(i * 7 + 1);
                if (dcerpc_uint8_coder("b", dce, pdu, iov, &v)) {
                        return -1;
                }
        }
        return 0;
}

static int
rep_coder(char *name _U_, struct dcerpc_context *dce,
          struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov, void *ptr _U_)
{
        uint8_t i;

        for (i = 0; i < STUB_LEN; i++) {
                if (dcerpc_uint8_coder("b", dce, pdu, iov, &got[i])) {
                        return -1;
                }
        }
        return 0;
}

static int
rep_stub_ok(void)
{
        uint8_t i;

        for (i = 0; i < STUB_LEN; i++) {
                if (got[i] != (uint8_t)(i * 13 + 5)) {
                        return 0;
                }
        }
        return 1;
}

/* ---------------------------------------------------- one session */

struct session {
        struct smb2_context *smb2;
        struct dcerpc_context *dce;
        struct dcerpc_schannel *sch;
};

static void
session_close(struct session *s)
{
        dcerpc_destroy_context(s->dce);
        dcerpc_schannel_destroy(s->sch);
        smb2_destroy_context(s->smb2);
}

/* A secure channel and a context for it, opened and bound */
static int
session_open(struct session *s, int level, int hsign, int ack_auth)
{
        static const uint8_t cc[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        static const uint8_t sc[8] = {
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
        };
        struct smb2_create_reply cr;
        uint8_t cred[8], b[128];

        s->smb2 = smb2_init_context();
        s->dce = dcerpc_create_context(s->smb2);
        s->sch = dcerpc_schannel_create(cc, sc, "password",
                                        DCERPC_SCHANNEL_AES);
        if (s->smb2 == NULL || s->dce == NULL || s->sch == NULL) {
                return -1;
        }
        dcerpc_schannel_server_credential(s->sch, cred);
        if (dcerpc_schannel_check_server_credential(s->sch, cred,
                                                    DCERPC_SCHANNEL_AES) ||
            dcerpc_set_schannel(s->dce, s->sch, level, "AD",
                                "TESTHOST")) {
                return -1;
        }
        cb_done = 0;
        if (dcerpc_connect_context_async(s->dce, "netlogon",
                                         &netlogon_syntax, call_cb, NULL)) {
                return -1;
        }
        memset(&cr, 0, sizeof(cr));
        cr.file_id[0] = 1;
        last_cb(s->smb2, 0, &cr, last_priv);
        reply(s->smb2, 0, b, bind_ack(b, level, hsign, ack_auth));
        return cb_done ? cb_status : -1;
}

/* Send the 20-byte request; the fragment sent is in sent[] */
static int
session_call(struct session *s)
{
        cb_done = 0;
        sent_len = 0;
        return dcerpc_call_async(s->dce, 0x15, req_coder, NULL, rep_coder,
                                 8, call_cb, NULL);
}

/* ---------------------------------------------------- the tests */

static void
test_bind(void)
{
        /* auth type 68, level 5, no pad, context id 1, then the
         * NL_AUTH_MESSAGE: NEGOTIATE_REQUEST, both OEM NetBIOS names */
        static const uint8_t trailer[28] = {
                0x44, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                'A', 'D', 0, 'T', 'E', 'S', 'T', 'H', 'O', 'S', 'T', 0
        };
        struct session s;

        printf("BIND and BIND_ACK auth trailers\n");
        CHECK(session_open(&s, DCERPC_AUTH_LEVEL_INTEGRITY, 1, 1) == 0);
        /* the BIND offers header signing and carries the trailer */
        CHECK((sent[3] & 0x04) != 0);
        CHECK(sent_len == (size_t)(sent[8] | (sent[9] << 8)));
        CHECK(sent[10] == 20 && sent[11] == 0);
        CHECK(sent_len >= sizeof(trailer) &&
              memcmp(sent + sent_len - sizeof(trailer), trailer,
                     sizeof(trailer)) == 0);
        session_close(&s);

        /* too late once bound */
        CHECK(session_open(&s, DCERPC_AUTH_LEVEL_INTEGRITY, 1, 1) == 0);
        CHECK(dcerpc_set_schannel(s.dce, s.sch, DCERPC_AUTH_LEVEL_PRIVACY,
                                  "AD", "TESTHOST") != 0);
        session_close(&s);

        /* a BIND_ACK that does not take the auth is refused */
        CHECK(session_open(&s, DCERPC_AUTH_LEVEL_INTEGRITY, 1, 0) != 0);
        session_close(&s);
}

static void
test_signed(int hsign, const uint8_t *req, size_t req_len,
            const uint8_t *rep, size_t rep_len)
{
        struct session s;

        printf("signed request and reply, header signing %s\n",
               hsign ? "on" : "off");
        CHECK(session_open(&s, DCERPC_AUTH_LEVEL_INTEGRITY, hsign, 1) == 0);
        CHECK(session_call(&s) == 0);
        CHECK(sent_len == req_len && memcmp(sent, req, req_len) == 0);
        memset(got, 0, sizeof(got));
        reply(s.smb2, 0, rep, rep_len);
        CHECK(cb_done && cb_status == 0);
        CHECK(rep_stub_ok());
        session_close(&s);
}

static void
test_sealed(void)
{
        static const uint8_t token_hdr[8] = {
                0x13, 0x00, 0x1a, 0x00, 0xff, 0xff, 0x00, 0x00
        };
        struct session s;
        uint8_t i;
        int plain = 1;

        printf("sealed request and reply\n");
        CHECK(session_open(&s, DCERPC_AUTH_LEVEL_PRIVACY, 1, 1) == 0);
        CHECK(session_call(&s) == 0);
        /*
         * The confounder is random, so check the shape: the same
         * lengths and trailer as the signed request, a sealing token,
         * and a stub that is no longer the plaintext.
         */
        CHECK(sent_len == sizeof(req_l5_hsign));
        CHECK(memcmp(sent, req_l5_hsign, 24) == 0);
        CHECK(sent[56] == 68 && sent[57] == 6 && sent[58] == 12);
        CHECK(memcmp(sent + 64, token_hdr, 8) == 0);
        for (i = 0; i < STUB_LEN; i++) {
                if (sent[24 + i] != (uint8_t)(i * 7 + 1)) {
                        plain = 0;
                }
        }
        CHECK(!plain);
        memset(got, 0, sizeof(got));
        reply(s.smb2, 0, rep_l6_hsign, sizeof(rep_l6_hsign));
        CHECK(cb_done && cb_status == 0);
        CHECK(rep_stub_ok());
        session_close(&s);
}

static void
test_refused(void)
{
        uint8_t bad[sizeof(rep_l5_hsign)];
        uint8_t fault[32];
        struct session s;

        printf("tampered and unprotected replies\n");
        /* a changed header byte fails the signature and ends the channel */
        CHECK(session_open(&s, DCERPC_AUTH_LEVEL_INTEGRITY, 1, 1) == 0);
        CHECK(session_call(&s) == 0);
        memcpy(bad, rep_l5_hsign, sizeof(bad));
        bad[20] ^= 0x01;
        reply(s.smb2, 0, bad, sizeof(bad));
        CHECK(cb_done && cb_status != 0);
        CHECK(session_call(&s) != 0);
        session_close(&s);

        /* a reply without its auth trailer */
        CHECK(session_open(&s, DCERPC_AUTH_LEVEL_INTEGRITY, 1, 1) == 0);
        CHECK(session_call(&s) == 0);
        memcpy(bad, rep_l5_hsign, 24 + 32);
        put16(bad + 8, 24 + 32);
        put16(bad + 10, 0);
        reply(s.smb2, 0, bad, 24 + 32);
        CHECK(cb_done && cb_status != 0);
        session_close(&s);

        /* a lone unsigned FAULT is still a fault */
        CHECK(session_open(&s, DCERPC_AUTH_LEVEL_INTEGRITY, 1, 1) == 0);
        CHECK(session_call(&s) == 0);
        memset(fault, 0, sizeof(fault));
        fault[0] = 5;
        fault[2] = 3;
        fault[3] = 3;
        fault[4] = 0x10;
        put16(fault + 8, 32);
        put32(fault + 12, 3);
        put32(fault + 24, 0x1c010003);
        reply(s.smb2, 0, fault, sizeof(fault));
        CHECK(cb_done && cb_status != 0);
        session_close(&s);
}

int
main(void)
{
        test_bind();
        test_signed(1, req_l5_hsign, sizeof(req_l5_hsign),
                    rep_l5_hsign, sizeof(rep_l5_hsign));
        test_signed(0, req_l5_nohsign, sizeof(req_l5_nohsign),
                    rep_l5_nohsign, sizeof(rep_l5_nohsign));
        test_sealed();
        test_refused();
        if (failures) {
                printf("%d failures\n", failures);
                return 1;
        }
        return 0;
}
