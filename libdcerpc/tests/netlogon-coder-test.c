/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Transcoding tests for the netlogon coders: NetrServerReqChallenge and
 * NetrServerAuthenticate3. See coder-test.h for the tests run per case.
 *
 * Where the known-good NDR stubs come from (ad-adc, a Windows Server 2016
 * domain controller, for the workstation account NLTEST1$):
 *
 * - Replies were captured from the server. Windows always replies in its
 *   native format, so there are only NDR32 and NDR64 little-endian ones.
 * - Requests were encoded by libdcerpc and sent to the server, which
 *   accepted them as NDR32 LE, NDR32 BE and NDR64 LE. Windows does not
 *   support NDR64 BE.
 * - Each flavor ran ReqChallenge and then Authenticate3 on one
 *   \\pipe\\netlogon connection, with the AES credentials computed from
 *   the account password; the server credential in each reply checked
 *   out. The server challenge, and so both credentials, differ per run,
 *   hence one case per flavor for those.
 *
 * The data was generated from the captures.
 */

#include <stdint.h>
#include <stddef.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/netlogon.h>

#include "coder-test.h"

/* Requests for the reply cases */
static struct netlogon_ServerReqChallenge_req reqchallenge_rep_req;
static struct netlogon_ServerAuthenticate3_req authenticate3_rep_req;

/*
 * Known-good NDR stubs: the PDU body after the 24-byte request or
 * response header.
 */
static const uint8_t reqchallenge_req_ndr32_le[] = {
        0x55, 0x70, 0x74, 0x72, 0x09, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x61, 0x00, 0x64, 0x00,
        0x2d, 0x00, 0x61, 0x00, 0x64, 0x00, 0x63, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x4e, 0x00, 0x4c, 0x00, 0x54, 0x00, 0x45, 0x00,
        0x53, 0x00, 0x54, 0x00, 0x31, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};
static const uint8_t reqchallenge_req_ndr32_be[] = {
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x5c, 0x00, 0x5c, 0x00, 0x61, 0x00, 0x64,
        0x00, 0x2d, 0x00, 0x61, 0x00, 0x64, 0x00, 0x63,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x4e, 0x00, 0x4c, 0x00, 0x54, 0x00, 0x45,
        0x00, 0x53, 0x00, 0x54, 0x00, 0x31, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};
static const uint8_t reqchallenge_req_ndr64_le[] = {
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x61, 0x00, 0x64, 0x00,
        0x2d, 0x00, 0x61, 0x00, 0x64, 0x00, 0x63, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4e, 0x00, 0x4c, 0x00, 0x54, 0x00, 0x45, 0x00,
        0x53, 0x00, 0x54, 0x00, 0x31, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};
static const uint8_t reqchallenge_rep_ndr32_le[] = {
        0x4c, 0xf0, 0xec, 0x96, 0xf9, 0x85, 0x36, 0x11,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t reqchallenge_rep_ndr64_le[] = {
        0xf2, 0xc5, 0x3e, 0xab, 0x34, 0x9b, 0x8e, 0xf8,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t authenticate3_req_ndr32_le[] = {
        0x55, 0x70, 0x74, 0x72, 0x09, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x61, 0x00, 0x64, 0x00,
        0x2d, 0x00, 0x61, 0x00, 0x64, 0x00, 0x63, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x4e, 0x00, 0x4c, 0x00, 0x54, 0x00, 0x45, 0x00,
        0x53, 0x00, 0x54, 0x00, 0x31, 0x00, 0x24, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x4e, 0x00, 0x4c, 0x00, 0x54, 0x00, 0x45, 0x00,
        0x53, 0x00, 0x54, 0x00, 0x31, 0x00, 0x00, 0x00,
        0x2c, 0xde, 0x00, 0x3c, 0x46, 0x64, 0x28, 0x4f,
        0xff, 0xff, 0x2f, 0x61,
};
static const uint8_t authenticate3_req_ndr32_be[] = {
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x5c, 0x00, 0x5c, 0x00, 0x61, 0x00, 0x64,
        0x00, 0x2d, 0x00, 0x61, 0x00, 0x64, 0x00, 0x63,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x4e, 0x00, 0x4c, 0x00, 0x54, 0x00, 0x45,
        0x00, 0x53, 0x00, 0x54, 0x00, 0x31, 0x00, 0x24,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x4e, 0x00, 0x4c, 0x00, 0x54, 0x00, 0x45,
        0x00, 0x53, 0x00, 0x54, 0x00, 0x31, 0x00, 0x00,
        0x5c, 0x2f, 0xd0, 0x03, 0x69, 0x60, 0xf8, 0x3c,
        0x61, 0x2f, 0xff, 0xff,
};
static const uint8_t authenticate3_req_ndr64_le[] = {
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x61, 0x00, 0x64, 0x00,
        0x2d, 0x00, 0x61, 0x00, 0x64, 0x00, 0x63, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4e, 0x00, 0x4c, 0x00, 0x54, 0x00, 0x45, 0x00,
        0x53, 0x00, 0x54, 0x00, 0x31, 0x00, 0x24, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4e, 0x00, 0x4c, 0x00, 0x54, 0x00, 0x45, 0x00,
        0x53, 0x00, 0x54, 0x00, 0x31, 0x00, 0x00, 0x00,
        0x96, 0x2e, 0x58, 0x87, 0xc3, 0x93, 0x17, 0x16,
        0xff, 0xff, 0x2f, 0x61,
};
static const uint8_t authenticate3_rep_ndr32_le[] = {
        0x61, 0x1d, 0xa9, 0xda, 0x2c, 0xaa, 0xcd, 0xb5,
        0xff, 0xff, 0x2f, 0x61, 0x59, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t authenticate3_rep_ndr64_le[] = {
        0x65, 0xf6, 0x0f, 0x26, 0x6a, 0x17, 0x8e, 0xd0,
        0xff, 0xff, 0x2f, 0x61, 0x59, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
};

/* Known-good YAML */
static const char reqchallenge_req_yaml[] =
        "ServerReqChallenge: Request\n"
        "  PrimaryName: \\\\ad-adc\n"
        "  ComputerName: NLTEST1\n"
        "  ClientChallenge: \n"
        "    Data: 0102030405060708\n";

static const char reqchallenge_rep_ndr32_le_yaml[] =
        "ServerReqChallenge: Response\n"
        "  ServerChallenge: \n"
        "    Data: 4cf0ec96f9853611\n"
        "  Status: 0\n";

static const char reqchallenge_rep_ndr64_le_yaml[] =
        "ServerReqChallenge: Response\n"
        "  ServerChallenge: \n"
        "    Data: f2c53eab349b8ef8\n"
        "  Status: 0\n";

static const char authenticate3_req_ndr32_le_yaml[] =
        "ServerAuthenticate3: Request\n"
        "  PrimaryName: \\\\ad-adc\n"
        "  AccountName: NLTEST1$\n"
        "  SecureChannelType: WorkstationSecureChannel\n"
        "  ComputerName: NLTEST1\n"
        "  ClientCredential: \n"
        "    Data: 2cde003c4664284f\n"
        "  NegotiateFlags: NEG_ACCOUNT_LOCKOUT"
        " | NEG_PERSISTENT_SAMREPL | NEG_ARCFOUR"
        " | NEG_PROMOTION_COUNT | NEG_CHANGELOG_BDC"
        " | NEG_FULL_SYNC_REPL | NEG_MULTIPLE_SIDS | NEG_REDO"
        " | NEG_PASSWORD_CHANGE_REFUSAL | NEG_SEND_PASSWORD_INFO_PDC"
        " | NEG_GENERIC_PASSTHROUGH | NEG_CONCURRENT_RPC"
        " | NEG_AVOID_ACCOUNT_DB_REPL"
        " | NEG_AVOID_SECURITYAUTH_DB_REPL | NEG_STRONG_KEYS"
        " | NEG_TRANSITIVE_TRUSTS | NEG_DNS_DOMAIN_TRUSTS"
        " | NEG_PASSWORD_SET2 | NEG_GETDOMAININFO"
        " | NEG_CROSS_FOREST_TRUSTS | NEG_RODC_PASSTHROUGH"
        " | NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC_LSASS"
        " | NEG_AUTHENTICATED_RPC\n";

static const char authenticate3_req_ndr32_be_yaml[] =
        "ServerAuthenticate3: Request\n"
        "  PrimaryName: \\\\ad-adc\n"
        "  AccountName: NLTEST1$\n"
        "  SecureChannelType: WorkstationSecureChannel\n"
        "  ComputerName: NLTEST1\n"
        "  ClientCredential: \n"
        "    Data: 5c2fd0036960f83c\n"
        "  NegotiateFlags: NEG_ACCOUNT_LOCKOUT"
        " | NEG_PERSISTENT_SAMREPL | NEG_ARCFOUR"
        " | NEG_PROMOTION_COUNT | NEG_CHANGELOG_BDC"
        " | NEG_FULL_SYNC_REPL | NEG_MULTIPLE_SIDS | NEG_REDO"
        " | NEG_PASSWORD_CHANGE_REFUSAL | NEG_SEND_PASSWORD_INFO_PDC"
        " | NEG_GENERIC_PASSTHROUGH | NEG_CONCURRENT_RPC"
        " | NEG_AVOID_ACCOUNT_DB_REPL"
        " | NEG_AVOID_SECURITYAUTH_DB_REPL | NEG_STRONG_KEYS"
        " | NEG_TRANSITIVE_TRUSTS | NEG_DNS_DOMAIN_TRUSTS"
        " | NEG_PASSWORD_SET2 | NEG_GETDOMAININFO"
        " | NEG_CROSS_FOREST_TRUSTS | NEG_RODC_PASSTHROUGH"
        " | NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC_LSASS"
        " | NEG_AUTHENTICATED_RPC\n";

static const char authenticate3_req_ndr64_le_yaml[] =
        "ServerAuthenticate3: Request\n"
        "  PrimaryName: \\\\ad-adc\n"
        "  AccountName: NLTEST1$\n"
        "  SecureChannelType: WorkstationSecureChannel\n"
        "  ComputerName: NLTEST1\n"
        "  ClientCredential: \n"
        "    Data: 962e5887c3931716\n"
        "  NegotiateFlags: NEG_ACCOUNT_LOCKOUT"
        " | NEG_PERSISTENT_SAMREPL | NEG_ARCFOUR"
        " | NEG_PROMOTION_COUNT | NEG_CHANGELOG_BDC"
        " | NEG_FULL_SYNC_REPL | NEG_MULTIPLE_SIDS | NEG_REDO"
        " | NEG_PASSWORD_CHANGE_REFUSAL | NEG_SEND_PASSWORD_INFO_PDC"
        " | NEG_GENERIC_PASSTHROUGH | NEG_CONCURRENT_RPC"
        " | NEG_AVOID_ACCOUNT_DB_REPL"
        " | NEG_AVOID_SECURITYAUTH_DB_REPL | NEG_STRONG_KEYS"
        " | NEG_TRANSITIVE_TRUSTS | NEG_DNS_DOMAIN_TRUSTS"
        " | NEG_PASSWORD_SET2 | NEG_GETDOMAININFO"
        " | NEG_CROSS_FOREST_TRUSTS | NEG_RODC_PASSTHROUGH"
        " | NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC_LSASS"
        " | NEG_AUTHENTICATED_RPC\n";

static const char authenticate3_rep_ndr32_le_yaml[] =
        "ServerAuthenticate3: Response\n"
        "  ServerCredential: \n"
        "    Data: 611da9da2caacdb5\n"
        "  NegotiateFlags: NEG_ACCOUNT_LOCKOUT"
        " | NEG_PERSISTENT_SAMREPL | NEG_ARCFOUR"
        " | NEG_PROMOTION_COUNT | NEG_CHANGELOG_BDC"
        " | NEG_FULL_SYNC_REPL | NEG_MULTIPLE_SIDS | NEG_REDO"
        " | NEG_PASSWORD_CHANGE_REFUSAL | NEG_SEND_PASSWORD_INFO_PDC"
        " | NEG_GENERIC_PASSTHROUGH | NEG_CONCURRENT_RPC"
        " | NEG_AVOID_ACCOUNT_DB_REPL"
        " | NEG_AVOID_SECURITYAUTH_DB_REPL | NEG_STRONG_KEYS"
        " | NEG_TRANSITIVE_TRUSTS | NEG_DNS_DOMAIN_TRUSTS"
        " | NEG_PASSWORD_SET2 | NEG_GETDOMAININFO"
        " | NEG_CROSS_FOREST_TRUSTS | NEG_RODC_PASSTHROUGH"
        " | NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC_LSASS"
        " | NEG_AUTHENTICATED_RPC\n"
        "  AccountRid: 1113\n"
        "  Status: 0\n";

static const char authenticate3_rep_ndr64_le_yaml[] =
        "ServerAuthenticate3: Response\n"
        "  ServerCredential: \n"
        "    Data: 65f60f266a178ed0\n"
        "  NegotiateFlags: NEG_ACCOUNT_LOCKOUT"
        " | NEG_PERSISTENT_SAMREPL | NEG_ARCFOUR"
        " | NEG_PROMOTION_COUNT | NEG_CHANGELOG_BDC"
        " | NEG_FULL_SYNC_REPL | NEG_MULTIPLE_SIDS | NEG_REDO"
        " | NEG_PASSWORD_CHANGE_REFUSAL | NEG_SEND_PASSWORD_INFO_PDC"
        " | NEG_GENERIC_PASSTHROUGH | NEG_CONCURRENT_RPC"
        " | NEG_AVOID_ACCOUNT_DB_REPL"
        " | NEG_AVOID_SECURITYAUTH_DB_REPL | NEG_STRONG_KEYS"
        " | NEG_TRANSITIVE_TRUSTS | NEG_DNS_DOMAIN_TRUSTS"
        " | NEG_PASSWORD_SET2 | NEG_GETDOMAININFO"
        " | NEG_CROSS_FOREST_TRUSTS | NEG_RODC_PASSTHROUGH"
        " | NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC_LSASS"
        " | NEG_AUTHENTICATED_RPC\n"
        "  AccountRid: 1113\n"
        "  Status: 0\n";

static const struct test_case test_cases[] = {
        { "ServerReqChallenge request", "ServerReqChallenge",
          netlogon_ServerReqChallenge_req_coder, sizeof(struct netlogon_ServerReqChallenge_req),
          NULL, reqchallenge_req_yaml,
          { { reqchallenge_req_ndr32_le, sizeof(reqchallenge_req_ndr32_le) },
            { reqchallenge_req_ndr32_be, sizeof(reqchallenge_req_ndr32_be) },
            { reqchallenge_req_ndr64_le, sizeof(reqchallenge_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "ServerReqChallenge reply, NDR32 LE", "ServerReqChallenge",
          netlogon_ServerReqChallenge_rep_coder, sizeof(struct netlogon_ServerReqChallenge_rep),
          &reqchallenge_rep_req, reqchallenge_rep_ndr32_le_yaml,
          { { reqchallenge_rep_ndr32_le, sizeof(reqchallenge_rep_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "ServerReqChallenge reply, NDR64 LE", "ServerReqChallenge",
          netlogon_ServerReqChallenge_rep_coder, sizeof(struct netlogon_ServerReqChallenge_rep),
          &reqchallenge_rep_req, reqchallenge_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { reqchallenge_rep_ndr64_le, sizeof(reqchallenge_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "ServerAuthenticate3 request, NDR32 LE", "ServerAuthenticate3",
          netlogon_ServerAuthenticate3_req_coder, sizeof(struct netlogon_ServerAuthenticate3_req),
          NULL, authenticate3_req_ndr32_le_yaml,
          { { authenticate3_req_ndr32_le, sizeof(authenticate3_req_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "ServerAuthenticate3 request, NDR32 BE", "ServerAuthenticate3",
          netlogon_ServerAuthenticate3_req_coder, sizeof(struct netlogon_ServerAuthenticate3_req),
          NULL, authenticate3_req_ndr32_be_yaml,
          { { NULL, 0 },
            { authenticate3_req_ndr32_be, sizeof(authenticate3_req_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "ServerAuthenticate3 request, NDR64 LE", "ServerAuthenticate3",
          netlogon_ServerAuthenticate3_req_coder, sizeof(struct netlogon_ServerAuthenticate3_req),
          NULL, authenticate3_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { authenticate3_req_ndr64_le, sizeof(authenticate3_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "ServerAuthenticate3 reply, NDR32 LE", "ServerAuthenticate3",
          netlogon_ServerAuthenticate3_rep_coder, sizeof(struct netlogon_ServerAuthenticate3_rep),
          &authenticate3_rep_req, authenticate3_rep_ndr32_le_yaml,
          { { authenticate3_rep_ndr32_le, sizeof(authenticate3_rep_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "ServerAuthenticate3 reply, NDR64 LE", "ServerAuthenticate3",
          netlogon_ServerAuthenticate3_rep_coder, sizeof(struct netlogon_ServerAuthenticate3_rep),
          &authenticate3_rep_req, authenticate3_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { authenticate3_rep_ndr64_le, sizeof(authenticate3_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
};

int main(void)
{
        return run_coder_tests(test_cases,
                               sizeof(test_cases) / sizeof(test_cases[0]));
}
