/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Transcoding tests for the dssetup coders: DsRolerGetPrimaryDomainInformation
 * for each of its three levels. See coder-test.h for the tests run per case.
 *
 * Where the known-good NDR stubs come from (win16-1, Windows Server 2016, a
 * standalone server):
 *
 * - Replies were captured from the server. Windows always replies in its
 *   native format, so there are only NDR32 and NDR64 little-endian ones.
 * - Requests were encoded by libdcerpc and sent to the server, which
 *   accepted them as NDR32 LE, NDR32 BE and NDR64 LE and answered each
 *   flavor alike. Windows does not support NDR64 BE.
 * - The calls ran as one chain per flavor on \\pipe\\lsarpc:
 *   DsRolePrimaryDomainInfoBasic, DsRoleUpgradeStatus and
 *   DsRoleOperationState. The DsRoleOperationState reply has its 2-aligned
 *   arm right after the 16-bit discriminant in NDR32.
 *
 * The data was generated from the captures.
 */

#include <stdint.h>
#include <stddef.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/dssetup.h>

#include "coder-test.h"

/* Requests for the reply cases */
static struct dssetup_GetPrimaryDomainInformation_req dsroleprimarydomaininfobasic_rep_req = {
        .InfoLevel = DSSETUP_DsRolePrimaryDomainInfoBasic,
};
static struct dssetup_GetPrimaryDomainInformation_req dsroleupgradestatus_rep_req = {
        .InfoLevel = DSSETUP_DsRoleUpgradeStatus,
};
static struct dssetup_GetPrimaryDomainInformation_req dsroleoperationstate_rep_req = {
        .InfoLevel = DSSETUP_DsRoleOperationState,
};

/*
 * Known-good NDR stubs: the PDU body after the 24-byte request or
 * response header.
 */
static const uint8_t dsroleprimarydomaininfobasic_rep_ndr32_le[] = {
        0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x57, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x4b, 0x00,
        0x47, 0x00, 0x52, 0x00, 0x4f, 0x00, 0x55, 0x00,
        0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t dsroleprimarydomaininfobasic_rep_ndr64_le[] = {
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x57, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x4b, 0x00,
        0x47, 0x00, 0x52, 0x00, 0x4f, 0x00, 0x55, 0x00,
        0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t dsroleupgradestatus_rep_ndr32_le[] = {
        0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t dsroleupgradestatus_rep_ndr64_le[] = {
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t dsroleoperationstate_rep_ndr32_le[] = {
        0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t dsroleoperationstate_rep_ndr64_le[] = {
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t dsroleprimarydomaininfobasic_req_ndr32_le[] = {
        0x01, 0x00,
};
static const uint8_t dsroleprimarydomaininfobasic_req_ndr32_be[] = {
        0x00, 0x01,
};
static const uint8_t dsroleprimarydomaininfobasic_req_ndr64_le[] = {
        0x01, 0x00, 0x00, 0x00,
};
static const uint8_t dsroleupgradestatus_req_ndr32_le[] = {
        0x02, 0x00,
};
static const uint8_t dsroleupgradestatus_req_ndr32_be[] = {
        0x00, 0x02,
};
static const uint8_t dsroleupgradestatus_req_ndr64_le[] = {
        0x02, 0x00, 0x00, 0x00,
};
static const uint8_t dsroleoperationstate_req_ndr32_le[] = {
        0x03, 0x00,
};
static const uint8_t dsroleoperationstate_req_ndr32_be[] = {
        0x00, 0x03,
};
static const uint8_t dsroleoperationstate_req_ndr64_le[] = {
        0x03, 0x00, 0x00, 0x00,
};

/* Known-good YAML */
static const char dsroleprimarydomaininfobasic_rep_yaml[] =
        "GetPrimaryDomainInformation: Response\n"
        "  DomainInfo:\n"
        "    DomainInfoBasic: \n"
        "      MachineRole: DsRole_RoleStandaloneServer\n"
        "      Flags: 0x00000000\n"
        "      DomainNameFlat: WORKGROUP\n"
        "      DomainGuid: 00000000-0000-0000-0000-000000000000\n"
        "  Status: 0\n";

static const char dsroleupgradestatus_rep_yaml[] =
        "GetPrimaryDomainInformation: Response\n"
        "  DomainInfo:\n"
        "    UpgradStatusInfo: \n"
        "      OperationState: 0\n"
        "      PreviousServerState: DsRoleServerUnknown\n"
        "  Status: 0\n";

static const char dsroleoperationstate_rep_yaml[] =
        "GetPrimaryDomainInformation: Response\n"
        "  DomainInfo:\n"
        "    OperationStateInfo: \n"
        "      OperationState: DsRoleOperationIdle\n"
        "  Status: 0\n";

static const char dsroleprimarydomaininfobasic_req_yaml[] =
        "GetPrimaryDomainInformation: Request\n"
        "  InfoLevel: DsRolePrimaryDomainInfoBasic\n";

static const char dsroleupgradestatus_req_yaml[] =
        "GetPrimaryDomainInformation: Request\n"
        "  InfoLevel: DsRoleUpgradeStatus\n";

static const char dsroleoperationstate_req_yaml[] =
        "GetPrimaryDomainInformation: Request\n"
        "  InfoLevel: DsRoleOperationState\n";

static const struct test_case test_cases[] = {
        { "GetPrimaryDomainInformation reply, DsRolePrimaryDomainInfoBasic", "GetPrimaryDomainInformation",
          dssetup_GetPrimaryDomainInformation_rep_coder, sizeof(struct dssetup_GetPrimaryDomainInformation_rep),
          &dsroleprimarydomaininfobasic_rep_req, dsroleprimarydomaininfobasic_rep_yaml,
          { { dsroleprimarydomaininfobasic_rep_ndr32_le, sizeof(dsroleprimarydomaininfobasic_rep_ndr32_le) },
            { NULL, 0 },
            { dsroleprimarydomaininfobasic_rep_ndr64_le, sizeof(dsroleprimarydomaininfobasic_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "GetPrimaryDomainInformation reply, DsRoleUpgradeStatus", "GetPrimaryDomainInformation",
          dssetup_GetPrimaryDomainInformation_rep_coder, sizeof(struct dssetup_GetPrimaryDomainInformation_rep),
          &dsroleupgradestatus_rep_req, dsroleupgradestatus_rep_yaml,
          { { dsroleupgradestatus_rep_ndr32_le, sizeof(dsroleupgradestatus_rep_ndr32_le) },
            { NULL, 0 },
            { dsroleupgradestatus_rep_ndr64_le, sizeof(dsroleupgradestatus_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "GetPrimaryDomainInformation reply, DsRoleOperationState", "GetPrimaryDomainInformation",
          dssetup_GetPrimaryDomainInformation_rep_coder, sizeof(struct dssetup_GetPrimaryDomainInformation_rep),
          &dsroleoperationstate_rep_req, dsroleoperationstate_rep_yaml,
          { { dsroleoperationstate_rep_ndr32_le, sizeof(dsroleoperationstate_rep_ndr32_le) },
            { NULL, 0 },
            { dsroleoperationstate_rep_ndr64_le, sizeof(dsroleoperationstate_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "GetPrimaryDomainInformation request, DsRolePrimaryDomainInfoBasic", "GetPrimaryDomainInformation",
          dssetup_GetPrimaryDomainInformation_req_coder, sizeof(struct dssetup_GetPrimaryDomainInformation_req),
          NULL, dsroleprimarydomaininfobasic_req_yaml,
          { { dsroleprimarydomaininfobasic_req_ndr32_le, sizeof(dsroleprimarydomaininfobasic_req_ndr32_le) },
            { dsroleprimarydomaininfobasic_req_ndr32_be, sizeof(dsroleprimarydomaininfobasic_req_ndr32_be) },
            { dsroleprimarydomaininfobasic_req_ndr64_le, sizeof(dsroleprimarydomaininfobasic_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "GetPrimaryDomainInformation request, DsRoleUpgradeStatus", "GetPrimaryDomainInformation",
          dssetup_GetPrimaryDomainInformation_req_coder, sizeof(struct dssetup_GetPrimaryDomainInformation_req),
          NULL, dsroleupgradestatus_req_yaml,
          { { dsroleupgradestatus_req_ndr32_le, sizeof(dsroleupgradestatus_req_ndr32_le) },
            { dsroleupgradestatus_req_ndr32_be, sizeof(dsroleupgradestatus_req_ndr32_be) },
            { dsroleupgradestatus_req_ndr64_le, sizeof(dsroleupgradestatus_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "GetPrimaryDomainInformation request, DsRoleOperationState", "GetPrimaryDomainInformation",
          dssetup_GetPrimaryDomainInformation_req_coder, sizeof(struct dssetup_GetPrimaryDomainInformation_req),
          NULL, dsroleoperationstate_req_yaml,
          { { dsroleoperationstate_req_ndr32_le, sizeof(dsroleoperationstate_req_ndr32_le) },
            { dsroleoperationstate_req_ndr32_be, sizeof(dsroleoperationstate_req_ndr32_be) },
            { dsroleoperationstate_req_ndr64_le, sizeof(dsroleoperationstate_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
};

int main(void)
{
        return run_coder_tests(test_cases,
                               sizeof(test_cases) / sizeof(test_cases[0]));
}
