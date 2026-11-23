/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Set up a Netlogon secure channel to a domain controller and make
 * calls over a schannel-bound pipe, signed and sealed.
 *
 * -j first creates the workstation account <machine>$ over samr, or
 * resets its password if it exists. The URL then needs domain admin
 * credentials. -f also checks that an RPC fault leaves the secure
 * channel usable for the next call.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <dcerpc/dcerpc.h>
#include <dcerpc/schannel.h>
#include <dcerpc/netlogon.h>
#include <dcerpc/samr.h>

#define STATUS_USER_EXISTS 0xc0000063
#define USER_WORKSTATION_TRUST_ACCOUNT 0x00000080
#define NEGOTIATE_FLAGS 0x612fffff

static void usage(void)
{
        fprintf(stderr, "Usage:\n"
                "dcerpc-schannel [-j] [-f] <smb2-url> <machine> <password>\n\n"
                "  -j  create or reset the account <machine>$ first\n"
                "  -f  check that a call after an RPC fault still works\n\n"
                "URL format: smb://<domain>;<user>@<dc>/\n");
        exit(1);
}

static struct dcerpc_context *open_pipe(struct smb2_context *smb2,
                                        const char *pipe,
                                        p_syntax_id_t *syntax,
                                        struct dcerpc_schannel *sch,
                                        int level, const char *domain,
                                        const char *machine)
{
        struct dcerpc_context *dce;

        dce = dcerpc_create_context(smb2);
        if (dce == NULL) {
                printf("dcerpc_create_context failed\n");
                exit(10);
        }
        if (sch && dcerpc_set_schannel(dce, sch, level, domain, machine)) {
                printf("dcerpc_set_schannel failed: %s\n",
                       dcerpc_get_error(dce));
                exit(10);
        }
        if (dcerpc_connect_context(dce, pipe, syntax)) {
                printf("failed to open %s: %s\n", pipe,
                       dcerpc_get_error(dce));
                exit(10);
        }
        return dce;
}

static void rc4(const uint8_t *key, size_t key_len, uint8_t *data,
                size_t len)
{
        uint8_t s[256], t;
        size_t k;
        int i, j;

        for (i = 0; i < 256; i++) {
                s[i] = i;
        }
        for (i = j = 0; i < 256; i++) {
                j = (j + s[i] + key[i % key_len]) & 0xff;
                t = s[i]; s[i] = s[j]; s[j] = t;
        }
        for (k = 0, i = j = 0; k < len; k++) {
                i = (i + 1) & 0xff;
                j = (j + s[i]) & 0xff;
                t = s[i]; s[i] = s[j]; s[j] = t;
                data[k] ^= s[(s[i] + s[j]) & 0xff];
        }
}

static void *call(struct dcerpc_context *dce, const char *what, int opnum,
                  dcerpc_coder req_coder, void *req,
                  dcerpc_coder rep_coder, int size)
{
        void *rep;

        rep = dcerpc_call(dce, opnum, req_coder, req, rep_coder, size);
        if (rep == NULL) {
                printf("%s failed: %s\n", what, dcerpc_get_error(dce));
                exit(10);
        }
        return rep;
}

static void check_status(const char *what, uint32_t status)
{
        if (status) {
                printf("%s failed: 0x%08x\n", what, status);
                exit(10);
        }
}

static void samr_close(struct dcerpc_context *dce,
                       struct dcerpc_context_handle *h)
{
        struct samr_CloseHandle_req req;

        req.SamHandle = *h;
        dcerpc_free_data(dce, call(dce, "CloseHandle", SAMR_CLOSEHANDLE,
                                   samr_CloseHandle_req_coder, &req,
                                   samr_CloseHandle_rep_coder,
                                   sizeof(struct samr_CloseHandle_rep)));
}

static void set_user_info(struct dcerpc_context *dce,
                          struct dcerpc_context_handle *user,
                          enum samr_USER_INFORMATION_CLASS level,
                          union samr_SAMPR_USER_INFO_BUFFER *buf)
{
        struct samr_SetInformationUser2_req req;
        struct samr_SetInformationUser2_rep *rep;

        req.UserHandle = *user;
        req.UserInformationClass = level;
        req.Buffer = *buf;
        rep = call(dce, "SetInformationUser2", SAMR_SETINFORMATIONUSER2,
                   samr_SetInformationUser2_req_coder, &req,
                   samr_SetInformationUser2_rep_coder,
                   sizeof(*rep));
        check_status("SetInformationUser2", rep->status);
        dcerpc_free_data(dce, rep);
}

/* Create <machine>$ as a workstation account, or reset its password. */
static void join(struct smb2_context *smb2, const char *domain,
                 const char *account, const char *password)
{
        struct dcerpc_context *dce;
        struct samr_Connect5_req c_req = {0};
        struct samr_Connect5_rep *c_rep;
        struct samr_LookupDomainInSamServer_req ld_req;
        struct samr_LookupDomainInSamServer_rep *ld_rep;
        struct samr_OpenDomain_req od_req;
        struct samr_OpenDomain_rep *od_rep;
        struct samr_CreateUser2InDomain_req cu_req;
        struct samr_CreateUser2InDomain_rep *cu_rep;
        struct dcerpc_context_handle server, dom, user;
        union samr_SAMPR_USER_INFO_BUFFER buf;
        uint8_t key[16];
        uint8_t *pw;
        size_t i, len = strlen(password);

        if (len > 256) {
                printf("password too long\n");
                exit(10);
        }
        dce = open_pipe(smb2, "samr", &samr_interface, NULL, 0, NULL, NULL);

        c_req.ServerName = (char *)"";
        c_req.DesiredAccess = MAXIMUM_ALLOWED;
        c_req.InVersion = 1;
        c_req.InRevisionInfo.V1.Revision = 3;
        c_rep = call(dce, "Connect5", SAMR_CONNECT5,
                     samr_Connect5_req_coder, &c_req,
                     samr_Connect5_rep_coder, sizeof(*c_rep));
        check_status("Connect5", c_rep->status);
        server = c_rep->ServerHandle;
        dcerpc_free_data(dce, c_rep);

        ld_req.ServerHandle = server;
        ld_req.Name = (char *)domain;
        ld_rep = call(dce, "LookupDomainInSamServer",
                      SAMR_LOOKUPDOMAININSAMSERVER,
                      samr_LookupDomainInSamServer_req_coder, &ld_req,
                      samr_LookupDomainInSamServer_rep_coder,
                      sizeof(*ld_rep));
        check_status("LookupDomainInSamServer", ld_rep->status);

        od_req.ServerHandle = server;
        od_req.DesiredAccess = MAXIMUM_ALLOWED;
        od_req.DomainId = *ld_rep->DomainId;
        dcerpc_free_data(dce, ld_rep);
        od_rep = call(dce, "OpenDomain", SAMR_OPENDOMAIN,
                      samr_OpenDomain_req_coder, &od_req,
                      samr_OpenDomain_rep_coder, sizeof(*od_rep));
        check_status("OpenDomain", od_rep->status);
        dom = od_rep->DomainHandle;
        dcerpc_free_data(dce, od_rep);

        cu_req.DomainHandle = dom;
        cu_req.Name = (char *)account;
        cu_req.AccountType = USER_WORKSTATION_TRUST_ACCOUNT;
        cu_req.DesiredAccess = MAXIMUM_ALLOWED;
        cu_rep = call(dce, "CreateUser2InDomain", SAMR_CREATEUSER2INDOMAIN,
                      samr_CreateUser2InDomain_req_coder, &cu_req,
                      samr_CreateUser2InDomain_rep_coder,
                      sizeof(*cu_rep));
        if (cu_rep->status == STATUS_USER_EXISTS) {
                struct samr_LookupNamesInDomain_req ln_req;
                struct samr_LookupNamesInDomain_rep *ln_rep;
                struct samr_OpenUser_req ou_req;
                struct samr_OpenUser_rep *ou_rep;
                char *names[1] = { (char *)account };

                printf("%s exists, resetting its password\n", account);
                ln_req.DomainHandle = dom;
                ln_req.Count = 1;
                ln_req.Names = names;
                ln_rep = call(dce, "LookupNamesInDomain",
                              SAMR_LOOKUPNAMESINDOMAIN,
                              samr_LookupNamesInDomain_req_coder, &ln_req,
                              samr_LookupNamesInDomain_rep_coder,
                              sizeof(*ln_rep));
                check_status("LookupNamesInDomain", ln_rep->status);
                ou_req.DomainHandle = dom;
                ou_req.DesiredAccess = MAXIMUM_ALLOWED;
                ou_req.UserId = ln_rep->RelativeIds.Element[0];
                dcerpc_free_data(dce, ln_rep);
                ou_rep = call(dce, "OpenUser", SAMR_OPENUSER,
                              samr_OpenUser_req_coder, &ou_req,
                              samr_OpenUser_rep_coder, sizeof(*ou_rep));
                check_status("OpenUser", ou_rep->status);
                user = ou_rep->UserHandle;
                dcerpc_free_data(dce, ou_rep);
        } else {
                check_status("CreateUser2InDomain", cu_rep->status);
                printf("created %s, rid %u\n", account, cu_rep->RelativeId);
                user = cu_rep->UserHandle;
        }
        dcerpc_free_data(dce, cu_rep);

        /*
         * SAMPR_USER_PASSWORD: random fill, the UTF-16LE password at the
         * end of the 512 bytes, then its length in bytes. RC4 with the
         * SMB session key.
         */
        memset(&buf, 0, sizeof(buf));
        pw = buf.Internal5.UserPassword.Buffer;
        srandom(time(NULL) ^ getpid());
        for (i = 0; i < 512; i++) {
                pw[i] = random();
        }
        for (i = 0; i < len; i++) {
                pw[512 - 2 * len + 2 * i] = password[i];
                pw[512 - 2 * len + 2 * i + 1] = 0;
        }
        pw[512] = (2 * len) & 0xff;
        pw[513] = (2 * len) >> 8;
        pw[514] = pw[515] = 0;
        if (smb2_get_application_key(smb2, key)) {
                printf("no SMB session key: %s\n", smb2_get_error(smb2));
                exit(10);
        }
        rc4(key, sizeof(key), pw, 516);
        set_user_info(dce, &user, SAMR_UserInternal5Information, &buf);

        memset(&buf, 0, sizeof(buf));
        buf.Control.UserAccountControl = USER_WORKSTATION_TRUST_ACCOUNT;
        set_user_info(dce, &user, SAMR_UserControlInformation, &buf);
        printf("password set, account enabled\n");

        samr_close(dce, &user);
        samr_close(dce, &dom);
        samr_close(dce, &server);
        dcerpc_destroy_context(dce);
}

/* ReqChallenge and Authenticate3 on a plain netlogon pipe. */
static struct dcerpc_schannel *authenticate(struct smb2_context *smb2,
                                            const char *machine,
                                            const char *account,
                                            const char *password)
{
        struct dcerpc_context *dce;
        struct dcerpc_schannel *sch;
        struct netlogon_ServerReqChallenge_req rc_req;
        struct netlogon_ServerReqChallenge_rep *rc_rep;
        struct netlogon_ServerAuthenticate3_req a_req;
        struct netlogon_ServerAuthenticate3_rep *a_rep;
        uint8_t cc[8];

        dce = open_pipe(smb2, "netlogon", &netlogon_interface, NULL, 0,
                        NULL, NULL);
        if (dcerpc_schannel_client_challenge(cc)) {
                printf("no client challenge\n");
                exit(10);
        }
        rc_req.PrimaryName = NULL;
        rc_req.ComputerName = (char *)machine;
        memcpy(rc_req.ClientChallenge.Data, cc, 8);
        rc_rep = call(dce, "ServerReqChallenge", NETLOGON_SERVERREQCHALLENGE,
                      netlogon_ServerReqChallenge_req_coder, &rc_req,
                      netlogon_ServerReqChallenge_rep_coder,
                      sizeof(*rc_rep));
        check_status("ServerReqChallenge", rc_rep->status);
        sch = dcerpc_schannel_create(cc, rc_rep->ServerChallenge.Data,
                                     password, NEGOTIATE_FLAGS);
        dcerpc_free_data(dce, rc_rep);
        if (sch == NULL) {
                printf("dcerpc_schannel_create failed\n");
                exit(10);
        }

        a_req.PrimaryName = NULL;
        a_req.AccountName = (char *)account;
        a_req.SecureChannelType = NETLOGON_WorkstationSecureChannel;
        a_req.ComputerName = (char *)machine;
        dcerpc_schannel_client_credential(sch, a_req.ClientCredential.Data);
        a_req.NegotiateFlags = NEGOTIATE_FLAGS;
        a_rep = call(dce, "ServerAuthenticate3", NETLOGON_SERVERAUTHENTICATE3,
                     netlogon_ServerAuthenticate3_req_coder, &a_req,
                     netlogon_ServerAuthenticate3_rep_coder,
                     sizeof(*a_rep));
        check_status("ServerAuthenticate3", a_rep->status);
        if (dcerpc_schannel_check_server_credential(
                    sch, a_rep->ServerCredential.Data,
                    a_rep->NegotiateFlags)) {
                printf("server credential check failed\n");
                exit(10);
        }
        printf("secure channel up, flags 0x%08x\n", a_rep->NegotiateFlags);
        dcerpc_free_data(dce, a_rep);
        dcerpc_destroy_context(dce);
        return sch;
}

static void get_capabilities(struct dcerpc_context *dce,
                             struct dcerpc_schannel *sch,
                             const char *machine)
{
        struct netlogon_LogonGetCapabilities_req req;
        struct netlogon_LogonGetCapabilities_rep *rep;

        memset(&req, 0, sizeof(req));
        req.ServerName = NULL;
        req.ComputerName = (char *)machine;
        req.QueryLevel = 1;
        req.Authenticator.Timestamp = (uint32_t)time(NULL);
        dcerpc_schannel_authenticator(sch, req.Authenticator.Timestamp,
                                      req.Authenticator.Credential.Data);
        rep = call(dce, "LogonGetCapabilities", NETLOGON_LOGONGETCAPABILITIES,
                   netlogon_LogonGetCapabilities_req_coder, &req,
                   netlogon_LogonGetCapabilities_rep_coder, sizeof(*rep));
        check_status("LogonGetCapabilities", rep->status);
        if (dcerpc_schannel_check_authenticator(
                    sch, rep->ReturnAuthenticator.Credential.Data)) {
                printf("return authenticator check failed\n");
                exit(10);
        }
        if (dcerpc_schannel_check_capabilities(
                    sch, rep->Capabilities.ServerCapabilities)) {
                printf("capabilities differ from the negotiated flags\n");
                exit(10);
        }
        printf("  LogonGetCapabilities: 0x%08x\n",
               rep->Capabilities.ServerCapabilities);
        dcerpc_free_data(dce, rep);
}

static int empty_coder(char *name, struct dcerpc_context *dce,
                       struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                       void *ptr)
{
        return 0;
}

/* An opnum netlogon does not have: the server answers with a FAULT. */
static void fault(struct dcerpc_context *dce)
{
        void *rep;

        rep = dcerpc_call(dce, 200, empty_coder, NULL, empty_coder, 4);
        if (rep != NULL) {
                printf("opnum 200 did not fault\n");
                exit(10);
        }
        printf("  opnum 200: %s\n", dcerpc_get_error(dce));
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        const char *machine, *password;
        char account[64];
        int do_join = 0, do_fault = 0, c, level;

        while ((c = getopt(argc, argv, "jf")) != -1) {
                switch (c) {
                case 'j':
                        do_join = 1;
                        break;
                case 'f':
                        do_fault = 1;
                        break;
                default:
                        usage();
                }
        }
        if (argc - optind != 3) {
                usage();
        }
        machine = argv[optind + 1];
        password = argv[optind + 2];
        if (strlen(machine) > 15) {
                printf("machine name longer than 15 characters\n");
                exit(10);
        }
        snprintf(account, sizeof(account), "%s$", machine);

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                exit(10);
        }
        url = smb2_parse_url(smb2, argv[optind]);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(smb2));
                exit(10);
        }
        if (url->domain == NULL) {
                fprintf(stderr, "The URL needs the NetBIOS domain name\n");
                exit(10);
        }
        if (url->user) {
                smb2_set_user(smb2, url->user);
        }
        smb2_set_domain(smb2, url->domain);
        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (smb2_connect_share(smb2, url->server, "IPC$", NULL) < 0) {
                printf("Failed to connect to IPC$. %s\n",
                       smb2_get_error(smb2));
                exit(10);
        }
        if (do_join) {
                join(smb2, url->domain, account, password);
        }

        for (level = DCERPC_AUTH_LEVEL_INTEGRITY;
             level <= DCERPC_AUTH_LEVEL_PRIVACY; level++) {
                struct dcerpc_schannel *sch;
                struct dcerpc_context *dce;

                sch = authenticate(smb2, machine, account, password);
                dce = open_pipe(smb2, "netlogon", &netlogon_interface, sch,
                                level, url->domain, machine);
                printf("schannel bind, %s\n",
                       level == DCERPC_AUTH_LEVEL_PRIVACY ?
                       "sealed" : "signed");
                get_capabilities(dce, sch, machine);
                if (do_fault) {
                        fault(dce);
                        get_capabilities(dce, sch, machine);
                }
                dcerpc_destroy_context(dce);
                dcerpc_schannel_destroy(sch);
        }

        smb2_disconnect_share(smb2);
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);
        return 0;
}
