/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2020 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-dcerpc.h"
#include "libsmb2-dcerpc-lsa.h"

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

int is_finished;
struct ndr_context_handle PolicyHandle;

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-dcerpc-coder-test\n\n");
        exit(1);
}

void co_cb(struct dcerpc_context *dce, int status,
           void *command_data, void *cb_data)
{
        struct lsa_openpolicy2_req op_req;
        struct smb2_url *url = cb_data;

        if (status != SMB2_STATUS_SUCCESS) {
                printf("failed to connect to LSA (%s) %s\n",
                       strerror(-status), dcerpc_get_error(dce));
                exit(10);
        }

        op_req.SystemName = malloc(strlen(url->server) + 3);
        if (op_req.SystemName == NULL) {
                printf("failed to allocate SystemName\n");
                exit(10);
        }
        sprintf(op_req.SystemName, "\\\\%s", url->server);

        op_req.ObjectAttributes.Length = 24;
        op_req.DesiredAccess = POLICY_LOOKUP_NAMES |
                POLICY_VIEW_LOCAL_INFORMATION;

        if (dcerpc_call_async(dce,
                              LSA_OPENPOLICY2,
                              lsa_OpenPolicy2_req_coder, &op_req,
                              lsa_OpenPolicy2_rep_coder,
                              sizeof(struct lsa_openpolicy2_rep),
                              NULL, NULL) != 0) {
                printf("dcerpc_call_async failed with %s\n",
                       dcerpc_get_error(dce));
                exit(10);
        }
        free(op_req.SystemName);
}

static void test_dcerpc_codec(struct dcerpc_context *dce, char *method,
                              dcerpc_coder coder, void *req, int req_size,
                              int expected_offset, uint8_t *expected_data,
                              int print_buf)
{
        struct dcerpc_pdu *pdu;
        struct smb2_iovec iov;
        static unsigned char buf[65536];
        int offset;
        int i;

        printf("Test codec for %s\n", method);

        /* Encode */
        pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE, req_size);
        iov.len = 65536;
        iov.buf = buf;
        memset(iov.buf, 0, iov.len);
        offset = coder(dce, pdu, &iov, 0, req);
        dcerpc_free_pdu(dce, pdu);

        if (offset != expected_offset) {
                printf("Encoding failed. Offset/Expected mismatch. %d/%d\n",
                       offset, expected_offset);
                exit(20);
        }

        if (print_buf) {
                printf("offset:%d  expected:%d\n", offset, expected_offset);
                for (i = 0; i < offset; i++) {
                        if (i % 8 == 0) printf("[0x%02x]  ", i);
                        printf("0x%02x, ", iov.buf[i]);
                        if (i % 8 == 7) printf("\n");
                }
                printf("\n");
        }
        if (memcmp(iov.buf, expected_data, expected_offset)) {
                printf("Encoding failed. Data Mismatch\n");
                for (i = 0; i < expected_offset; i++) {
                        if (iov.buf[i] != expected_data[i]) {
                                printf("[0x%02x]: Expected:0x%02x Got:0x%02x\n", i, expected_data[i], iov.buf[i]);
                        }
                }
                exit(20);
        }

        /* Decode it again */
        memset(req, 0, req_size);
        pdu = dcerpc_allocate_pdu(dce, DCERPC_DECODE, req_size);
        offset = coder(dce, pdu, &iov, 0, req);
        dcerpc_free_pdu(dce, pdu);
        if (offset != expected_offset) {
                printf("Encoding failed. Offset/Expected mismatch. %d/%d\n",
                       offset, expected_offset);
                exit(20);
        }

        /* And encode it again */
        pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE, req_size);
        iov.len = 65536;
        iov.buf = buf;
        memset(iov.buf, 0, iov.len);
        offset = coder(dce, pdu, &iov, 0, req);
        dcerpc_free_pdu(dce, pdu);

        if (offset != expected_offset) {
                printf("Encoding failed. Offset/Expected mismatch. %d/%d\n",
                       offset, expected_offset);
                exit(20);
        }

        if (print_buf) {
                printf("offset:%d  expected:%d\n", offset, expected_offset);
                for (i = 0; i < offset; i++) {
                        if (i % 8 == 0) printf("[0x%02x]  ", i);
                        printf("0x%02x, ", iov.buf[i]);
                        if (i % 8 == 7) printf("\n");
                }
                printf("\n");
        }
        if (memcmp(iov.buf, expected_data, expected_offset)) {
                printf("Encoding failed. Data mismatch\n");
                for (i = 0; i < expected_offset; i++) {
                        if (iov.buf[i] != expected_data[i]) {
                                printf("[0x%02x]: Expected:0x%02x Got:0x%02x\n", i, expected_data[i], iov.buf[i]);
                        }
                }
                exit(20);
        }

}

static void test_LSA_LookupSids2_req(struct dcerpc_context *dce)
{
        struct lsa_lookupsids2_req req;
        PRPC_SID sid, *sids;
        uint32_t sa[2];
        int num_sids;
        unsigned char buf[] = {
            0x00, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 
            0x65, 0x66, 0x67, 0x68, 0x35, 0x34, 0x33, 0x32, 
            0x31, 0x30, 0x6a, 0x69, 0x02, 0x00, 0x00, 0x00, 
            0x55, 0x70, 0x74, 0x72, 0x02, 0x00, 0x00, 0x00, 
            0x55, 0x70, 0x74, 0x72, 0x55, 0x70, 0x74, 0x72, 
            0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 
            0x20, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 
            0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x55, 0x70, 0x74, 0x72, 
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x02, 0x00, 0x00, 0x00 };

        memcpy(&req.PolicyHandle, &PolicyHandle,
               sizeof(struct ndr_context_handle));

        sid = malloc(sizeof(*sid) + 2 * sizeof(uint32_t));
        if (sid == NULL) {
                printf("failed to allocate SID\n");
                exit(10);
        }
        sid->Revision = 1;
        sid->SubAuthorityCount = 2;
        memcpy(sid->IdentifierAuthority, NT_SID_AUTHORITY, 6);
        sid->SubAuthority = &sa[0];
        sid->SubAuthority[0] = 32;
        sid->SubAuthority[1] = 544;

        num_sids = 2;
        sids = malloc(num_sids * sizeof(PRPC_SID));
        if (sids == NULL) {
                printf("failed to allocate SIDs\n");
                exit(10);
        }
        req.SidEnumBuffer.Entries = num_sids;
        req.SidEnumBuffer.SidInfo = sids;
        req.SidEnumBuffer.SidInfo[0] = sid;
        req.SidEnumBuffer.SidInfo[1] = sid;

        req.TranslatedNames.Entries = 0;
        req.TranslatedNames.Names = 0;
        req.LookupLevel = LsapLookupWksta;
        
        test_dcerpc_codec(dce, "LSA LookupSids2 Request",
                          lsa_LookupSids2_req_coder, &req, sizeof(req),
                          sizeof(buf), buf, 0);
        free(sid);
        free(sids);
}

static void test_LSA_LookupSids2_rep(struct dcerpc_context *dce)
{
        struct lsa_lookupsids2_rep rep;
        LSAPR_TRUST_INFORMATION domains[1];
        LSAPR_TRANSLATED_NAME_EX names[2];
        uint32_t sa[1];
        unsigned char buf[] = {
0x55, 0x70, 0x74, 0x72, 0x01, 0x00, 0x00, 0x00, 
0x55, 0x70, 0x74, 0x72, 0x20, 0x00, 0x00, 0x00, 
0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x10, 0x00, 
0x55, 0x70, 0x74, 0x72, 0x55, 0x70, 0x74, 0x72, 
0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x07, 0x00, 0x00, 0x00, 0x42, 0x00, 0x55, 0x00, 
0x49, 0x00, 0x4c, 0x00, 0x54, 0x00, 0x49, 0x00, 
0x4e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 
0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
0x55, 0x70, 0x74, 0x72, 0x02, 0x00, 0x00, 0x00, 
0x04, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x1c, 0x00, 
0x55, 0x70, 0x74, 0x72, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
0x1c, 0x00, 0x1c, 0x00, 0x55, 0x70, 0x74, 0x72, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x0e, 0x00, 0x00, 0x00, 0x41, 0x00, 0x64, 0x00, 
0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x69, 0x00, 
0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x61, 0x00, 
0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x73, 0x00, 
0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x0e, 0x00, 0x00, 0x00, 0x41, 0x00, 0x64, 0x00, 
0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x69, 0x00, 
0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x61, 0x00, 
0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x73, 0x00, 
0x02, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00 };

        domains[0].Name = "BUILTIN";
        domains[0].Sid.Revision = 1;
        domains[0].Sid.SubAuthorityCount = 1;
        memcpy(domains[0].Sid.IdentifierAuthority, NT_SID_AUTHORITY, 6);
        domains[0].Sid.SubAuthority = sa;
        domains[0].Sid.SubAuthority[0] = 32;

        names[0].Use = 4;
        names[0].Name = "Administrators";
        names[0].DomainIndex = 0;
        names[0].Flags = 0;
        names[1].Use = 4;
        names[1].Name = "Administrators";
        names[1].DomainIndex = 0;
        names[1].Flags = 0;
                
        rep.status = 27;
        rep.ReferencedDomains.Entries = 1;
        rep.ReferencedDomains.Domains = domains;
        rep.ReferencedDomains.MaxEntries = 32;
        rep.TranslatedNames.Entries = 2;
        rep.TranslatedNames.Names = names;
        rep.MappedCount = 2;

        test_dcerpc_codec(dce, "LSA LookupSids2 Reply",
                          lsa_LookupSids2_rep_coder, &rep, sizeof(rep),
                          sizeof(buf), buf, 0);
}

static void test_LSA_Close_req(struct dcerpc_context *dce)
{
        struct lsa_lookupsids2_req req;
        unsigned char buf[] = {
0x00, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 
0x65, 0x66, 0x67, 0x68, 0x35, 0x34, 0x33, 0x32, 
0x31, 0x30, 0x6a, 0x69 };

        memcpy(&req.PolicyHandle, &PolicyHandle,
               sizeof(struct ndr_context_handle));

        test_dcerpc_codec(dce, "LSA Close Request",
                          lsa_Close_req_coder, &req, sizeof(req),
                          sizeof(buf), buf, 0);
}

static void test_LSA_Close_rep(struct dcerpc_context *dce)
{
        struct lsa_close_rep rep;
        unsigned char buf[] = {
0x00, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 
0x65, 0x66, 0x67, 0x68, 0x35, 0x34, 0x33, 0x32, 
0x31, 0x30, 0x6a, 0x69, 0x00, 0x00, 0x00, 0x00 };

        rep.status = 0;
        memcpy(&rep.PolicyHandle, &PolicyHandle,
               sizeof(struct ndr_context_handle));

        test_dcerpc_codec(dce, "LSA Close Reply",
                          lsa_Close_rep_coder, &rep, sizeof(rep),
                          sizeof(buf), buf, 0);
}

static void test_LSA_OpenPolicy2_req(struct dcerpc_context *dce)
{
        struct lsa_openpolicy2_req req;
        unsigned char buf[] = {
0x55, 0x70, 0x74, 0x72, 0x0a, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 
0x5c, 0x00, 0x5c, 0x00, 0x77, 0x00, 0x69, 0x00, 
0x6e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x2d, 0x00, 
0x31, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00 };

        req.SystemName = "\\\\win16-1";
        req.ObjectAttributes.Length = 24;
        req.DesiredAccess = POLICY_LOOKUP_NAMES |
                POLICY_VIEW_LOCAL_INFORMATION;

        test_dcerpc_codec(dce, "LSA OpenPolicy2 Request",
                          lsa_OpenPolicy2_req_coder, &req, sizeof(req),
                          sizeof(buf), buf, 0);
}

static void test_LSA_OpenPolicy2_rep(struct dcerpc_context *dce)
{
        struct lsa_openpolicy2_rep rep;
        unsigned char buf[] = {
0x00, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 
0x65, 0x66, 0x67, 0x68, 0x35, 0x34, 0x33, 0x32, 
0x31, 0x30, 0x6a, 0x69, 0x00, 0x00, 0x00, 0x00 };

        rep.status = 0;
        memcpy(&rep.PolicyHandle, &PolicyHandle,
               sizeof(struct ndr_context_handle));

        test_dcerpc_codec(dce, "LSA OpenPolicy2 Reply",
                          lsa_OpenPolicy2_rep_coder, &rep, sizeof(rep),
                          sizeof(buf), buf, 0);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct dcerpc_context *dce;
        char ph[16] = "abcdefghij012345";

        if (argc != 1) {
                usage();
        }

	smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                exit(0);
        }

        dce = dcerpc_create_context(smb2);
        if (dce == NULL) {
		printf("Failed to create dce context. %s\n",
                       smb2_get_error(smb2));
		exit(10);
        }

        PolicyHandle.context_handle_attributes = 0;
        memcpy(&PolicyHandle.context_handle_uuid, ph, 16);

        test_LSA_LookupSids2_req(dce);
        test_LSA_LookupSids2_rep(dce);
        test_LSA_Close_req(dce);
        test_LSA_Close_rep(dce);
        test_LSA_OpenPolicy2_req(dce);
        test_LSA_OpenPolicy2_rep(dce);

        dcerpc_destroy_context(dce);
        smb2_destroy_context(smb2);
        
	return 0;
}
