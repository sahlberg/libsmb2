/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Transcoding tests for the samr coders: the request and reply of every
 * operation, and LookupDomainInSamServer for the account domain, Builtin
 * and a domain that does not exist. See coder-test.h for the tests run
 * per case.
 *
 * Where the known-good NDR stubs come from (win16-1, Windows Server 2016):
 *
 * - Replies were captured from the server. Windows always replies in its
 *   native format, so there are only NDR32 and NDR64 little-endian ones.
 * - Requests were encoded by libdcerpc and sent to the server, which
 *   accepted them as NDR32 LE, NDR32 BE and NDR64 LE and answered each
 *   flavor alike apart from the context handles. Windows does not support
 *   NDR64 BE.
 * - The calls ran as one chain per flavor: Connect,
 *   EnumerateDomainsInSamServer, LookupDomainInSamServer for
 *   WIN-OR90BFOC38G, Builtin and NoSuchDomain (STATUS_NO_SUCH_DOMAIN, no
 *   DomainId), CloseHandle, Connect2 and CloseHandle, Connect5 and
 *   CloseHandle.
 *
 * The data was generated from the captures; cases whose captures differ
 * in live values are split into one case per capture.
 */

#include <stdint.h>
#include <stddef.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/samr.h>

#include "coder-test.h"

/* Requests for the reply cases */
static struct samr_Connect_req connect_rep_ndr32_le_req = {};
static struct samr_Connect_req connect_rep_ndr64_le_req = {};
static struct samr_EnumerateDomainsInSamServer_req enumeratedomainsinsamserver_rep_req = {};
static struct samr_LookupDomainInSamServer_req lookupdomaininsamserver_rep_req = {};
static struct samr_LookupDomainInSamServer_req lookupdomaininsamserver_builtin_rep_req = {};
static struct samr_LookupDomainInSamServer_req lookupdomaininsamserver_nosuchdomain_rep_req = {};
static struct samr_CloseHandle_req closehandle_rep_req = {};
static struct samr_Connect2_req connect2_rep_ndr32_le_req = {};
static struct samr_Connect2_req connect2_rep_ndr64_le_req = {};
static struct samr_Connect5_req connect5_rep_ndr32_le_req = {};
static struct samr_Connect5_req connect5_rep_ndr64_le_req = {};

/*
 * Known-good NDR stubs: the PDU body after the 24-byte request or
 * response header.
 */
static const uint8_t connect_rep_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x37, 0x7d, 0x72, 0x71,
        0xa1, 0x12, 0xed, 0x40, 0xbc, 0x20, 0xfb, 0x87,
        0x05, 0x17, 0x5d, 0x2d, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t connect_rep_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0xf7, 0x50, 0x2a, 0x61,
        0x06, 0xf1, 0x40, 0x40, 0x9d, 0xd8, 0x37, 0x0f,
        0xc7, 0x93, 0xe1, 0x0a, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumeratedomainsinsamserver_rep_ndr32_le[] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1e, 0x00, 0x20, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x10, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x2d, 0x00,
        0x4f, 0x00, 0x52, 0x00, 0x39, 0x00, 0x30, 0x00,
        0x42, 0x00, 0x46, 0x00, 0x4f, 0x00, 0x43, 0x00,
        0x33, 0x00, 0x38, 0x00, 0x47, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x42, 0x00, 0x75, 0x00,
        0x69, 0x00, 0x6c, 0x00, 0x74, 0x00, 0x69, 0x00,
        0x6e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumeratedomainsinsamserver_rep_ndr64_le[] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1e, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0e, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x2d, 0x00,
        0x4f, 0x00, 0x52, 0x00, 0x39, 0x00, 0x30, 0x00,
        0x42, 0x00, 0x46, 0x00, 0x4f, 0x00, 0x43, 0x00,
        0x33, 0x00, 0x38, 0x00, 0x47, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x42, 0x00, 0x75, 0x00, 0x69, 0x00, 0x6c, 0x00,
        0x74, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t lookupdomaininsamserver_rep_ndr32_le[] = {
        0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x15, 0x00, 0x00, 0x00, 0x9f, 0x7c, 0x1a, 0x26,
        0xc6, 0x30, 0x46, 0x68, 0x62, 0x80, 0xb6, 0xcb,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t lookupdomaininsamserver_rep_ndr64_le[] = {
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x15, 0x00, 0x00, 0x00, 0x9f, 0x7c, 0x1a, 0x26,
        0xc6, 0x30, 0x46, 0x68, 0x62, 0x80, 0xb6, 0xcb,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t lookupdomaininsamserver_builtin_rep_ndr32_le[] = {
        0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t lookupdomaininsamserver_builtin_rep_ndr64_le[] = {
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t lookupdomaininsamserver_nosuchdomain_rep_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0xdf, 0x00, 0x00, 0xc0,
};
static const uint8_t lookupdomaininsamserver_nosuchdomain_rep_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xdf, 0x00, 0x00, 0xc0,
};
static const uint8_t closehandle_rep_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t closehandle_rep_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t connect2_rep_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x51, 0x42, 0x5a, 0xdb,
        0x89, 0x23, 0x3d, 0x47, 0x90, 0x3d, 0xcf, 0x09,
        0xe8, 0x99, 0x91, 0x5f, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t connect2_rep_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x76, 0x82, 0x4d, 0x14,
        0x1f, 0x82, 0xc2, 0x46, 0x8f, 0x18, 0xcc, 0x92,
        0xce, 0xe8, 0x5e, 0xb2, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t connect5_rep_ndr32_le_ndr32_le[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x31, 0xec, 0xfa, 0x0b,
        0x71, 0x50, 0xa3, 0x45, 0xba, 0x73, 0x68, 0x35,
        0x49, 0xf2, 0xe8, 0xd9, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t connect5_rep_ndr64_le_ndr64_le[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x44, 0x26, 0x13, 0x67,
        0x65, 0x16, 0xc5, 0x47, 0x93, 0x49, 0xa9, 0xb6,
        0x6b, 0xac, 0xd1, 0xd8, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t connect_req_ndr32_le[] = {
        0x55, 0x70, 0x74, 0x72, 0x5c, 0x00, 0x00, 0x00,
        0x31, 0x00, 0x00, 0x00,
};
static const uint8_t connect_req_ndr32_be[] = {
        0x72, 0x74, 0x70, 0x55, 0x00, 0x5c, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x31,
};
static const uint8_t connect_req_ndr64_le[] = {
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x5c, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00,
};
static const uint8_t enumeratedomainsinsamserver_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x37, 0x7d, 0x72, 0x71,
        0xa1, 0x12, 0xed, 0x40, 0xbc, 0x20, 0xfb, 0x87,
        0x05, 0x17, 0x5d, 0x2d, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
};
static const uint8_t enumeratedomainsinsamserver_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0xcb, 0xe0, 0xa2, 0xc6,
        0x79, 0xbe, 0x42, 0x35, 0xa9, 0x52, 0x42, 0x57,
        0xa3, 0x46, 0x87, 0x1e, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00,
};
static const uint8_t enumeratedomainsinsamserver_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0xf7, 0x50, 0x2a, 0x61,
        0x06, 0xf1, 0x40, 0x40, 0x9d, 0xd8, 0x37, 0x0f,
        0xc7, 0x93, 0xe1, 0x0a, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
};
static const uint8_t lookupdomaininsamserver_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x37, 0x7d, 0x72, 0x71,
        0xa1, 0x12, 0xed, 0x40, 0xbc, 0x20, 0xfb, 0x87,
        0x05, 0x17, 0x5d, 0x2d, 0x1e, 0x00, 0x20, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x2d, 0x00,
        0x4f, 0x00, 0x52, 0x00, 0x39, 0x00, 0x30, 0x00,
        0x42, 0x00, 0x46, 0x00, 0x4f, 0x00, 0x43, 0x00,
        0x33, 0x00, 0x38, 0x00, 0x47, 0x00,
};
static const uint8_t lookupdomaininsamserver_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0xcb, 0xe0, 0xa2, 0xc6,
        0x79, 0xbe, 0x42, 0x35, 0xa9, 0x52, 0x42, 0x57,
        0xa3, 0x46, 0x87, 0x1e, 0x00, 0x1e, 0x00, 0x20,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        0x00, 0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x2d,
        0x00, 0x4f, 0x00, 0x52, 0x00, 0x39, 0x00, 0x30,
        0x00, 0x42, 0x00, 0x46, 0x00, 0x4f, 0x00, 0x43,
        0x00, 0x33, 0x00, 0x38, 0x00, 0x47,
};
static const uint8_t lookupdomaininsamserver_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0xf7, 0x50, 0x2a, 0x61,
        0x06, 0xf1, 0x40, 0x40, 0x9d, 0xd8, 0x37, 0x0f,
        0xc7, 0x93, 0xe1, 0x0a, 0x00, 0x00, 0x00, 0x00,
        0x1e, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x2d, 0x00,
        0x4f, 0x00, 0x52, 0x00, 0x39, 0x00, 0x30, 0x00,
        0x42, 0x00, 0x46, 0x00, 0x4f, 0x00, 0x43, 0x00,
        0x33, 0x00, 0x38, 0x00, 0x47, 0x00,
};
static const uint8_t closehandle_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x37, 0x7d, 0x72, 0x71,
        0xa1, 0x12, 0xed, 0x40, 0xbc, 0x20, 0xfb, 0x87,
        0x05, 0x17, 0x5d, 0x2d,
};
static const uint8_t closehandle_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0xcb, 0xe0, 0xa2, 0xc6,
        0x79, 0xbe, 0x42, 0x35, 0xa9, 0x52, 0x42, 0x57,
        0xa3, 0x46, 0x87, 0x1e,
};
static const uint8_t closehandle_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0xf7, 0x50, 0x2a, 0x61,
        0x06, 0xf1, 0x40, 0x40, 0x9d, 0xd8, 0x37, 0x0f,
        0xc7, 0x93, 0xe1, 0x0a,
};
static const uint8_t connect2_req_ndr32_le[] = {
        0x55, 0x70, 0x74, 0x72, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x49, 0x00,
        0x4e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x2d, 0x00,
        0x31, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
};
static const uint8_t connect2_req_ndr32_be[] = {
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x0a,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
        0x00, 0x5c, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x49,
        0x00, 0x4e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x2d,
        0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
};
static const uint8_t connect2_req_ndr64_le[] = {
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x49, 0x00,
        0x4e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x2d, 0x00,
        0x31, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
};
static const uint8_t connect5_req_ndr32_le[] = {
        0x55, 0x70, 0x74, 0x72, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x49, 0x00,
        0x4e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x2d, 0x00,
        0x31, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t connect5_req_ndr32_be[] = {
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x0a,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
        0x00, 0x5c, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x49,
        0x00, 0x4e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x2d,
        0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t connect5_req_ndr64_le[] = {
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x57, 0x00, 0x49, 0x00,
        0x4e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x2d, 0x00,
        0x31, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Known-good YAML */
static const char connect_rep_ndr32_le_yaml[] =
        "Connect: Response\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 71727d37-12a1-40ed-bc20-fb8705175d2d\n"
        "  Status: 0\n";

static const char connect_rep_ndr64_le_yaml[] =
        "Connect: Response\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 612a50f7-f106-4040-9dd8-370fc793e10a\n"
        "  Status: 0\n";

static const char enumeratedomainsinsamserver_rep_yaml[] =
        "EnumerateDomainsInSamServer: Response\n"
        "  EnumerationContext: 2\n"
        "  Buffer: \n"
        "    EntriesRead: 2\n"
        "    Buffer:\n"
        "      - RelativeId: 0\n"
        "        Name: WIN-OR90BFOC38G\n"
        "      - RelativeId: 0\n"
        "        Name: Builtin\n"
        "  CountReturned: 2\n"
        "  Status: 0\n";

static const char lookupdomaininsamserver_rep_yaml[] =
        "LookupDomainInSamServer: Response\n"
        "  DomainId: S-1-5-21-639270047-1749430470-3417735266\n"
        "  Status: 0\n";

static const char lookupdomaininsamserver_builtin_rep_yaml[] =
        "LookupDomainInSamServer: Response\n"
        "  DomainId: S-1-5-32\n"
        "  Status: 0\n";

static const char lookupdomaininsamserver_nosuchdomain_rep_yaml[] =
        "LookupDomainInSamServer: Response\n"
        "  Status: 3221225695\n";

static const char closehandle_rep_yaml[] =
        "CloseHandle: Response\n"
        "  SamHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 00000000-0000-0000-0000-000000000000\n"
        "  Status: 0\n";

static const char connect2_rep_ndr32_le_yaml[] =
        "Connect2: Response\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: db5a4251-2389-473d-903d-cf09e899915f\n"
        "  Status: 0\n";

static const char connect2_rep_ndr64_le_yaml[] =
        "Connect2: Response\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 144d8276-821f-46c2-8f18-cc92cee85eb2\n"
        "  Status: 0\n";

static const char connect5_rep_ndr32_le_yaml[] =
        "Connect5: Response\n"
        "  OutVersion: 1\n"
        "  OutRevisionInfo:\n"
        "    V1: \n"
        "      Revision: 3\n"
        "      SupportedFeatures: 0\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 0bfaec31-5071-45a3-ba73-683549f2e8d9\n"
        "  Status: 0\n";

static const char connect5_rep_ndr64_le_yaml[] =
        "Connect5: Response\n"
        "  OutVersion: 1\n"
        "  OutRevisionInfo:\n"
        "    V1: \n"
        "      Revision: 3\n"
        "      SupportedFeatures: 0\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 67132644-1665-47c5-9349-a9b66bacd1d8\n"
        "  Status: 0\n";

static const char connect_req_yaml[] =
        "Connect: Request\n"
        "  ServerName: 92\n"
        "  DesiredAccess: SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN\n";

static const char enumeratedomainsinsamserver_req_ndr32_le_yaml[] =
        "EnumerateDomainsInSamServer: Request\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 71727d37-12a1-40ed-bc20-fb8705175d2d\n"
        "  EnumerationContext: 0\n"
        "  PreferedMaximumLength: 4096\n";

static const char enumeratedomainsinsamserver_req_ndr32_be_yaml[] =
        "EnumerateDomainsInSamServer: Request\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: cbe0a2c6-79be-4235-a952-4257a346871e\n"
        "  EnumerationContext: 0\n"
        "  PreferedMaximumLength: 4096\n";

static const char enumeratedomainsinsamserver_req_ndr64_le_yaml[] =
        "EnumerateDomainsInSamServer: Request\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 612a50f7-f106-4040-9dd8-370fc793e10a\n"
        "  EnumerationContext: 0\n"
        "  PreferedMaximumLength: 4096\n";

static const char lookupdomaininsamserver_req_ndr32_le_yaml[] =
        "LookupDomainInSamServer: Request\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 71727d37-12a1-40ed-bc20-fb8705175d2d\n"
        "  Name: WIN-OR90BFOC38G\n";

static const char lookupdomaininsamserver_req_ndr32_be_yaml[] =
        "LookupDomainInSamServer: Request\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: cbe0a2c6-79be-4235-a952-4257a346871e\n"
        "  Name: WIN-OR90BFOC38G\n";

static const char lookupdomaininsamserver_req_ndr64_le_yaml[] =
        "LookupDomainInSamServer: Request\n"
        "  ServerHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 612a50f7-f106-4040-9dd8-370fc793e10a\n"
        "  Name: WIN-OR90BFOC38G\n";

static const char closehandle_req_ndr32_le_yaml[] =
        "CloseHandle: Request\n"
        "  SamHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 71727d37-12a1-40ed-bc20-fb8705175d2d\n";

static const char closehandle_req_ndr32_be_yaml[] =
        "CloseHandle: Request\n"
        "  SamHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: cbe0a2c6-79be-4235-a952-4257a346871e\n";

static const char closehandle_req_ndr64_le_yaml[] =
        "CloseHandle: Request\n"
        "  SamHandle: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 612a50f7-f106-4040-9dd8-370fc793e10a\n";

static const char connect2_req_yaml[] =
        "Connect2: Request\n"
        "  ServerName: \\\\WIN16-1\n"
        "  DesiredAccess: SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS\n";

static const char connect5_req_yaml[] =
        "Connect5: Request\n"
        "  ServerName: \\\\WIN16-1\n"
        "  DesiredAccess: SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS\n"
        "  InVersion: 1\n"
        "  InRevisionInfo:\n"
        "    V1: \n"
        "      Revision: 3\n"
        "      SupportedFeatures: 0\n";

static const struct test_case test_cases[] = {
        { "Connect reply (NDR32 LE capture)", "Connect",
          samr_Connect_rep_coder, sizeof(struct samr_Connect_rep),
          &connect_rep_ndr32_le_req, connect_rep_ndr32_le_yaml,
          { { connect_rep_ndr32_le_ndr32_le, sizeof(connect_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "Connect reply (NDR64 LE capture)", "Connect",
          samr_Connect_rep_coder, sizeof(struct samr_Connect_rep),
          &connect_rep_ndr64_le_req, connect_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { connect_rep_ndr64_le_ndr64_le, sizeof(connect_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "EnumerateDomainsInSamServer reply", "EnumerateDomainsInSamServer",
          samr_EnumerateDomainsInSamServer_rep_coder, sizeof(struct samr_EnumerateDomainsInSamServer_rep),
          &enumeratedomainsinsamserver_rep_req, enumeratedomainsinsamserver_rep_yaml,
          { { enumeratedomainsinsamserver_rep_ndr32_le, sizeof(enumeratedomainsinsamserver_rep_ndr32_le) },
            { NULL, 0 },
            { enumeratedomainsinsamserver_rep_ndr64_le, sizeof(enumeratedomainsinsamserver_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "LookupDomainInSamServer reply, account domain", "LookupDomainInSamServer",
          samr_LookupDomainInSamServer_rep_coder, sizeof(struct samr_LookupDomainInSamServer_rep),
          &lookupdomaininsamserver_rep_req, lookupdomaininsamserver_rep_yaml,
          { { lookupdomaininsamserver_rep_ndr32_le, sizeof(lookupdomaininsamserver_rep_ndr32_le) },
            { NULL, 0 },
            { lookupdomaininsamserver_rep_ndr64_le, sizeof(lookupdomaininsamserver_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "LookupDomainInSamServer reply, Builtin", "LookupDomainInSamServer",
          samr_LookupDomainInSamServer_rep_coder, sizeof(struct samr_LookupDomainInSamServer_rep),
          &lookupdomaininsamserver_builtin_rep_req, lookupdomaininsamserver_builtin_rep_yaml,
          { { lookupdomaininsamserver_builtin_rep_ndr32_le, sizeof(lookupdomaininsamserver_builtin_rep_ndr32_le) },
            { NULL, 0 },
            { lookupdomaininsamserver_builtin_rep_ndr64_le, sizeof(lookupdomaininsamserver_builtin_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "LookupDomainInSamServer reply, STATUS_NO_SUCH_DOMAIN", "LookupDomainInSamServer",
          samr_LookupDomainInSamServer_rep_coder, sizeof(struct samr_LookupDomainInSamServer_rep),
          &lookupdomaininsamserver_nosuchdomain_rep_req, lookupdomaininsamserver_nosuchdomain_rep_yaml,
          { { lookupdomaininsamserver_nosuchdomain_rep_ndr32_le, sizeof(lookupdomaininsamserver_nosuchdomain_rep_ndr32_le) },
            { NULL, 0 },
            { lookupdomaininsamserver_nosuchdomain_rep_ndr64_le, sizeof(lookupdomaininsamserver_nosuchdomain_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "CloseHandle reply", "CloseHandle",
          samr_CloseHandle_rep_coder, sizeof(struct samr_CloseHandle_rep),
          &closehandle_rep_req, closehandle_rep_yaml,
          { { closehandle_rep_ndr32_le, sizeof(closehandle_rep_ndr32_le) },
            { NULL, 0 },
            { closehandle_rep_ndr64_le, sizeof(closehandle_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "Connect2 reply (NDR32 LE capture)", "Connect2",
          samr_Connect2_rep_coder, sizeof(struct samr_Connect2_rep),
          &connect2_rep_ndr32_le_req, connect2_rep_ndr32_le_yaml,
          { { connect2_rep_ndr32_le_ndr32_le, sizeof(connect2_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "Connect2 reply (NDR64 LE capture)", "Connect2",
          samr_Connect2_rep_coder, sizeof(struct samr_Connect2_rep),
          &connect2_rep_ndr64_le_req, connect2_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { connect2_rep_ndr64_le_ndr64_le, sizeof(connect2_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "Connect5 reply (NDR32 LE capture)", "Connect5",
          samr_Connect5_rep_coder, sizeof(struct samr_Connect5_rep),
          &connect5_rep_ndr32_le_req, connect5_rep_ndr32_le_yaml,
          { { connect5_rep_ndr32_le_ndr32_le, sizeof(connect5_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "Connect5 reply (NDR64 LE capture)", "Connect5",
          samr_Connect5_rep_coder, sizeof(struct samr_Connect5_rep),
          &connect5_rep_ndr64_le_req, connect5_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { connect5_rep_ndr64_le_ndr64_le, sizeof(connect5_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "Connect request", "Connect",
          samr_Connect_req_coder, sizeof(struct samr_Connect_req),
          NULL, connect_req_yaml,
          { { connect_req_ndr32_le, sizeof(connect_req_ndr32_le) },
            { connect_req_ndr32_be, sizeof(connect_req_ndr32_be) },
            { connect_req_ndr64_le, sizeof(connect_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "EnumerateDomainsInSamServer request (NDR32 LE capture)", "EnumerateDomainsInSamServer",
          samr_EnumerateDomainsInSamServer_req_coder, sizeof(struct samr_EnumerateDomainsInSamServer_req),
          NULL, enumeratedomainsinsamserver_req_ndr32_le_yaml,
          { { enumeratedomainsinsamserver_req_ndr32_le_ndr32_le, sizeof(enumeratedomainsinsamserver_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "EnumerateDomainsInSamServer request (NDR32 BE capture)", "EnumerateDomainsInSamServer",
          samr_EnumerateDomainsInSamServer_req_coder, sizeof(struct samr_EnumerateDomainsInSamServer_req),
          NULL, enumeratedomainsinsamserver_req_ndr32_be_yaml,
          { { NULL, 0 },
            { enumeratedomainsinsamserver_req_ndr32_be_ndr32_be, sizeof(enumeratedomainsinsamserver_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "EnumerateDomainsInSamServer request (NDR64 LE capture)", "EnumerateDomainsInSamServer",
          samr_EnumerateDomainsInSamServer_req_coder, sizeof(struct samr_EnumerateDomainsInSamServer_req),
          NULL, enumeratedomainsinsamserver_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { enumeratedomainsinsamserver_req_ndr64_le_ndr64_le, sizeof(enumeratedomainsinsamserver_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "LookupDomainInSamServer request (NDR32 LE capture)", "LookupDomainInSamServer",
          samr_LookupDomainInSamServer_req_coder, sizeof(struct samr_LookupDomainInSamServer_req),
          NULL, lookupdomaininsamserver_req_ndr32_le_yaml,
          { { lookupdomaininsamserver_req_ndr32_le_ndr32_le, sizeof(lookupdomaininsamserver_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "LookupDomainInSamServer request (NDR32 BE capture)", "LookupDomainInSamServer",
          samr_LookupDomainInSamServer_req_coder, sizeof(struct samr_LookupDomainInSamServer_req),
          NULL, lookupdomaininsamserver_req_ndr32_be_yaml,
          { { NULL, 0 },
            { lookupdomaininsamserver_req_ndr32_be_ndr32_be, sizeof(lookupdomaininsamserver_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "LookupDomainInSamServer request (NDR64 LE capture)", "LookupDomainInSamServer",
          samr_LookupDomainInSamServer_req_coder, sizeof(struct samr_LookupDomainInSamServer_req),
          NULL, lookupdomaininsamserver_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { lookupdomaininsamserver_req_ndr64_le_ndr64_le, sizeof(lookupdomaininsamserver_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "CloseHandle request (NDR32 LE capture)", "CloseHandle",
          samr_CloseHandle_req_coder, sizeof(struct samr_CloseHandle_req),
          NULL, closehandle_req_ndr32_le_yaml,
          { { closehandle_req_ndr32_le_ndr32_le, sizeof(closehandle_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "CloseHandle request (NDR32 BE capture)", "CloseHandle",
          samr_CloseHandle_req_coder, sizeof(struct samr_CloseHandle_req),
          NULL, closehandle_req_ndr32_be_yaml,
          { { NULL, 0 },
            { closehandle_req_ndr32_be_ndr32_be, sizeof(closehandle_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "CloseHandle request (NDR64 LE capture)", "CloseHandle",
          samr_CloseHandle_req_coder, sizeof(struct samr_CloseHandle_req),
          NULL, closehandle_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { closehandle_req_ndr64_le_ndr64_le, sizeof(closehandle_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "Connect2 request", "Connect2",
          samr_Connect2_req_coder, sizeof(struct samr_Connect2_req),
          NULL, connect2_req_yaml,
          { { connect2_req_ndr32_le, sizeof(connect2_req_ndr32_le) },
            { connect2_req_ndr32_be, sizeof(connect2_req_ndr32_be) },
            { connect2_req_ndr64_le, sizeof(connect2_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "Connect5 request", "Connect5",
          samr_Connect5_req_coder, sizeof(struct samr_Connect5_req),
          NULL, connect5_req_yaml,
          { { connect5_req_ndr32_le, sizeof(connect5_req_ndr32_le) },
            { connect5_req_ndr32_be, sizeof(connect5_req_ndr32_be) },
            { connect5_req_ndr64_le, sizeof(connect5_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
};

int main(void)
{
        return run_coder_tests(test_cases,
                               sizeof(test_cases) / sizeof(test_cases[0]));
}
