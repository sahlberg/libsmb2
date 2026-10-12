/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Transcoding tests for the winreg coders: the request and reply of every
 * operation, each value type BaseRegSetValue and BaseRegEnumValue carry,
 * and BaseRegCreateKey with and without RPC_SECURITY_ATTRIBUTES. See
 * coder-test.h for the tests run per case.
 *
 * Where the known-good NDR stubs come from (win16-1, Windows Server 2016):
 *
 * - Replies were captured from the server. Windows always replies in its
 *   native format, so there are only NDR32 and NDR64 little-endian ones.
 * - Requests were encoded by libdcerpc and sent to the server, which
 *   accepted them as NDR32 LE, NDR32 BE and NDR64 LE, and answered each
 *   flavor alike apart from live values (context handles, last-write
 *   times). Windows does not support NDR64 BE.
 * - The calls ran as one chain per flavor that opens HKLM\SOFTWARE,
 *   creates the key libdcerpc-test with a subkey and REG_SZ, REG_DWORD and
 *   REG_BINARY values, queries and enumerates them, and deletes them
 *   again; and a chain that opens and closes each predefined key.
 *
 * Replies with out strings (BaseRegQueryInfoKey, BaseRegEnumKey,
 * BaseRegEnumValue) are marked XFAIL: Windows sets their MaximumLength to
 * the client's buffer size, which libdcerpc does not keep because these
 * strings are char *, so they re-encode with MaximumLength = Length.
 *
 * The data was generated from the captures; cases whose captures differ
 * in live values are split into one case per capture.
 */

#include <stdint.h>
#include <stddef.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/winreg.h>

#include "coder-test.h"

/* Requests for the reply cases */
static struct winreg_OpenLocalMachine_req OpenLocalMachine_rep_ndr32_le_req = {};
static struct winreg_OpenLocalMachine_req OpenLocalMachine_rep_ndr64_le_req = {};
static struct winreg_OpenClassesRoot_req OpenClassesRoot_rep_ndr32_le_req = {};
static struct winreg_OpenClassesRoot_req OpenClassesRoot_rep_ndr64_le_req = {};
static struct winreg_OpenCurrentUser_req OpenCurrentUser_rep_ndr32_le_req = {};
static struct winreg_OpenCurrentUser_req OpenCurrentUser_rep_ndr64_le_req = {};
static struct winreg_OpenUsers_req OpenUsers_rep_ndr32_le_req = {};
static struct winreg_OpenUsers_req OpenUsers_rep_ndr64_le_req = {};
static struct winreg_OpenCurrentConfig_req OpenCurrentConfig_rep_ndr32_le_req = {};
static struct winreg_OpenCurrentConfig_req OpenCurrentConfig_rep_ndr64_le_req = {};
static struct winreg_BaseRegOpenKey_req openkey_rep_ndr32_le_req = {};
static struct winreg_BaseRegOpenKey_req openkey_rep_ndr64_le_req = {};
static struct winreg_BaseRegCreateKey_req createkey_rep_ndr32_le_req = {};
static struct winreg_BaseRegCreateKey_req createkey_rep_ndr64_le_req = {};
static struct winreg_BaseRegSetValue_req setvalue_rep_req = {};
static struct winreg_BaseRegQueryInfoKey_req queryinfokey_rep_ndr32_le_req = {};
static struct winreg_BaseRegQueryInfoKey_req queryinfokey_rep_ndr64_le_req = {};
static struct winreg_BaseRegEnumValue_req enumvalue_REG_SZ_rep_req = {};
static struct winreg_BaseRegEnumValue_req enumvalue_REG_DWORD_rep_req = {};
static struct winreg_BaseRegEnumValue_req enumvalue_REG_BINARY_rep_req = {};
static struct winreg_BaseRegCloseKey_req closekey_rep_req = {};
static struct winreg_BaseRegEnumKey_req enumkey_rep_ndr32_le_req = {};
static struct winreg_BaseRegEnumKey_req enumkey_rep_ndr64_le_req = {};
static struct winreg_BaseRegDeleteValue_req deletevalue_rep_req = {};
static struct winreg_BaseRegDeleteKey_req deletekey_rep_req = {};

/*
 * Known-good NDR stubs: the PDU body after the 24-byte request or
 * response header.
 */
static const uint8_t OpenLocalMachine_rep_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0xec, 0xe2, 0xdb, 0x70,
        0x9c, 0x28, 0x22, 0x47, 0x88, 0x51, 0x31, 0xcb,
        0x7d, 0x30, 0x14, 0x68, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t OpenLocalMachine_rep_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x50, 0x67, 0x08, 0xb8,
        0xa5, 0x55, 0x4b, 0x4b, 0xad, 0xba, 0x8e, 0xe3,
        0xb8, 0x62, 0x6a, 0x98, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t OpenClassesRoot_rep_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x97, 0xc9, 0x28, 0xc3,
        0xfc, 0x91, 0xbd, 0x40, 0x8e, 0x14, 0x00, 0x31,
        0xb0, 0x15, 0x2b, 0xac, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t OpenClassesRoot_rep_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x71, 0xfa, 0x67, 0x94,
        0x60, 0x5b, 0x9f, 0x47, 0xbf, 0xc5, 0x1c, 0xde,
        0x2c, 0x2f, 0x07, 0x56, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t OpenCurrentUser_rep_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0xd4, 0x0a, 0x72, 0xee,
        0xc5, 0x0f, 0x3c, 0x45, 0x99, 0x7a, 0x02, 0xfd,
        0xf5, 0x63, 0x45, 0xa6, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t OpenCurrentUser_rep_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x7e, 0xee, 0xef, 0xc8,
        0x77, 0xd0, 0x35, 0x46, 0xab, 0xac, 0x0e, 0xda,
        0xe3, 0x5c, 0xe8, 0x1b, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t OpenUsers_rep_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x17, 0xa0, 0xb6, 0xe0,
        0x0d, 0x87, 0xdf, 0x4b, 0x92, 0x54, 0x56, 0x67,
        0x73, 0xb8, 0xdf, 0x41, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t OpenUsers_rep_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0xec, 0x49, 0x75, 0xb5,
        0x78, 0x87, 0x7d, 0x4b, 0xb3, 0xff, 0x65, 0x7b,
        0x86, 0x75, 0xf3, 0x70, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t OpenCurrentConfig_rep_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x96, 0x70, 0x74, 0xe2,
        0xb4, 0x95, 0x1f, 0x4f, 0x9e, 0x8a, 0x06, 0xad,
        0x9f, 0x22, 0xa1, 0x47, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t OpenCurrentConfig_rep_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x0e, 0x8c, 0x7e, 0x5d,
        0x79, 0x01, 0xc8, 0x4b, 0x80, 0x17, 0xb9, 0x8b,
        0x71, 0x5e, 0xb9, 0xdf, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t openkey_rep_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x03, 0x10, 0x02, 0xd2,
        0x6e, 0x8a, 0x25, 0x42, 0x95, 0xaf, 0x4f, 0xdf,
        0xec, 0x32, 0xb7, 0x2d, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t openkey_rep_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x97, 0x27, 0x43, 0x18,
        0xb7, 0xd2, 0x25, 0x4a, 0xb6, 0x2c, 0x9f, 0x3a,
        0x87, 0x4d, 0xf7, 0x49, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t createkey_rep_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x29, 0x7e, 0xc4, 0xab,
        0x86, 0x01, 0x3d, 0x41, 0xb9, 0xac, 0x95, 0x89,
        0xb5, 0xd6, 0xa5, 0x65, 0x00, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t createkey_rep_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x88, 0x4d, 0x86, 0x75,
        0xf1, 0xee, 0xe1, 0x45, 0xb5, 0x4b, 0xed, 0xdf,
        0x69, 0x24, 0x0f, 0xc8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t setvalue_rep_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t setvalue_rep_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t queryinfokey_rep_ndr32_le_ndr32_le[] = {
        0x02, 0x00, 0x80, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
        0xb8, 0x00, 0x00, 0x00, 0xb7, 0xd7, 0xbf, 0x57,
        0x9b, 0x5a, 0xdd, 0x01, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t queryinfokey_rep_ndr64_le_ndr64_le[] = {
        0x02, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00,
        0xce, 0xfd, 0xc6, 0x57, 0x9b, 0x5a, 0xdd, 0x01,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumvalue_REG_SZ_rep_ndr32_le[] = {
        0x06, 0x00, 0x00, 0x04, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x73, 0x00, 0x7a, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x69, 0x00,
        0x62, 0x00, 0x64, 0x00, 0x63, 0x00, 0x65, 0x00,
        0x72, 0x00, 0x70, 0x00, 0x63, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x02, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumvalue_REG_SZ_rep_ndr64_le[] = {
        0x06, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x73, 0x00, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x6c, 0x00, 0x69, 0x00, 0x62, 0x00, 0x64, 0x00,
        0x63, 0x00, 0x65, 0x00, 0x72, 0x00, 0x70, 0x00,
        0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumvalue_REG_DWORD_rep_ndr32_le[] = {
        0x0c, 0x00, 0x00, 0x04, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x64, 0x00, 0x77, 0x00,
        0x6f, 0x00, 0x72, 0x00, 0x64, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12, 0x0c, 0x00, 0x02, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumvalue_REG_DWORD_rep_ndr64_le[] = {
        0x0c, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72, 0x00,
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumvalue_REG_BINARY_rep_ndr32_le[] = {
        0x08, 0x00, 0x00, 0x04, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x62, 0x00, 0x69, 0x00,
        0x6e, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
        0xff, 0xfe, 0xfd, 0x00, 0x0c, 0x00, 0x02, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumvalue_REG_BINARY_rep_ndr64_le[] = {
        0x08, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x62, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t closekey_rep_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t closekey_rep_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumkey_rep_ndr32_le_ndr32_le[] = {
        0x08, 0x00, 0x00, 0x04, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x73, 0x00, 0x75, 0x00,
        0x62, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
        0x02, 0x00, 0x80, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0xb7, 0xd7, 0xbf, 0x57,
        0x9b, 0x5a, 0xdd, 0x01, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumkey_rep_ndr64_le_ndr64_le[] = {
        0x08, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x73, 0x00, 0x75, 0x00, 0x62, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xce, 0xfd, 0xc6, 0x57, 0x9b, 0x5a, 0xdd, 0x01,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t deletevalue_rep_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t deletevalue_rep_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t deletekey_rep_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t deletekey_rep_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t OpenLocalMachine_req_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x0f, 0x00,
};
static const uint8_t OpenLocalMachine_req_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x3f,
};
static const uint8_t OpenLocalMachine_req_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3f, 0x00, 0x0f, 0x00,
};
static const uint8_t OpenClassesRoot_req_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x02, 0x00,
};
static const uint8_t OpenClassesRoot_req_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x19,
};
static const uint8_t OpenClassesRoot_req_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x02, 0x00,
};
static const uint8_t OpenCurrentUser_req_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x02, 0x00,
};
static const uint8_t OpenCurrentUser_req_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x19,
};
static const uint8_t OpenCurrentUser_req_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x02, 0x00,
};
static const uint8_t OpenUsers_req_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x02, 0x00,
};
static const uint8_t OpenUsers_req_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x19,
};
static const uint8_t OpenUsers_req_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x02, 0x00,
};
static const uint8_t OpenCurrentConfig_req_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x02, 0x00,
};
static const uint8_t OpenCurrentConfig_req_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x19,
};
static const uint8_t OpenCurrentConfig_req_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x19, 0x00, 0x02, 0x00,
};
static const uint8_t openkey_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0xec, 0xe2, 0xdb, 0x70,
        0x9c, 0x28, 0x22, 0x47, 0x88, 0x51, 0x31, 0xcb,
        0x7d, 0x30, 0x14, 0x68, 0x12, 0x00, 0x12, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x09, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x53, 0x00, 0x4f, 0x00, 0x46, 0x00, 0x54, 0x00,
        0x57, 0x00, 0x41, 0x00, 0x52, 0x00, 0x45, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3f, 0x00, 0x0f, 0x00,
};
static const uint8_t openkey_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x1e, 0xfc, 0x41, 0x81,
        0x27, 0x04, 0x44, 0x78, 0xa2, 0xb6, 0x37, 0xcf,
        0xba, 0xf3, 0x8d, 0x28, 0x00, 0x12, 0x00, 0x12,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x53, 0x00, 0x4f, 0x00, 0x46, 0x00, 0x54,
        0x00, 0x57, 0x00, 0x41, 0x00, 0x52, 0x00, 0x45,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0f, 0x00, 0x3f,
};
static const uint8_t openkey_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x50, 0x67, 0x08, 0xb8,
        0xa5, 0x55, 0x4b, 0x4b, 0xad, 0xba, 0x8e, 0xe3,
        0xb8, 0x62, 0x6a, 0x98, 0x00, 0x00, 0x00, 0x00,
        0x12, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x53, 0x00, 0x4f, 0x00, 0x46, 0x00, 0x54, 0x00,
        0x57, 0x00, 0x41, 0x00, 0x52, 0x00, 0x45, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3f, 0x00, 0x0f, 0x00,
};
static const uint8_t createkey_secattr_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x03, 0x10, 0x02, 0xd2,
        0x6e, 0x8a, 0x25, 0x42, 0x95, 0xaf, 0x4f, 0xdf,
        0xec, 0x32, 0xb7, 0x2d, 0x1e, 0x00, 0x1e, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x0f, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x6c, 0x00, 0x69, 0x00, 0x62, 0x00, 0x64, 0x00,
        0x63, 0x00, 0x65, 0x00, 0x72, 0x00, 0x70, 0x00,
        0x63, 0x00, 0x2d, 0x00, 0x74, 0x00, 0x65, 0x00,
        0x73, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x55, 0x70, 0x74, 0x72,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x0f, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x0c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t createkey_secattr_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x48, 0x08, 0x95, 0x96,
        0xc5, 0x28, 0x45, 0x01, 0x8b, 0x22, 0x58, 0x52,
        0x72, 0xa9, 0x6c, 0x58, 0x00, 0x1e, 0x00, 0x1e,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x0f,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        0x00, 0x6c, 0x00, 0x69, 0x00, 0x62, 0x00, 0x64,
        0x00, 0x63, 0x00, 0x65, 0x00, 0x72, 0x00, 0x70,
        0x00, 0x63, 0x00, 0x2d, 0x00, 0x74, 0x00, 0x65,
        0x00, 0x73, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x02, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x3f,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x0c,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t createkey_secattr_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x97, 0x27, 0x43, 0x18,
        0xb7, 0xd2, 0x25, 0x4a, 0xb6, 0x2c, 0x9f, 0x3a,
        0x87, 0x4d, 0xf7, 0x49, 0x00, 0x00, 0x00, 0x00,
        0x1e, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x6c, 0x00, 0x69, 0x00, 0x62, 0x00, 0x64, 0x00,
        0x63, 0x00, 0x65, 0x00, 0x72, 0x00, 0x70, 0x00,
        0x63, 0x00, 0x2d, 0x00, 0x74, 0x00, 0x65, 0x00,
        0x73, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3f, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t createkey_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x29, 0x7e, 0xc4, 0xab,
        0x86, 0x01, 0x3d, 0x41, 0xb9, 0xac, 0x95, 0x89,
        0xb5, 0xd6, 0xa5, 0x65, 0x08, 0x00, 0x08, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x73, 0x00, 0x75, 0x00, 0x62, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x55, 0x70, 0x74, 0x72,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x0f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x55, 0x70, 0x74, 0x72,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t createkey_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x7d, 0x42, 0xdd, 0xa0,
        0x49, 0xf0, 0x43, 0x38, 0xb7, 0x80, 0x41, 0x96,
        0xd3, 0x2a, 0xb8, 0xac, 0x00, 0x08, 0x00, 0x08,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x73, 0x00, 0x75, 0x00, 0x62, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x02, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x3f,
        0x00, 0x00, 0x00, 0x00, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t createkey_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x88, 0x4d, 0x86, 0x75,
        0xf1, 0xee, 0xe1, 0x45, 0xb5, 0x4b, 0xed, 0xdf,
        0x69, 0x24, 0x0f, 0xc8, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x73, 0x00, 0x75, 0x00, 0x62, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x3f, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t setvalue_REG_SZ_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x29, 0x7e, 0xc4, 0xab,
        0x86, 0x01, 0x3d, 0x41, 0xb9, 0xac, 0x95, 0x89,
        0xb5, 0xd6, 0xa5, 0x65, 0x06, 0x00, 0x06, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x73, 0x00, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x6c, 0x00, 0x69, 0x00, 0x62, 0x00, 0x64, 0x00,
        0x63, 0x00, 0x65, 0x00, 0x72, 0x00, 0x70, 0x00,
        0x63, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
};
static const uint8_t setvalue_REG_SZ_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x7d, 0x42, 0xdd, 0xa0,
        0x49, 0xf0, 0x43, 0x38, 0xb7, 0x80, 0x41, 0x96,
        0xd3, 0x2a, 0xb8, 0xac, 0x00, 0x06, 0x00, 0x06,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x73, 0x00, 0x7a, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14,
        0x6c, 0x00, 0x69, 0x00, 0x62, 0x00, 0x64, 0x00,
        0x63, 0x00, 0x65, 0x00, 0x72, 0x00, 0x70, 0x00,
        0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14,
};
static const uint8_t setvalue_REG_SZ_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x88, 0x4d, 0x86, 0x75,
        0xf1, 0xee, 0xe1, 0x45, 0xb5, 0x4b, 0xed, 0xdf,
        0x69, 0x24, 0x0f, 0xc8, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x73, 0x00, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x6c, 0x00, 0x69, 0x00, 0x62, 0x00, 0x64, 0x00,
        0x63, 0x00, 0x65, 0x00, 0x72, 0x00, 0x70, 0x00,
        0x63, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
};
static const uint8_t setvalue_REG_DWORD_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x29, 0x7e, 0xc4, 0xab,
        0x86, 0x01, 0x3d, 0x41, 0xb9, 0xac, 0x95, 0x89,
        0xb5, 0xd6, 0xa5, 0x65, 0x0c, 0x00, 0x0c, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x64, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72, 0x00,
        0x64, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12,
        0x04, 0x00, 0x00, 0x00,
};
static const uint8_t setvalue_REG_DWORD_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x7d, 0x42, 0xdd, 0xa0,
        0x49, 0xf0, 0x43, 0x38, 0xb7, 0x80, 0x41, 0x96,
        0xd3, 0x2a, 0xb8, 0xac, 0x00, 0x0c, 0x00, 0x0c,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
        0x00, 0x64, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72,
        0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x04, 0x78, 0x56, 0x34, 0x12,
        0x00, 0x00, 0x00, 0x04,
};
static const uint8_t setvalue_REG_DWORD_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x88, 0x4d, 0x86, 0x75,
        0xf1, 0xee, 0xe1, 0x45, 0xb5, 0x4b, 0xed, 0xdf,
        0x69, 0x24, 0x0f, 0xc8, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72, 0x00,
        0x64, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12, 0x04, 0x00, 0x00, 0x00,
};
static const uint8_t setvalue_REG_BINARY_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x29, 0x7e, 0xc4, 0xab,
        0x86, 0x01, 0x3d, 0x41, 0xb9, 0xac, 0x95, 0x89,
        0xb5, 0xd6, 0xa5, 0x65, 0x08, 0x00, 0x08, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x62, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0x00,
        0x07, 0x00, 0x00, 0x00,
};
static const uint8_t setvalue_REG_BINARY_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x7d, 0x42, 0xdd, 0xa0,
        0x49, 0xf0, 0x43, 0x38, 0xb7, 0x80, 0x41, 0x96,
        0xd3, 0x2a, 0xb8, 0xac, 0x00, 0x08, 0x00, 0x08,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x62, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x07,
        0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0x00,
        0x00, 0x00, 0x00, 0x07,
};
static const uint8_t setvalue_REG_BINARY_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x88, 0x4d, 0x86, 0x75,
        0xf1, 0xee, 0xe1, 0x45, 0xb5, 0x4b, 0xed, 0xdf,
        0x69, 0x24, 0x0f, 0xc8, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x62, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0x00,
        0x07, 0x00, 0x00, 0x00,
};
static const uint8_t queryinfokey_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x29, 0x7e, 0xc4, 0xab,
        0x86, 0x01, 0x3d, 0x41, 0xb9, 0xac, 0x95, 0x89,
        0xb5, 0xd6, 0xa5, 0x65, 0x00, 0x00, 0x80, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t queryinfokey_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x7d, 0x42, 0xdd, 0xa0,
        0x49, 0xf0, 0x43, 0x38, 0xb7, 0x80, 0x41, 0x96,
        0xd3, 0x2a, 0xb8, 0xac, 0x00, 0x00, 0x00, 0x80,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t queryinfokey_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x88, 0x4d, 0x86, 0x75,
        0xf1, 0xee, 0xe1, 0x45, 0xb5, 0x4b, 0xed, 0xdf,
        0x69, 0x24, 0x0f, 0xc8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumvalue_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x29, 0x7e, 0xc4, 0xab,
        0x86, 0x01, 0x3d, 0x41, 0xb9, 0xac, 0x95, 0x89,
        0xb5, 0xd6, 0xa5, 0x65, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x55, 0x70, 0x74, 0x72,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x55, 0x70, 0x74, 0x72,
        0x00, 0x00, 0x00, 0x00, 0x55, 0x70, 0x74, 0x72,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x55, 0x70, 0x74, 0x72,
        0x40, 0x00, 0x00, 0x00, 0x55, 0x70, 0x74, 0x72,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumvalue_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x7d, 0x42, 0xdd, 0xa0,
        0x49, 0xf0, 0x43, 0x38, 0xb7, 0x80, 0x41, 0x96,
        0xd3, 0x2a, 0xb8, 0xac, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x00, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x40, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumvalue_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x88, 0x4d, 0x86, 0x75,
        0xf1, 0xee, 0xe1, 0x45, 0xb5, 0x4b, 0xed, 0xdf,
        0x69, 0x24, 0x0f, 0xc8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x00,
};
static const uint8_t closekey_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0xc5, 0x31, 0xdb, 0x0f,
        0x4c, 0xb7, 0x2c, 0x44, 0xae, 0x52, 0xa9, 0xb0,
        0x30, 0x8d, 0x1b, 0x37,
};
static const uint8_t closekey_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x8f, 0x4d, 0xe7, 0x4f,
        0xd1, 0x90, 0x45, 0xcf, 0x81, 0x77, 0xef, 0x2c,
        0x37, 0xe0, 0xf6, 0xb4,
};
static const uint8_t closekey_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x7a, 0x29, 0x2f, 0xa0,
        0xff, 0xd5, 0x2e, 0x46, 0xba, 0x6d, 0xd9, 0xba,
        0x4a, 0xd0, 0x88, 0x45,
};
static const uint8_t enumkey_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x29, 0x7e, 0xc4, 0xab,
        0x86, 0x01, 0x3d, 0x41, 0xb9, 0xac, 0x95, 0x89,
        0xb5, 0xd6, 0xa5, 0x65, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x55, 0x70, 0x74, 0x72,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x55, 0x70, 0x74, 0x72,
        0x00, 0x00, 0x80, 0x00, 0x55, 0x70, 0x74, 0x72,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x55, 0x70, 0x74, 0x72,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumkey_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x7d, 0x42, 0xdd, 0xa0,
        0x49, 0xf0, 0x43, 0x38, 0xb7, 0x80, 0x41, 0x96,
        0xd3, 0x2a, 0xb8, 0xac, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x80, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t enumkey_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x88, 0x4d, 0x86, 0x75,
        0xf1, 0xee, 0xe1, 0x45, 0xb5, 0x4b, 0xed, 0xdf,
        0x69, 0x24, 0x0f, 0xc8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t deletevalue_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x29, 0x7e, 0xc4, 0xab,
        0x86, 0x01, 0x3d, 0x41, 0xb9, 0xac, 0x95, 0x89,
        0xb5, 0xd6, 0xa5, 0x65, 0x06, 0x00, 0x06, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x73, 0x00, 0x7a, 0x00, 0x00, 0x00,
};
static const uint8_t deletevalue_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x7d, 0x42, 0xdd, 0xa0,
        0x49, 0xf0, 0x43, 0x38, 0xb7, 0x80, 0x41, 0x96,
        0xd3, 0x2a, 0xb8, 0xac, 0x00, 0x06, 0x00, 0x06,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x73, 0x00, 0x7a, 0x00, 0x00,
};
static const uint8_t deletevalue_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x88, 0x4d, 0x86, 0x75,
        0xf1, 0xee, 0xe1, 0x45, 0xb5, 0x4b, 0xed, 0xdf,
        0x69, 0x24, 0x0f, 0xc8, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x73, 0x00, 0x7a, 0x00, 0x00, 0x00,
};
static const uint8_t deletekey_req_ndr32_le_ndr32_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x29, 0x7e, 0xc4, 0xab,
        0x86, 0x01, 0x3d, 0x41, 0xb9, 0xac, 0x95, 0x89,
        0xb5, 0xd6, 0xa5, 0x65, 0x08, 0x00, 0x08, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x73, 0x00, 0x75, 0x00, 0x62, 0x00, 0x00, 0x00,
};
static const uint8_t deletekey_req_ndr32_be_ndr32_be[] = {
        0x00, 0x00, 0x00, 0x00, 0x7d, 0x42, 0xdd, 0xa0,
        0x49, 0xf0, 0x43, 0x38, 0xb7, 0x80, 0x41, 0x96,
        0xd3, 0x2a, 0xb8, 0xac, 0x00, 0x08, 0x00, 0x08,
        0x72, 0x74, 0x70, 0x55, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x73, 0x00, 0x75, 0x00, 0x62, 0x00, 0x00,
};
static const uint8_t deletekey_req_ndr64_le_ndr64_le[] = {
        0x00, 0x00, 0x00, 0x00, 0x88, 0x4d, 0x86, 0x75,
        0xf1, 0xee, 0xe1, 0x45, 0xb5, 0x4b, 0xed, 0xdf,
        0x69, 0x24, 0x0f, 0xc8, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x55, 0x70, 0x74, 0x72, 0x72, 0x74, 0x70, 0x55,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x73, 0x00, 0x75, 0x00, 0x62, 0x00, 0x00, 0x00,
};

/* Known-good YAML */
static const char OpenLocalMachine_rep_ndr32_le_yaml[] =
        "OpenLocalMachine: Response\n"
        "  phKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 70dbe2ec-289c-4722-8851-31cb7d301468\n"
        "  Status: 0\n";

static const char OpenLocalMachine_rep_ndr64_le_yaml[] =
        "OpenLocalMachine: Response\n"
        "  phKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: b8086750-55a5-4b4b-adba-8ee3b8626a98\n"
        "  Status: 0\n";

static const char OpenClassesRoot_rep_ndr32_le_yaml[] =
        "OpenClassesRoot: Response\n"
        "  phKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: c328c997-91fc-40bd-8e14-0031b0152bac\n"
        "  Status: 0\n";

static const char OpenClassesRoot_rep_ndr64_le_yaml[] =
        "OpenClassesRoot: Response\n"
        "  phKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 9467fa71-5b60-479f-bfc5-1cde2c2f0756\n"
        "  Status: 0\n";

static const char OpenCurrentUser_rep_ndr32_le_yaml[] =
        "OpenCurrentUser: Response\n"
        "  phKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: ee720ad4-0fc5-453c-997a-02fdf56345a6\n"
        "  Status: 0\n";

static const char OpenCurrentUser_rep_ndr64_le_yaml[] =
        "OpenCurrentUser: Response\n"
        "  phKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: c8efee7e-d077-4635-abac-0edae35ce81b\n"
        "  Status: 0\n";

static const char OpenUsers_rep_ndr32_le_yaml[] =
        "OpenUsers: Response\n"
        "  phKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: e0b6a017-870d-4bdf-9254-566773b8df41\n"
        "  Status: 0\n";

static const char OpenUsers_rep_ndr64_le_yaml[] =
        "OpenUsers: Response\n"
        "  phKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: b57549ec-8778-4b7d-b3ff-657b8675f370\n"
        "  Status: 0\n";

static const char OpenCurrentConfig_rep_ndr32_le_yaml[] =
        "OpenCurrentConfig: Response\n"
        "  phKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: e2747096-95b4-4f1f-9e8a-06ad9f22a147\n"
        "  Status: 0\n";

static const char OpenCurrentConfig_rep_ndr64_le_yaml[] =
        "OpenCurrentConfig: Response\n"
        "  phKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 5d7e8c0e-0179-4bc8-8017-b98b715eb9df\n"
        "  Status: 0\n";

static const char openkey_rep_ndr32_le_yaml[] =
        "BaseRegOpenKey: Response\n"
        "  phkResult: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: d2021003-8a6e-4225-95af-4fdfec32b72d\n"
        "  Status: 0\n";

static const char openkey_rep_ndr64_le_yaml[] =
        "BaseRegOpenKey: Response\n"
        "  phkResult: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 18432797-d2b7-4a25-b62c-9f3a874df749\n"
        "  Status: 0\n";

static const char createkey_rep_ndr32_le_yaml[] =
        "BaseRegCreateKey: Response\n"
        "  phkResult: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: abc47e29-0186-413d-b9ac-9589b5d6a565\n"
        "  lpdwDisposition: REG_CREATED_NEW_KEY\n"
        "  Status: 0\n";

static const char createkey_rep_ndr64_le_yaml[] =
        "BaseRegCreateKey: Response\n"
        "  phkResult: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 75864d88-eef1-45e1-b54b-eddf69240fc8\n"
        "  lpdwDisposition: REG_CREATED_NEW_KEY\n"
        "  Status: 0\n";

static const char setvalue_rep_yaml[] =
        "BaseRegSetValue: Response\n"
        "  Status: 0\n";

static const char queryinfokey_rep_ndr32_le_yaml[] =
        "BaseRegQueryInfoKey: Response\n"
        "  lpClassOut: \n"
        "  lpcSubKeys: 0\n"
        "  lpcbMaxSubKeyLen: 0\n"
        "  lpcbMaxClassLen: 0\n"
        "  lpcValues: 3\n"
        "  lpcbMaxValueNameLen: 10\n"
        "  lpcbMaxValueLen: 20\n"
        "  lpcbSecurityDescriptor: 184\n"
        "  lpftLastWriteTime: \n"
        "    dwLowDateTime: 1472190391\n"
        "    dwHighDateTime: 31283867\n"
        "  Status: 0\n";

static const char queryinfokey_rep_ndr64_le_yaml[] =
        "BaseRegQueryInfoKey: Response\n"
        "  lpClassOut: \n"
        "  lpcSubKeys: 0\n"
        "  lpcbMaxSubKeyLen: 0\n"
        "  lpcbMaxClassLen: 0\n"
        "  lpcValues: 3\n"
        "  lpcbMaxValueNameLen: 10\n"
        "  lpcbMaxValueLen: 20\n"
        "  lpcbSecurityDescriptor: 184\n"
        "  lpftLastWriteTime: \n"
        "    dwLowDateTime: 1472658894\n"
        "    dwHighDateTime: 31283867\n"
        "  Status: 0\n";

static const char enumvalue_REG_SZ_rep_yaml[] =
        "BaseRegEnumValue: Response\n"
        "  lpValueNameOut: sz\n"
        "  lpType: REG_SZ\n"
        "  lpData: 6c00690062006400630065007200700063000000\n"
        "  lpcbData: 20\n"
        "  lpcbLen: 20\n"
        "  Status: 0\n";

static const char enumvalue_REG_DWORD_rep_yaml[] =
        "BaseRegEnumValue: Response\n"
        "  lpValueNameOut: dword\n"
        "  lpType: REG_DWORD\n"
        "  lpData: 78563412\n"
        "  lpcbData: 4\n"
        "  lpcbLen: 4\n"
        "  Status: 0\n";

static const char enumvalue_REG_BINARY_rep_yaml[] =
        "BaseRegEnumValue: Response\n"
        "  lpValueNameOut: bin\n"
        "  lpType: REG_BINARY\n"
        "  lpData: 00010203fffefd\n"
        "  lpcbData: 7\n"
        "  lpcbLen: 7\n"
        "  Status: 0\n";

static const char closekey_rep_yaml[] =
        "BaseRegCloseKey: Response\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 00000000-0000-0000-0000-000000000000\n"
        "  Status: 0\n";

static const char enumkey_rep_ndr32_le_yaml[] =
        "BaseRegEnumKey: Response\n"
        "  lpNameOut: sub\n"
        "  lplpClassOut: \n"
        "  lpftLastWriteTime: \n"
        "    dwLowDateTime: 1472190391\n"
        "    dwHighDateTime: 31283867\n"
        "  Status: 0\n";

static const char enumkey_rep_ndr64_le_yaml[] =
        "BaseRegEnumKey: Response\n"
        "  lpNameOut: sub\n"
        "  lplpClassOut: \n"
        "  lpftLastWriteTime: \n"
        "    dwLowDateTime: 1472658894\n"
        "    dwHighDateTime: 31283867\n"
        "  Status: 0\n";

static const char deletevalue_rep_yaml[] =
        "BaseRegDeleteValue: Response\n"
        "  Status: 0\n";

static const char deletekey_rep_yaml[] =
        "BaseRegDeleteKey: Response\n"
        "  Status: 0\n";

static const char OpenLocalMachine_req_yaml[] =
        "OpenLocalMachine: Request\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_READ | KEY_WRITE | KEY_ALL_ACCESS\n";

static const char OpenClassesRoot_req_yaml[] =
        "OpenClassesRoot: Request\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL | KEY_READ\n";

static const char OpenCurrentUser_req_yaml[] =
        "OpenCurrentUser: Request\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL | KEY_READ\n";

static const char OpenUsers_req_yaml[] =
        "OpenUsers: Request\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL | KEY_READ\n";

static const char OpenCurrentConfig_req_yaml[] =
        "OpenCurrentConfig: Request\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL | KEY_READ\n";

static const char openkey_req_ndr32_le_yaml[] =
        "BaseRegOpenKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 70dbe2ec-289c-4722-8851-31cb7d301468\n"
        "  lpSubKey: SOFTWARE\n"
        "  dwOptions: REG_OPTION_NON_VOLATILE\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_READ | KEY_WRITE | KEY_ALL_ACCESS\n";

static const char openkey_req_ndr32_be_yaml[] =
        "BaseRegOpenKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 1efc4181-2704-4478-a2b6-37cfbaf38d28\n"
        "  lpSubKey: SOFTWARE\n"
        "  dwOptions: REG_OPTION_NON_VOLATILE\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_READ | KEY_WRITE | KEY_ALL_ACCESS\n";

static const char openkey_req_ndr64_le_yaml[] =
        "BaseRegOpenKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: b8086750-55a5-4b4b-adba-8ee3b8626a98\n"
        "  lpSubKey: SOFTWARE\n"
        "  dwOptions: REG_OPTION_NON_VOLATILE\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_READ | KEY_WRITE | KEY_ALL_ACCESS\n";

static const char createkey_secattr_req_ndr32_le_yaml[] =
        "BaseRegCreateKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: d2021003-8a6e-4225-95af-4fdfec32b72d\n"
        "  lpSubKey: libdcerpc-test\n"
        "  lpClass: \n"
        "  dwOptions: REG_OPTION_NON_VOLATILE\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_READ | KEY_WRITE | KEY_ALL_ACCESS\n"
        "  lpSecurityAttributes: \n"
        "    nLength: 12\n"
        "    RpcSecurityDescriptor: \n"
        "      cbInSecurityDescriptor: 0\n"
        "      cbOutSecurityDescriptor: 0\n"
        "    bInheritHandle: 0\n"
        "  lpdwDisposition: 0\n";

static const char createkey_secattr_req_ndr32_be_yaml[] =
        "BaseRegCreateKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 48089596-c528-4501-8b22-585272a96c58\n"
        "  lpSubKey: libdcerpc-test\n"
        "  lpClass: \n"
        "  dwOptions: REG_OPTION_NON_VOLATILE\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_READ | KEY_WRITE | KEY_ALL_ACCESS\n"
        "  lpSecurityAttributes: \n"
        "    nLength: 12\n"
        "    RpcSecurityDescriptor: \n"
        "      cbInSecurityDescriptor: 0\n"
        "      cbOutSecurityDescriptor: 0\n"
        "    bInheritHandle: 0\n"
        "  lpdwDisposition: 0\n";

static const char createkey_secattr_req_ndr64_le_yaml[] =
        "BaseRegCreateKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 18432797-d2b7-4a25-b62c-9f3a874df749\n"
        "  lpSubKey: libdcerpc-test\n"
        "  lpClass: \n"
        "  dwOptions: REG_OPTION_NON_VOLATILE\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_READ | KEY_WRITE | KEY_ALL_ACCESS\n"
        "  lpSecurityAttributes: \n"
        "    nLength: 12\n"
        "    RpcSecurityDescriptor: \n"
        "      cbInSecurityDescriptor: 0\n"
        "      cbOutSecurityDescriptor: 0\n"
        "    bInheritHandle: 0\n"
        "  lpdwDisposition: 0\n";

static const char createkey_req_ndr32_le_yaml[] =
        "BaseRegCreateKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: abc47e29-0186-413d-b9ac-9589b5d6a565\n"
        "  lpSubKey: sub\n"
        "  lpClass: \n"
        "  dwOptions: REG_OPTION_NON_VOLATILE\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_READ | KEY_WRITE | KEY_ALL_ACCESS\n"
        "  lpdwDisposition: 0\n";

static const char createkey_req_ndr32_be_yaml[] =
        "BaseRegCreateKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 7d42dda0-49f0-4338-b780-4196d32ab8ac\n"
        "  lpSubKey: sub\n"
        "  lpClass: \n"
        "  dwOptions: REG_OPTION_NON_VOLATILE\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_READ | KEY_WRITE | KEY_ALL_ACCESS\n"
        "  lpdwDisposition: 0\n";

static const char createkey_req_ndr64_le_yaml[] =
        "BaseRegCreateKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 75864d88-eef1-45e1-b54b-eddf69240fc8\n"
        "  lpSubKey: sub\n"
        "  lpClass: \n"
        "  dwOptions: REG_OPTION_NON_VOLATILE\n"
        "  samDesired: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | KEY_READ | KEY_WRITE | KEY_ALL_ACCESS\n"
        "  lpdwDisposition: 0\n";

static const char setvalue_REG_SZ_req_ndr32_le_yaml[] =
        "BaseRegSetValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: abc47e29-0186-413d-b9ac-9589b5d6a565\n"
        "  lpValueName: sz\n"
        "  dwType: REG_SZ\n"
        "  lpData: 6c00690062006400630065007200700063000000\n"
        "  cbData: 20\n";

static const char setvalue_REG_SZ_req_ndr32_be_yaml[] =
        "BaseRegSetValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 7d42dda0-49f0-4338-b780-4196d32ab8ac\n"
        "  lpValueName: sz\n"
        "  dwType: REG_SZ\n"
        "  lpData: 6c00690062006400630065007200700063000000\n"
        "  cbData: 20\n";

static const char setvalue_REG_SZ_req_ndr64_le_yaml[] =
        "BaseRegSetValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 75864d88-eef1-45e1-b54b-eddf69240fc8\n"
        "  lpValueName: sz\n"
        "  dwType: REG_SZ\n"
        "  lpData: 6c00690062006400630065007200700063000000\n"
        "  cbData: 20\n";

static const char setvalue_REG_DWORD_req_ndr32_le_yaml[] =
        "BaseRegSetValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: abc47e29-0186-413d-b9ac-9589b5d6a565\n"
        "  lpValueName: dword\n"
        "  dwType: REG_DWORD\n"
        "  lpData: 78563412\n"
        "  cbData: 4\n";

static const char setvalue_REG_DWORD_req_ndr32_be_yaml[] =
        "BaseRegSetValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 7d42dda0-49f0-4338-b780-4196d32ab8ac\n"
        "  lpValueName: dword\n"
        "  dwType: REG_DWORD\n"
        "  lpData: 78563412\n"
        "  cbData: 4\n";

static const char setvalue_REG_DWORD_req_ndr64_le_yaml[] =
        "BaseRegSetValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 75864d88-eef1-45e1-b54b-eddf69240fc8\n"
        "  lpValueName: dword\n"
        "  dwType: REG_DWORD\n"
        "  lpData: 78563412\n"
        "  cbData: 4\n";

static const char setvalue_REG_BINARY_req_ndr32_le_yaml[] =
        "BaseRegSetValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: abc47e29-0186-413d-b9ac-9589b5d6a565\n"
        "  lpValueName: bin\n"
        "  dwType: REG_BINARY\n"
        "  lpData: 00010203fffefd\n"
        "  cbData: 7\n";

static const char setvalue_REG_BINARY_req_ndr32_be_yaml[] =
        "BaseRegSetValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 7d42dda0-49f0-4338-b780-4196d32ab8ac\n"
        "  lpValueName: bin\n"
        "  dwType: REG_BINARY\n"
        "  lpData: 00010203fffefd\n"
        "  cbData: 7\n";

static const char setvalue_REG_BINARY_req_ndr64_le_yaml[] =
        "BaseRegSetValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 75864d88-eef1-45e1-b54b-eddf69240fc8\n"
        "  lpValueName: bin\n"
        "  dwType: REG_BINARY\n"
        "  lpData: 00010203fffefd\n"
        "  cbData: 7\n";

static const char queryinfokey_req_ndr32_le_yaml[] =
        "BaseRegQueryInfoKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: abc47e29-0186-413d-b9ac-9589b5d6a565\n"
        "  lpClassIn: \n";

static const char queryinfokey_req_ndr32_be_yaml[] =
        "BaseRegQueryInfoKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 7d42dda0-49f0-4338-b780-4196d32ab8ac\n"
        "  lpClassIn: \n";

static const char queryinfokey_req_ndr64_le_yaml[] =
        "BaseRegQueryInfoKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 75864d88-eef1-45e1-b54b-eddf69240fc8\n"
        "  lpClassIn: \n";

static const char enumvalue_req_ndr32_le_yaml[] =
        "BaseRegEnumValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: abc47e29-0186-413d-b9ac-9589b5d6a565\n"
        "  dwIndex: 0\n"
        "  lpValueNameIn: \n"
        "  lpType: REG_NONE\n"
        "  lpData:\n"
        "  lpcbData: 64\n"
        "  lpcbLen: 0\n";

static const char enumvalue_req_ndr32_be_yaml[] =
        "BaseRegEnumValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 7d42dda0-49f0-4338-b780-4196d32ab8ac\n"
        "  dwIndex: 0\n"
        "  lpValueNameIn: \n"
        "  lpType: REG_NONE\n"
        "  lpData:\n"
        "  lpcbData: 64\n"
        "  lpcbLen: 0\n";

static const char enumvalue_req_ndr64_le_yaml[] =
        "BaseRegEnumValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 75864d88-eef1-45e1-b54b-eddf69240fc8\n"
        "  dwIndex: 0\n"
        "  lpValueNameIn: \n"
        "  lpType: REG_NONE\n"
        "  lpData:\n"
        "  lpcbData: 64\n"
        "  lpcbLen: 0\n";

static const char closekey_req_ndr32_le_yaml[] =
        "BaseRegCloseKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 0fdb31c5-b74c-442c-ae52-a9b0308d1b37\n";

static const char closekey_req_ndr32_be_yaml[] =
        "BaseRegCloseKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 8f4de74f-d190-45cf-8177-ef2c37e0f6b4\n";

static const char closekey_req_ndr64_le_yaml[] =
        "BaseRegCloseKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: a02f297a-d5ff-462e-ba6d-d9ba4ad08845\n";

static const char enumkey_req_ndr32_le_yaml[] =
        "BaseRegEnumKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: abc47e29-0186-413d-b9ac-9589b5d6a565\n"
        "  dwIndex: 0\n"
        "  lpNameIn: \n"
        "  lpClassIn: \n"
        "  lpftLastWriteTime: \n"
        "    dwLowDateTime: 0\n"
        "    dwHighDateTime: 0\n";

static const char enumkey_req_ndr32_be_yaml[] =
        "BaseRegEnumKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 7d42dda0-49f0-4338-b780-4196d32ab8ac\n"
        "  dwIndex: 0\n"
        "  lpNameIn: \n"
        "  lpClassIn: \n"
        "  lpftLastWriteTime: \n"
        "    dwLowDateTime: 0\n"
        "    dwHighDateTime: 0\n";

static const char enumkey_req_ndr64_le_yaml[] =
        "BaseRegEnumKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 75864d88-eef1-45e1-b54b-eddf69240fc8\n"
        "  dwIndex: 0\n"
        "  lpNameIn: \n"
        "  lpClassIn: \n"
        "  lpftLastWriteTime: \n"
        "    dwLowDateTime: 0\n"
        "    dwHighDateTime: 0\n";

static const char deletevalue_req_ndr32_le_yaml[] =
        "BaseRegDeleteValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: abc47e29-0186-413d-b9ac-9589b5d6a565\n"
        "  lpValueName: sz\n";

static const char deletevalue_req_ndr32_be_yaml[] =
        "BaseRegDeleteValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 7d42dda0-49f0-4338-b780-4196d32ab8ac\n"
        "  lpValueName: sz\n";

static const char deletevalue_req_ndr64_le_yaml[] =
        "BaseRegDeleteValue: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 75864d88-eef1-45e1-b54b-eddf69240fc8\n"
        "  lpValueName: sz\n";

static const char deletekey_req_ndr32_le_yaml[] =
        "BaseRegDeleteKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: abc47e29-0186-413d-b9ac-9589b5d6a565\n"
        "  lpSubKey: sub\n";

static const char deletekey_req_ndr32_be_yaml[] =
        "BaseRegDeleteKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 7d42dda0-49f0-4338-b780-4196d32ab8ac\n"
        "  lpSubKey: sub\n";

static const char deletekey_req_ndr64_le_yaml[] =
        "BaseRegDeleteKey: Request\n"
        "  hKey: \n"
        "    ContextHandleAttributes: 0\n"
        "    UUID: 75864d88-eef1-45e1-b54b-eddf69240fc8\n"
        "  lpSubKey: sub\n";

static const struct test_case test_cases[] = {
        { "OpenLocalMachine reply (NDR32 LE capture)", "OpenLocalMachine",
          winreg_OpenLocalMachine_rep_coder, sizeof(struct winreg_OpenLocalMachine_rep),
          &OpenLocalMachine_rep_ndr32_le_req, OpenLocalMachine_rep_ndr32_le_yaml,
          { { OpenLocalMachine_rep_ndr32_le_ndr32_le, sizeof(OpenLocalMachine_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "OpenLocalMachine reply (NDR64 LE capture)", "OpenLocalMachine",
          winreg_OpenLocalMachine_rep_coder, sizeof(struct winreg_OpenLocalMachine_rep),
          &OpenLocalMachine_rep_ndr64_le_req, OpenLocalMachine_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { OpenLocalMachine_rep_ndr64_le_ndr64_le, sizeof(OpenLocalMachine_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "OpenClassesRoot reply (NDR32 LE capture)", "OpenClassesRoot",
          winreg_OpenClassesRoot_rep_coder, sizeof(struct winreg_OpenClassesRoot_rep),
          &OpenClassesRoot_rep_ndr32_le_req, OpenClassesRoot_rep_ndr32_le_yaml,
          { { OpenClassesRoot_rep_ndr32_le_ndr32_le, sizeof(OpenClassesRoot_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "OpenClassesRoot reply (NDR64 LE capture)", "OpenClassesRoot",
          winreg_OpenClassesRoot_rep_coder, sizeof(struct winreg_OpenClassesRoot_rep),
          &OpenClassesRoot_rep_ndr64_le_req, OpenClassesRoot_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { OpenClassesRoot_rep_ndr64_le_ndr64_le, sizeof(OpenClassesRoot_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "OpenCurrentUser reply (NDR32 LE capture)", "OpenCurrentUser",
          winreg_OpenCurrentUser_rep_coder, sizeof(struct winreg_OpenCurrentUser_rep),
          &OpenCurrentUser_rep_ndr32_le_req, OpenCurrentUser_rep_ndr32_le_yaml,
          { { OpenCurrentUser_rep_ndr32_le_ndr32_le, sizeof(OpenCurrentUser_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "OpenCurrentUser reply (NDR64 LE capture)", "OpenCurrentUser",
          winreg_OpenCurrentUser_rep_coder, sizeof(struct winreg_OpenCurrentUser_rep),
          &OpenCurrentUser_rep_ndr64_le_req, OpenCurrentUser_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { OpenCurrentUser_rep_ndr64_le_ndr64_le, sizeof(OpenCurrentUser_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "OpenUsers reply (NDR32 LE capture)", "OpenUsers",
          winreg_OpenUsers_rep_coder, sizeof(struct winreg_OpenUsers_rep),
          &OpenUsers_rep_ndr32_le_req, OpenUsers_rep_ndr32_le_yaml,
          { { OpenUsers_rep_ndr32_le_ndr32_le, sizeof(OpenUsers_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "OpenUsers reply (NDR64 LE capture)", "OpenUsers",
          winreg_OpenUsers_rep_coder, sizeof(struct winreg_OpenUsers_rep),
          &OpenUsers_rep_ndr64_le_req, OpenUsers_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { OpenUsers_rep_ndr64_le_ndr64_le, sizeof(OpenUsers_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "OpenCurrentConfig reply (NDR32 LE capture)", "OpenCurrentConfig",
          winreg_OpenCurrentConfig_rep_coder, sizeof(struct winreg_OpenCurrentConfig_rep),
          &OpenCurrentConfig_rep_ndr32_le_req, OpenCurrentConfig_rep_ndr32_le_yaml,
          { { OpenCurrentConfig_rep_ndr32_le_ndr32_le, sizeof(OpenCurrentConfig_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "OpenCurrentConfig reply (NDR64 LE capture)", "OpenCurrentConfig",
          winreg_OpenCurrentConfig_rep_coder, sizeof(struct winreg_OpenCurrentConfig_rep),
          &OpenCurrentConfig_rep_ndr64_le_req, OpenCurrentConfig_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { OpenCurrentConfig_rep_ndr64_le_ndr64_le, sizeof(OpenCurrentConfig_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegOpenKey reply (NDR32 LE capture)", "BaseRegOpenKey",
          winreg_BaseRegOpenKey_rep_coder, sizeof(struct winreg_BaseRegOpenKey_rep),
          &openkey_rep_ndr32_le_req, openkey_rep_ndr32_le_yaml,
          { { openkey_rep_ndr32_le_ndr32_le, sizeof(openkey_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegOpenKey reply (NDR64 LE capture)", "BaseRegOpenKey",
          winreg_BaseRegOpenKey_rep_coder, sizeof(struct winreg_BaseRegOpenKey_rep),
          &openkey_rep_ndr64_le_req, openkey_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { openkey_rep_ndr64_le_ndr64_le, sizeof(openkey_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCreateKey reply (NDR32 LE capture)", "BaseRegCreateKey",
          winreg_BaseRegCreateKey_rep_coder, sizeof(struct winreg_BaseRegCreateKey_rep),
          &createkey_rep_ndr32_le_req, createkey_rep_ndr32_le_yaml,
          { { createkey_rep_ndr32_le_ndr32_le, sizeof(createkey_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCreateKey reply (NDR64 LE capture)", "BaseRegCreateKey",
          winreg_BaseRegCreateKey_rep_coder, sizeof(struct winreg_BaseRegCreateKey_rep),
          &createkey_rep_ndr64_le_req, createkey_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { createkey_rep_ndr64_le_ndr64_le, sizeof(createkey_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegSetValue reply", "BaseRegSetValue",
          winreg_BaseRegSetValue_rep_coder, sizeof(struct winreg_BaseRegSetValue_rep),
          &setvalue_rep_req, setvalue_rep_yaml,
          { { setvalue_rep_ndr32_le, sizeof(setvalue_rep_ndr32_le) },
            { NULL, 0 },
            { setvalue_rep_ndr64_le, sizeof(setvalue_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegQueryInfoKey reply (NDR32 LE capture)", "BaseRegQueryInfoKey",
          winreg_BaseRegQueryInfoKey_rep_coder, sizeof(struct winreg_BaseRegQueryInfoKey_rep),
          &queryinfokey_rep_ndr32_le_req, queryinfokey_rep_ndr32_le_yaml,
          { { queryinfokey_rep_ndr32_le_ndr32_le, sizeof(queryinfokey_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          (1u << NDR32_LE), "MaximumLength of out RPC_UNICODE_STRINGs is not kept, strings are char *" },
        { "BaseRegQueryInfoKey reply (NDR64 LE capture)", "BaseRegQueryInfoKey",
          winreg_BaseRegQueryInfoKey_rep_coder, sizeof(struct winreg_BaseRegQueryInfoKey_rep),
          &queryinfokey_rep_ndr64_le_req, queryinfokey_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { queryinfokey_rep_ndr64_le_ndr64_le, sizeof(queryinfokey_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          (1u << NDR64_LE), "MaximumLength of out RPC_UNICODE_STRINGs is not kept, strings are char *" },
        { "BaseRegEnumValue reply, REG_SZ", "BaseRegEnumValue",
          winreg_BaseRegEnumValue_rep_coder, sizeof(struct winreg_BaseRegEnumValue_rep),
          &enumvalue_REG_SZ_rep_req, enumvalue_REG_SZ_rep_yaml,
          { { enumvalue_REG_SZ_rep_ndr32_le, sizeof(enumvalue_REG_SZ_rep_ndr32_le) },
            { NULL, 0 },
            { enumvalue_REG_SZ_rep_ndr64_le, sizeof(enumvalue_REG_SZ_rep_ndr64_le) },
            { NULL, 0 } },
          (1u << NDR32_LE) | (1u << NDR64_LE), "MaximumLength of out RPC_UNICODE_STRINGs is not kept, strings are char *" },
        { "BaseRegEnumValue reply, REG_DWORD", "BaseRegEnumValue",
          winreg_BaseRegEnumValue_rep_coder, sizeof(struct winreg_BaseRegEnumValue_rep),
          &enumvalue_REG_DWORD_rep_req, enumvalue_REG_DWORD_rep_yaml,
          { { enumvalue_REG_DWORD_rep_ndr32_le, sizeof(enumvalue_REG_DWORD_rep_ndr32_le) },
            { NULL, 0 },
            { enumvalue_REG_DWORD_rep_ndr64_le, sizeof(enumvalue_REG_DWORD_rep_ndr64_le) },
            { NULL, 0 } },
          (1u << NDR32_LE) | (1u << NDR64_LE), "MaximumLength of out RPC_UNICODE_STRINGs is not kept, strings are char *" },
        { "BaseRegEnumValue reply, REG_BINARY", "BaseRegEnumValue",
          winreg_BaseRegEnumValue_rep_coder, sizeof(struct winreg_BaseRegEnumValue_rep),
          &enumvalue_REG_BINARY_rep_req, enumvalue_REG_BINARY_rep_yaml,
          { { enumvalue_REG_BINARY_rep_ndr32_le, sizeof(enumvalue_REG_BINARY_rep_ndr32_le) },
            { NULL, 0 },
            { enumvalue_REG_BINARY_rep_ndr64_le, sizeof(enumvalue_REG_BINARY_rep_ndr64_le) },
            { NULL, 0 } },
          (1u << NDR32_LE) | (1u << NDR64_LE), "MaximumLength of out RPC_UNICODE_STRINGs is not kept, strings are char *" },
        { "BaseRegCloseKey reply", "BaseRegCloseKey",
          winreg_BaseRegCloseKey_rep_coder, sizeof(struct winreg_BaseRegCloseKey_rep),
          &closekey_rep_req, closekey_rep_yaml,
          { { closekey_rep_ndr32_le, sizeof(closekey_rep_ndr32_le) },
            { NULL, 0 },
            { closekey_rep_ndr64_le, sizeof(closekey_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegEnumKey reply (NDR32 LE capture)", "BaseRegEnumKey",
          winreg_BaseRegEnumKey_rep_coder, sizeof(struct winreg_BaseRegEnumKey_rep),
          &enumkey_rep_ndr32_le_req, enumkey_rep_ndr32_le_yaml,
          { { enumkey_rep_ndr32_le_ndr32_le, sizeof(enumkey_rep_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          (1u << NDR32_LE), "MaximumLength of out RPC_UNICODE_STRINGs is not kept, strings are char *" },
        { "BaseRegEnumKey reply (NDR64 LE capture)", "BaseRegEnumKey",
          winreg_BaseRegEnumKey_rep_coder, sizeof(struct winreg_BaseRegEnumKey_rep),
          &enumkey_rep_ndr64_le_req, enumkey_rep_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { enumkey_rep_ndr64_le_ndr64_le, sizeof(enumkey_rep_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          (1u << NDR64_LE), "MaximumLength of out RPC_UNICODE_STRINGs is not kept, strings are char *" },
        { "BaseRegDeleteValue reply", "BaseRegDeleteValue",
          winreg_BaseRegDeleteValue_rep_coder, sizeof(struct winreg_BaseRegDeleteValue_rep),
          &deletevalue_rep_req, deletevalue_rep_yaml,
          { { deletevalue_rep_ndr32_le, sizeof(deletevalue_rep_ndr32_le) },
            { NULL, 0 },
            { deletevalue_rep_ndr64_le, sizeof(deletevalue_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegDeleteKey reply", "BaseRegDeleteKey",
          winreg_BaseRegDeleteKey_rep_coder, sizeof(struct winreg_BaseRegDeleteKey_rep),
          &deletekey_rep_req, deletekey_rep_yaml,
          { { deletekey_rep_ndr32_le, sizeof(deletekey_rep_ndr32_le) },
            { NULL, 0 },
            { deletekey_rep_ndr64_le, sizeof(deletekey_rep_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "OpenLocalMachine request", "OpenLocalMachine",
          winreg_OpenLocalMachine_req_coder, sizeof(struct winreg_OpenLocalMachine_req),
          NULL, OpenLocalMachine_req_yaml,
          { { OpenLocalMachine_req_ndr32_le, sizeof(OpenLocalMachine_req_ndr32_le) },
            { OpenLocalMachine_req_ndr32_be, sizeof(OpenLocalMachine_req_ndr32_be) },
            { OpenLocalMachine_req_ndr64_le, sizeof(OpenLocalMachine_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "OpenClassesRoot request", "OpenClassesRoot",
          winreg_OpenClassesRoot_req_coder, sizeof(struct winreg_OpenClassesRoot_req),
          NULL, OpenClassesRoot_req_yaml,
          { { OpenClassesRoot_req_ndr32_le, sizeof(OpenClassesRoot_req_ndr32_le) },
            { OpenClassesRoot_req_ndr32_be, sizeof(OpenClassesRoot_req_ndr32_be) },
            { OpenClassesRoot_req_ndr64_le, sizeof(OpenClassesRoot_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "OpenCurrentUser request", "OpenCurrentUser",
          winreg_OpenCurrentUser_req_coder, sizeof(struct winreg_OpenCurrentUser_req),
          NULL, OpenCurrentUser_req_yaml,
          { { OpenCurrentUser_req_ndr32_le, sizeof(OpenCurrentUser_req_ndr32_le) },
            { OpenCurrentUser_req_ndr32_be, sizeof(OpenCurrentUser_req_ndr32_be) },
            { OpenCurrentUser_req_ndr64_le, sizeof(OpenCurrentUser_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "OpenUsers request", "OpenUsers",
          winreg_OpenUsers_req_coder, sizeof(struct winreg_OpenUsers_req),
          NULL, OpenUsers_req_yaml,
          { { OpenUsers_req_ndr32_le, sizeof(OpenUsers_req_ndr32_le) },
            { OpenUsers_req_ndr32_be, sizeof(OpenUsers_req_ndr32_be) },
            { OpenUsers_req_ndr64_le, sizeof(OpenUsers_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "OpenCurrentConfig request", "OpenCurrentConfig",
          winreg_OpenCurrentConfig_req_coder, sizeof(struct winreg_OpenCurrentConfig_req),
          NULL, OpenCurrentConfig_req_yaml,
          { { OpenCurrentConfig_req_ndr32_le, sizeof(OpenCurrentConfig_req_ndr32_le) },
            { OpenCurrentConfig_req_ndr32_be, sizeof(OpenCurrentConfig_req_ndr32_be) },
            { OpenCurrentConfig_req_ndr64_le, sizeof(OpenCurrentConfig_req_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegOpenKey request (NDR32 LE capture)", "BaseRegOpenKey",
          winreg_BaseRegOpenKey_req_coder, sizeof(struct winreg_BaseRegOpenKey_req),
          NULL, openkey_req_ndr32_le_yaml,
          { { openkey_req_ndr32_le_ndr32_le, sizeof(openkey_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegOpenKey request (NDR32 BE capture)", "BaseRegOpenKey",
          winreg_BaseRegOpenKey_req_coder, sizeof(struct winreg_BaseRegOpenKey_req),
          NULL, openkey_req_ndr32_be_yaml,
          { { NULL, 0 },
            { openkey_req_ndr32_be_ndr32_be, sizeof(openkey_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegOpenKey request (NDR64 LE capture)", "BaseRegOpenKey",
          winreg_BaseRegOpenKey_req_coder, sizeof(struct winreg_BaseRegOpenKey_req),
          NULL, openkey_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { openkey_req_ndr64_le_ndr64_le, sizeof(openkey_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCreateKey request, RPC_SECURITY_ATTRIBUTES (NDR32 LE capture)", "BaseRegCreateKey",
          winreg_BaseRegCreateKey_req_coder, sizeof(struct winreg_BaseRegCreateKey_req),
          NULL, createkey_secattr_req_ndr32_le_yaml,
          { { createkey_secattr_req_ndr32_le_ndr32_le, sizeof(createkey_secattr_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCreateKey request, RPC_SECURITY_ATTRIBUTES (NDR32 BE capture)", "BaseRegCreateKey",
          winreg_BaseRegCreateKey_req_coder, sizeof(struct winreg_BaseRegCreateKey_req),
          NULL, createkey_secattr_req_ndr32_be_yaml,
          { { NULL, 0 },
            { createkey_secattr_req_ndr32_be_ndr32_be, sizeof(createkey_secattr_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCreateKey request, RPC_SECURITY_ATTRIBUTES (NDR64 LE capture)", "BaseRegCreateKey",
          winreg_BaseRegCreateKey_req_coder, sizeof(struct winreg_BaseRegCreateKey_req),
          NULL, createkey_secattr_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { createkey_secattr_req_ndr64_le_ndr64_le, sizeof(createkey_secattr_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCreateKey request (NDR32 LE capture)", "BaseRegCreateKey",
          winreg_BaseRegCreateKey_req_coder, sizeof(struct winreg_BaseRegCreateKey_req),
          NULL, createkey_req_ndr32_le_yaml,
          { { createkey_req_ndr32_le_ndr32_le, sizeof(createkey_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCreateKey request (NDR32 BE capture)", "BaseRegCreateKey",
          winreg_BaseRegCreateKey_req_coder, sizeof(struct winreg_BaseRegCreateKey_req),
          NULL, createkey_req_ndr32_be_yaml,
          { { NULL, 0 },
            { createkey_req_ndr32_be_ndr32_be, sizeof(createkey_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCreateKey request (NDR64 LE capture)", "BaseRegCreateKey",
          winreg_BaseRegCreateKey_req_coder, sizeof(struct winreg_BaseRegCreateKey_req),
          NULL, createkey_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { createkey_req_ndr64_le_ndr64_le, sizeof(createkey_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegSetValue request, REG_SZ (NDR32 LE capture)", "BaseRegSetValue",
          winreg_BaseRegSetValue_req_coder, sizeof(struct winreg_BaseRegSetValue_req),
          NULL, setvalue_REG_SZ_req_ndr32_le_yaml,
          { { setvalue_REG_SZ_req_ndr32_le_ndr32_le, sizeof(setvalue_REG_SZ_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegSetValue request, REG_SZ (NDR32 BE capture)", "BaseRegSetValue",
          winreg_BaseRegSetValue_req_coder, sizeof(struct winreg_BaseRegSetValue_req),
          NULL, setvalue_REG_SZ_req_ndr32_be_yaml,
          { { NULL, 0 },
            { setvalue_REG_SZ_req_ndr32_be_ndr32_be, sizeof(setvalue_REG_SZ_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegSetValue request, REG_SZ (NDR64 LE capture)", "BaseRegSetValue",
          winreg_BaseRegSetValue_req_coder, sizeof(struct winreg_BaseRegSetValue_req),
          NULL, setvalue_REG_SZ_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { setvalue_REG_SZ_req_ndr64_le_ndr64_le, sizeof(setvalue_REG_SZ_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegSetValue request, REG_DWORD (NDR32 LE capture)", "BaseRegSetValue",
          winreg_BaseRegSetValue_req_coder, sizeof(struct winreg_BaseRegSetValue_req),
          NULL, setvalue_REG_DWORD_req_ndr32_le_yaml,
          { { setvalue_REG_DWORD_req_ndr32_le_ndr32_le, sizeof(setvalue_REG_DWORD_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegSetValue request, REG_DWORD (NDR32 BE capture)", "BaseRegSetValue",
          winreg_BaseRegSetValue_req_coder, sizeof(struct winreg_BaseRegSetValue_req),
          NULL, setvalue_REG_DWORD_req_ndr32_be_yaml,
          { { NULL, 0 },
            { setvalue_REG_DWORD_req_ndr32_be_ndr32_be, sizeof(setvalue_REG_DWORD_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegSetValue request, REG_DWORD (NDR64 LE capture)", "BaseRegSetValue",
          winreg_BaseRegSetValue_req_coder, sizeof(struct winreg_BaseRegSetValue_req),
          NULL, setvalue_REG_DWORD_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { setvalue_REG_DWORD_req_ndr64_le_ndr64_le, sizeof(setvalue_REG_DWORD_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegSetValue request, REG_BINARY (NDR32 LE capture)", "BaseRegSetValue",
          winreg_BaseRegSetValue_req_coder, sizeof(struct winreg_BaseRegSetValue_req),
          NULL, setvalue_REG_BINARY_req_ndr32_le_yaml,
          { { setvalue_REG_BINARY_req_ndr32_le_ndr32_le, sizeof(setvalue_REG_BINARY_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegSetValue request, REG_BINARY (NDR32 BE capture)", "BaseRegSetValue",
          winreg_BaseRegSetValue_req_coder, sizeof(struct winreg_BaseRegSetValue_req),
          NULL, setvalue_REG_BINARY_req_ndr32_be_yaml,
          { { NULL, 0 },
            { setvalue_REG_BINARY_req_ndr32_be_ndr32_be, sizeof(setvalue_REG_BINARY_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegSetValue request, REG_BINARY (NDR64 LE capture)", "BaseRegSetValue",
          winreg_BaseRegSetValue_req_coder, sizeof(struct winreg_BaseRegSetValue_req),
          NULL, setvalue_REG_BINARY_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { setvalue_REG_BINARY_req_ndr64_le_ndr64_le, sizeof(setvalue_REG_BINARY_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegQueryInfoKey request (NDR32 LE capture)", "BaseRegQueryInfoKey",
          winreg_BaseRegQueryInfoKey_req_coder, sizeof(struct winreg_BaseRegQueryInfoKey_req),
          NULL, queryinfokey_req_ndr32_le_yaml,
          { { queryinfokey_req_ndr32_le_ndr32_le, sizeof(queryinfokey_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegQueryInfoKey request (NDR32 BE capture)", "BaseRegQueryInfoKey",
          winreg_BaseRegQueryInfoKey_req_coder, sizeof(struct winreg_BaseRegQueryInfoKey_req),
          NULL, queryinfokey_req_ndr32_be_yaml,
          { { NULL, 0 },
            { queryinfokey_req_ndr32_be_ndr32_be, sizeof(queryinfokey_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegQueryInfoKey request (NDR64 LE capture)", "BaseRegQueryInfoKey",
          winreg_BaseRegQueryInfoKey_req_coder, sizeof(struct winreg_BaseRegQueryInfoKey_req),
          NULL, queryinfokey_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { queryinfokey_req_ndr64_le_ndr64_le, sizeof(queryinfokey_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegEnumValue request (NDR32 LE capture)", "BaseRegEnumValue",
          winreg_BaseRegEnumValue_req_coder, sizeof(struct winreg_BaseRegEnumValue_req),
          NULL, enumvalue_req_ndr32_le_yaml,
          { { enumvalue_req_ndr32_le_ndr32_le, sizeof(enumvalue_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegEnumValue request (NDR32 BE capture)", "BaseRegEnumValue",
          winreg_BaseRegEnumValue_req_coder, sizeof(struct winreg_BaseRegEnumValue_req),
          NULL, enumvalue_req_ndr32_be_yaml,
          { { NULL, 0 },
            { enumvalue_req_ndr32_be_ndr32_be, sizeof(enumvalue_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegEnumValue request (NDR64 LE capture)", "BaseRegEnumValue",
          winreg_BaseRegEnumValue_req_coder, sizeof(struct winreg_BaseRegEnumValue_req),
          NULL, enumvalue_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { enumvalue_req_ndr64_le_ndr64_le, sizeof(enumvalue_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCloseKey request (NDR32 LE capture)", "BaseRegCloseKey",
          winreg_BaseRegCloseKey_req_coder, sizeof(struct winreg_BaseRegCloseKey_req),
          NULL, closekey_req_ndr32_le_yaml,
          { { closekey_req_ndr32_le_ndr32_le, sizeof(closekey_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCloseKey request (NDR32 BE capture)", "BaseRegCloseKey",
          winreg_BaseRegCloseKey_req_coder, sizeof(struct winreg_BaseRegCloseKey_req),
          NULL, closekey_req_ndr32_be_yaml,
          { { NULL, 0 },
            { closekey_req_ndr32_be_ndr32_be, sizeof(closekey_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegCloseKey request (NDR64 LE capture)", "BaseRegCloseKey",
          winreg_BaseRegCloseKey_req_coder, sizeof(struct winreg_BaseRegCloseKey_req),
          NULL, closekey_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { closekey_req_ndr64_le_ndr64_le, sizeof(closekey_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegEnumKey request (NDR32 LE capture)", "BaseRegEnumKey",
          winreg_BaseRegEnumKey_req_coder, sizeof(struct winreg_BaseRegEnumKey_req),
          NULL, enumkey_req_ndr32_le_yaml,
          { { enumkey_req_ndr32_le_ndr32_le, sizeof(enumkey_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegEnumKey request (NDR32 BE capture)", "BaseRegEnumKey",
          winreg_BaseRegEnumKey_req_coder, sizeof(struct winreg_BaseRegEnumKey_req),
          NULL, enumkey_req_ndr32_be_yaml,
          { { NULL, 0 },
            { enumkey_req_ndr32_be_ndr32_be, sizeof(enumkey_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegEnumKey request (NDR64 LE capture)", "BaseRegEnumKey",
          winreg_BaseRegEnumKey_req_coder, sizeof(struct winreg_BaseRegEnumKey_req),
          NULL, enumkey_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { enumkey_req_ndr64_le_ndr64_le, sizeof(enumkey_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegDeleteValue request (NDR32 LE capture)", "BaseRegDeleteValue",
          winreg_BaseRegDeleteValue_req_coder, sizeof(struct winreg_BaseRegDeleteValue_req),
          NULL, deletevalue_req_ndr32_le_yaml,
          { { deletevalue_req_ndr32_le_ndr32_le, sizeof(deletevalue_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegDeleteValue request (NDR32 BE capture)", "BaseRegDeleteValue",
          winreg_BaseRegDeleteValue_req_coder, sizeof(struct winreg_BaseRegDeleteValue_req),
          NULL, deletevalue_req_ndr32_be_yaml,
          { { NULL, 0 },
            { deletevalue_req_ndr32_be_ndr32_be, sizeof(deletevalue_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegDeleteValue request (NDR64 LE capture)", "BaseRegDeleteValue",
          winreg_BaseRegDeleteValue_req_coder, sizeof(struct winreg_BaseRegDeleteValue_req),
          NULL, deletevalue_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { deletevalue_req_ndr64_le_ndr64_le, sizeof(deletevalue_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegDeleteKey request (NDR32 LE capture)", "BaseRegDeleteKey",
          winreg_BaseRegDeleteKey_req_coder, sizeof(struct winreg_BaseRegDeleteKey_req),
          NULL, deletekey_req_ndr32_le_yaml,
          { { deletekey_req_ndr32_le_ndr32_le, sizeof(deletekey_req_ndr32_le_ndr32_le) },
            { NULL, 0 },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegDeleteKey request (NDR32 BE capture)", "BaseRegDeleteKey",
          winreg_BaseRegDeleteKey_req_coder, sizeof(struct winreg_BaseRegDeleteKey_req),
          NULL, deletekey_req_ndr32_be_yaml,
          { { NULL, 0 },
            { deletekey_req_ndr32_be_ndr32_be, sizeof(deletekey_req_ndr32_be_ndr32_be) },
            { NULL, 0 },
            { NULL, 0 } },
          0, NULL },
        { "BaseRegDeleteKey request (NDR64 LE capture)", "BaseRegDeleteKey",
          winreg_BaseRegDeleteKey_req_coder, sizeof(struct winreg_BaseRegDeleteKey_req),
          NULL, deletekey_req_ndr64_le_yaml,
          { { NULL, 0 },
            { NULL, 0 },
            { deletekey_req_ndr64_le_ndr64_le, sizeof(deletekey_req_ndr64_le_ndr64_le) },
            { NULL, 0 } },
          0, NULL },
};

int main(void)
{
        return run_coder_tests(test_cases,
                               sizeof(test_cases) / sizeof(test_cases[0]));
}
