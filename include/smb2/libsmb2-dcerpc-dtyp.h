/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _LIBSMB2_DCERPC_DTYP_H_
#define _LIBSMB2_DCERPC_DTYP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <smb2/libsmb2-dcerpc.h>

/*
 * MS-DTYP 2.4.2 SID / RPC_SID
 *
 * typedef struct _RPC_SID {
 *     unsigned char Revision;
 *     unsigned char SubAuthorityCount;
 *     byte IdentifierAuthority[6];
 *     [size_is(SubAuthorityCount)] unsigned long SubAuthority[];
 * } RPC_SID, *PRPC_SID, *PSID;
 */
extern unsigned char NT_SID_AUTHORITY[6];

#define MAXSUBAUTH 10
typedef struct RPC_SID {
        uint8_t Revision;
        uint8_t SubAuthorityCount;
        uint8_t IdentifierAuthority[6];
        uint32_t SubAuthority[MAXSUBAUTH];
} RPC_SID, *PRPC_SID;

/*
 * MS-DTYP 2.4.3 ACCESS_MASK
 *
 * typedef DWORD ACCESS_MASK;
 */
typedef uint32_t ACCESS_MASK;

/* Standard / generic rights (MS-DTYP 2.4.3) */
#define DELETE                          0x00010000
#define READ_CONTROL                    0x00020000
#define WRITE_DAC                       0x00040000
#define WRITE_DACL                      WRITE_DAC
#define WRITE_OWNER                     0x00080000
#define SYNCHRONIZE                     0x00100000
#define ACCESS_SYSTEM_SECURITY          0x01000000
#define MAXIMUM_ALLOWED                 0x02000000
#define GENERIC_ALL                     0x10000000
#define GENERIC_EXECUTE                 0x20000000
#define GENERIC_WRITE                   0x40000000
#define GENERIC_READ                    0x80000000

/*
 * MS-DTYP 2.4.4.1 ACE_HEADER
 *
 * typedef struct _ACE_HEADER {
 *     UCHAR AceType;
 *     UCHAR AceFlags;
 *     USHORT AceSize;
 * } ACE_HEADER, *PACE_HEADER;
 */

/* AceType values (MS-DTYP 2.4.4.1) */
#define ACCESS_ALLOWED_ACE_TYPE                 0x00
#define ACCESS_DENIED_ACE_TYPE                  0x01
#define SYSTEM_AUDIT_ACE_TYPE                   0x02
#define SYSTEM_ALARM_ACE_TYPE                   0x03
#define ACCESS_ALLOWED_COMPOUND_ACE_TYPE        0x04
#define ACCESS_ALLOWED_OBJECT_ACE_TYPE          0x05
#define ACCESS_DENIED_OBJECT_ACE_TYPE           0x06
#define SYSTEM_AUDIT_OBJECT_ACE_TYPE            0x07
#define SYSTEM_ALARM_OBJECT_ACE_TYPE            0x08
#define ACCESS_ALLOWED_CALLBACK_ACE_TYPE        0x09
#define ACCESS_DENIED_CALLBACK_ACE_TYPE         0x0A
#define ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE 0x0B
#define ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  0x0C
#define SYSTEM_AUDIT_CALLBACK_ACE_TYPE          0x0D
#define SYSTEM_ALARM_CALLBACK_ACE_TYPE          0x0E
#define SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   0x0F
#define SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   0x10
#define SYSTEM_MANDATORY_LABEL_ACE_TYPE         0x11
#define SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      0x12
#define SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        0x13

/* AceFlags values (MS-DTYP 2.4.4.1) */
#define OBJECT_INHERIT_ACE              0x01
#define CONTAINER_INHERIT_ACE           0x02
#define NO_PROPAGATE_INHERIT_ACE        0x04
#define INHERIT_ONLY_ACE                0x08
#define INHERITED_ACE                   0x10
#define SUCCESSFUL_ACCESS_ACE_FLAG      0x40
#define FAILED_ACCESS_ACE_FLAG          0x80

typedef struct _ACE_HEADER {
        uint8_t AceType;
        uint8_t AceFlags;
        /*
         * Wire-only: present in NDR, omitted from YAML/JSON. Parent ACE
         * coders set this from the body (e.g. Sid length) as needed.
         */
        uint16_t AceSize;
} ACE_HEADER, *PACE_HEADER;

int dcerpc_ACE_HEADER_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct smb2_iovec *iov, int *offset,
                            void *ptr);

/*
 * MS-DTYP 2.4.4.2 ACCESS_ALLOWED_ACE / 2.4.4.4 ACCESS_DENIED_ACE
 *
 * Packet form (self-relative security descriptors):
 *   Header (ACE_HEADER)
 *   Mask   (ACCESS_MASK)
 *   Sid    (packet SID, length a multiple of 4)
 *
 * Both types share the same wire layout; only AceType differs
 * (ACCESS_ALLOWED_ACE_TYPE vs ACCESS_DENIED_ACE_TYPE).
 *
 * C representation uses a full RPC_SID for Sid. On NDR the Sid is written
 * in packet form (no RPC size_is prefix); YAML/JSON use the S-R-I-S... string.
 * AceSize is wire-only (omitted from YAML/JSON; derived from Sid).
 */
typedef struct _ACCESS_ALLOWED_ACE {
        ACE_HEADER Header;
        ACCESS_MASK Mask;
        RPC_SID Sid;
} ACCESS_ALLOWED_ACE, *PACCESS_ALLOWED_ACE;

typedef struct _ACCESS_DENIED_ACE {
        ACE_HEADER Header;
        ACCESS_MASK Mask;
        RPC_SID Sid;
} ACCESS_DENIED_ACE, *PACCESS_DENIED_ACE;

int dcerpc_ACCESS_ALLOWED_ACE_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct smb2_iovec *iov, int *offset,
                                    void *ptr);
int dcerpc_ACCESS_DENIED_ACE_coder(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct smb2_iovec *iov, int *offset,
                                   void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_DCERPC_DTYP_H_ */
