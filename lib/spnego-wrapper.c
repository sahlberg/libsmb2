/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2024 by Brian Dodge <bdodge09@gmail.com>

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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef STDC_HEADERS
#include <stddef.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_UNISTD_H
#include <sys/unistd.h>
#endif

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"
#include "krb5-wrapper.h"
#include "asn1-ber.h"

#include "spnego-wrapper.h"

int
smb2_create_negotiate_reply_blob(struct smb2_context *smb2, void **neg_init_token)
{
        struct asn1ber_context asn_encoder;
        uint8_t *neg_init;
        int alloc_len;
        int pos[6];
        
        alloc_len = 5 * sizeof spnego_mech_ntlmssp;
        neg_init = calloc(1, alloc_len);
        if (neg_init == NULL) {
                smb2_set_error(smb2, "Failed to allocate negotiate token init");
                return 0;
        }

        memset(&asn_encoder, 0, sizeof(asn_encoder));
        asn_encoder.dst = neg_init;
        asn_encoder.dst_size = alloc_len;
        asn_encoder.dst_head = 0;
        
        asn1ber_ber_from_typecode(&asn_encoder, asnCONSTRUCTOR | asnAPPLICATION);
        /* save location of total length */
        asn1ber_save_out_state(&asn_encoder, &pos[0]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);
        
        /* insert top level oid */
        #if 0 /* precompiled oids are already BER encoded */
        asn1ber_ber_from_oid(&asn_encoder, &gss_mech_spnego);
        #else
        asn1ber_ber_from_bytes(&asn_encoder, asnOBJECT_ID,
                               (uint8_t*)gss_mech_spnego.elements, gss_mech_spnego.length);
        #endif        
        
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT(0));
        /* save location of length of sub mechanisms */
        asn1ber_save_out_state(&asn_encoder, &pos[1]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);
                
        asn1ber_ber_from_typecode(&asn_encoder, asnSTRUCT);
        /* save location of length of mechanism struct */
        asn1ber_save_out_state(&asn_encoder, &pos[2]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);
        
        /* constructed */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT(0));        
        /* save location of length of mechanism sequence */
        asn1ber_save_out_state(&asn_encoder, &pos[3]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);
        
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_SEQUENCE(0));
        /* save location of length of mechanism struct */
        asn1ber_save_out_state(&asn_encoder, &pos[4]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);

        /* for each negotiable mechanism */
        
        /* insert mechanism oids */
        #if 0 /* precompiled oids are already BER encoded */
        asn1ber_ber_from_oid(&asn_encoder, &spnego_mech_ntlmssp);
        #else
        asn1ber_ber_from_bytes(&asn_encoder, asnOBJECT_ID,
                       (uint8_t*)spnego_mech_ntlmssp.elements, spnego_mech_ntlmssp.length);
        #endif
#ifdef HAVE_LIBKRB5
        /* insert mechanism oids */
        #if 0 /* pre-compiled oids are already ber encoded */
        asn1ber_ber_from_oid(&asn_encoder, &spnego_mech_krb5);
        #else
        asn1ber_ber_from_bytes(&asn_encoder, asnOBJECT_ID,
                       (uint8_t*)spnego_mech_krb5.elements, spnego_mech_krb5.length);
        #endif
#endif
        asn1ber_annotate_length(&asn_encoder, pos[4], 5);
        asn1ber_annotate_length(&asn_encoder, pos[3], 5);
        asn1ber_annotate_length(&asn_encoder, pos[2], 5);
        asn1ber_annotate_length(&asn_encoder, pos[1], 5);
        asn1ber_annotate_length(&asn_encoder, pos[0], 5);

        *neg_init_token = neg_init;
        return asn_encoder.dst_head;
}

int
smb2_wrap_ntlmssp_challenge(struct smb2_context *smb2, const uint8_t *ntlmssp_token,
               const int token_len, void **neg_init_token)
{
        struct asn1ber_context asn_encoder;
        uint8_t *neg_init;
        int alloc_len;
        int pos[6];
        uint8_t oneone[] = { 1 };
        
        alloc_len = 64 + 2 * token_len;
        neg_init = calloc(1, alloc_len);
        if (neg_init == NULL) {
                smb2_set_error(smb2, "Failed to allocate spnego wrapper");
                return 0;
        }

        memset(&asn_encoder, 0, sizeof(asn_encoder));
        asn_encoder.dst = neg_init;
        asn_encoder.dst_size = alloc_len;
        asn_encoder.dst_head = 0;
        
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT(1));               /* A1 81 XX */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT_SIMPLE(1));
        /* save location of total length */
        asn1ber_save_out_state(&asn_encoder, &pos[0]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);

        asn1ber_ber_from_typecode(&asn_encoder, ASN1_SEQUENCE(0));              /* 30 81 YY */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT_SIMPLE(1));
        /* save location of sub length */
        asn1ber_save_out_state(&asn_encoder, &pos[1]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);
        
        /* negTokenTarg */
        /*   negResult: accept-incomplete */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT(0));               /* A0 ZZ */
        /* save location of length */
        asn1ber_save_out_state(&asn_encoder, &pos[2]);
        asn1ber_ber_reserve_length(&asn_encoder, 1);
        
        asn1ber_ber_from_bytes(&asn_encoder, asnENUMERATED, oneone, sizeof(oneone));      /* 0A 01 01 */
        asn1ber_annotate_length(&asn_encoder, pos[2], 1);

        /*   supportedMech */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT(1));               /* A1 ZZ */
        /* save location of total length */
        asn1ber_save_out_state(&asn_encoder, &pos[2]);
        asn1ber_ber_reserve_length(&asn_encoder, 1);
        
        #if 0 /* precompiled oids are already BER encoded */
        asn1ber_ber_from_oid(&asn_encoder, &spnego_mech_ntlmssp);
        #else
        asn1ber_ber_from_bytes(&asn_encoder, asnOBJECT_ID,
                       (uint8_t*)spnego_mech_ntlmssp.elements, spnego_mech_ntlmssp.length);
        #endif
        asn1ber_annotate_length(&asn_encoder, pos[2], 1);
        
        /*   ntlm service provider */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT(2));               /* A2 81 ZZ */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT_SIMPLE(1));
        /* save location of total length */
        asn1ber_save_out_state(&asn_encoder, &pos[2]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);

        asn1ber_ber_from_typecode(&asn_encoder, asnOCTET_STRING);               /* 04 81 zz */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT_SIMPLE(1));
        /* save location of total length */
        asn1ber_save_out_state(&asn_encoder, &pos[3]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);

        memcpy(asn_encoder.dst + asn_encoder.dst_head, ntlmssp_token, token_len);
        asn_encoder.dst_head += token_len;

        asn1ber_annotate_length(&asn_encoder, pos[3], 5);
        asn1ber_annotate_length(&asn_encoder, pos[2], 5);        
        asn1ber_annotate_length(&asn_encoder, pos[1], 5);
        asn1ber_annotate_length(&asn_encoder, pos[0], 5);

        *neg_init_token = neg_init;
        return asn_encoder.dst_head;
}

int
smb2_wrap_ntlmssp_result(struct smb2_context *smb2, const int authorized_ok, void **neg_init_token)
{
        struct asn1ber_context asn_encoder;
        uint8_t *neg_init;
        int alloc_len;
        int pos[6];
        uint8_t result_code = 0;
        
        alloc_len = 128;
        neg_init = calloc(1, alloc_len);
        if (neg_init == NULL) {
                smb2_set_error(smb2, "Failed to allocate spnego wrapper");
                return 0;
        }
        
        if (authorized_ok) {
                result_code = 0;
        }

        memset(&asn_encoder, 0, sizeof(asn_encoder));
        asn_encoder.dst = neg_init;
        asn_encoder.dst_size = alloc_len;
        asn_encoder.dst_head = 0;
        
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT(1));               /* A1 81 XX */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT_SIMPLE(1));
        /* save location of total length */
        asn1ber_save_out_state(&asn_encoder, &pos[0]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);

        asn1ber_ber_from_typecode(&asn_encoder, ASN1_SEQUENCE(0));              /* 30 81 YY */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT_SIMPLE(1));
        /* save location of sub length */
        asn1ber_save_out_state(&asn_encoder, &pos[1]);
        asn1ber_ber_reserve_length(&asn_encoder, 5);
        
        /* negTokenTarg */
        /*   negResult: accept-incomplete */
        asn1ber_ber_from_typecode(&asn_encoder, ASN1_CONTEXT(0));               /* A0 ZZ */
        /* save location of length */
        asn1ber_save_out_state(&asn_encoder, &pos[2]);
        asn1ber_ber_reserve_length(&asn_encoder, 1);
        
        asn1ber_ber_from_bytes(&asn_encoder, asnENUMERATED, &result_code, 1);      /* 0A 01 Value */
        asn1ber_annotate_length(&asn_encoder, pos[2], 1);

        asn1ber_annotate_length(&asn_encoder, pos[1], 5);
        asn1ber_annotate_length(&asn_encoder, pos[0], 5);

        *neg_init_token = neg_init;
        return asn_encoder.dst_head;
}

