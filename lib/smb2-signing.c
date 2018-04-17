/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2018 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#ifdef HAVE_OPENSSL_LIBS

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

#include "smb2-signing.h"

#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>

#define OPENSSL_VER_101	0x1000109fL
#define OPENSSL_VER_102	0x10002100L

#define MIN(a,b) (((a)<(b))?(a):(b))

#define	SIGNING_KEY_SIZE	16


int
smb2_pdu_add_signature(struct smb2_context *smb2,
                       struct smb2_pdu *pdu
                       )
{
        struct smb2_header *hdr = NULL;
        uint8_t signature[16];
        uint8_t key[SIGNING_KEY_SIZE];
        int key_len = 0;
        struct smb2_iovec *iov = NULL;

        if (pdu->out.niov < 2) {
                smb2_set_error(smb2, "Too few vectors to sign");
                return -1;
        }
        if (pdu->out.iov[0].len != SMB2_HEADER_SIZE) {
                smb2_set_error(smb2, "First vector is not same size as smb2 "
                               "header");
                return -1;
        }
        if (smb2->session_id == 0) {
                return 0; /* DO NOT sign the PDU if session id is 0 */
        }
        if (smb2->session_key_size == 0) {
                return -1;
        }

        hdr = &pdu->header;

        memset(&key[0], 0, SIGNING_KEY_SIZE);
        memcpy(key, smb2->session_key, MIN(smb2->session_key_size, SIGNING_KEY_SIZE));
        key_len = MIN(smb2->session_key_size, SIGNING_KEY_SIZE);

        /* Set the flag before calculating signature */
        iov = &pdu->out.iov[0];
        hdr->flags |= SMB2_FLAGS_SIGNED;
        smb2_set_uint32(iov, 16, hdr->flags);

        /* sign the pdu and store the signature in pdu->header.signature
         * if pdu is signed then add SMB2_FLAGS_SIGNED to pdu->header.flags
         */

        if (smb2->dialect > SMB2_VERSION_0210) {
                /* TODO signing is not implemented for SMB versions higher than 0210 */
                smb2_set_error(smb2, "Signing is not supported for SMB3");
                return -1;
        } else {
                uint8_t sha_digest[SHA256_DIGEST_LENGTH];
                unsigned int sha_digest_length = SHA256_DIGEST_LENGTH;
                int i;
#if (OPENSSL_VERSION_NUMBER <= OPENSSL_VER_102)
                HMAC_CTX ctx;
                HMAC_CTX_init(&ctx);
                HMAC_Init_ex(&ctx, &key[0], key_len, EVP_sha256(), NULL);
                for (i=0; i < pdu->out.niov; i++) {
                        HMAC_Update(&ctx, pdu->out.iov[i].buf, pdu->out.iov[i].len);
                }
                HMAC_Final(&ctx, &sha_digest[0], &sha_digest_length);
                HMAC_CTX_cleanup(&ctx);
#else
                HMAC_CTX *ctx = HMAC_CTX_new();
                HMAC_CTX_reset(ctx);
                HMAC_Init_ex(ctx, &key[0], key_len, EVP_sha256(), NULL);
                for (i=0; i < pdu->out.niov; i++) {
                        HMAC_Update(ctx, pdu->out.iov[i].buf, pdu->out.iov[i].len);
                }
                HMAC_Final(ctx, &sha_digest[0], &sha_digest_length);
                HMAC_CTX_free(ctx); ctx = NULL;
#endif
                memcpy(&signature[0], sha_digest, SMB2_SIGNATURE_SIZE);
        }

        memcpy(&(hdr->signature[0]), signature, SMB2_SIGNATURE_SIZE);
        memcpy(iov->buf + 48, hdr->signature, 16);

        return 0;
}

int
smb2_pdu_check_signature(struct smb2_context *smb2,
                         struct smb2_pdu *pdu
                         )
{
        return 0;
}

#endif /* HAVE_OPENSSL_LIBS */
