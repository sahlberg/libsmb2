/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2019 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#ifndef _SMB2_SEAL_H_
#define _SMB2_SEAL_H_

#ifdef __cplusplus
extern "C" {
#endif

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

#include <stdio.h>

#include "portable-endian.h"

#include "aes128ccm.h"
#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

static const char xfer[4] = {0xFD, 'S', 'M', 'B'};

int
smb3_encrypt_pdu(struct smb2_context *smb2,
                 struct smb2_pdu *pdu)
{
        struct smb2_pdu *tmp_pdu;
        uint32_t spl, u32;
        int i;
        uint16_t u16;

        if (!smb2->seal) {
                return 0;
        }
        if (!pdu->seal) {
                return 0;
        }

        spl = 52;  /* transform header */
        for (tmp_pdu = pdu; tmp_pdu; tmp_pdu = tmp_pdu->next_compound) {
                for (i = 0; i < tmp_pdu->out.niov; i++) {
                        spl += tmp_pdu->out.iov[i].len;
                }
        }
        pdu->crypt = malloc(spl);
        if (pdu->crypt == NULL) {
                pdu->seal = 0;
                return -1;
        }

        memset(pdu->crypt, 0, spl);
        memcpy(&pdu->crypt[0], xfer, 4);
        for (i = 20; i < 31; i++) {
                pdu->crypt[i] = random()&0xff;
        }
        u32 = htole32(spl - 52);
        memcpy(&pdu->crypt[36], &u32, 4);
        u16 = htole16(SMB_ENCRYPTION_AES128_CCM);
        memcpy(&pdu->crypt[42], &u16, 2);
        memcpy(&pdu->crypt[44], &smb2->session_id, 8);

        spl = 52;  /* transform header */
        for (tmp_pdu = pdu; tmp_pdu; tmp_pdu = tmp_pdu->next_compound) {
                for (i = 0; i < tmp_pdu->out.niov; i++) {
                        memcpy(&pdu->crypt[spl], tmp_pdu->out.iov[i].buf,
                               tmp_pdu->out.iov[i].len);
                        spl += tmp_pdu->out.iov[i].len;
                }
        }

        aes128ccm_encrypt(smb2->serverin_key,
                          &pdu->crypt[20], 11,
                          &pdu->crypt[20], 32,
                          &pdu->crypt[52], spl - 52,
                          &pdu->crypt[4], 16);
        pdu->crypt_len = spl;

        return 0;
}


#ifdef __cplusplus
}
#endif

#endif /* _SMB2_SEAL_H_ */
