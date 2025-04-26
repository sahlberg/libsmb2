/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2025 by André Guilherme <andregui17@outlook.com>

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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "compat.h"

#include "portable-endian.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

void
smb2_set_pdu_message_id(struct smb2_context* smb2, struct smb2_pdu* pdu, uint64_t message_id)
{
    pdu->header.message_id = message_id;
}

uint64_t
smb2_get_pdu_message_id(struct smb2_context* smb2, struct smb2_pdu* pdu)
{
    if (pdu) {
        return pdu->header.message_id;
    }
    else if (smb2) {
        return smb2->message_id;
    }
    return 0;
}