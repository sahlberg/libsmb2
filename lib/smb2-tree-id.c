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

int
smb2_select_tree_id(struct smb2_context* smb2, uint32_t tree_id)
{
    int i;

    for (
        i = 1;
        i <= smb2->tree_id_top && i <= SMB2_MAX_TREE_NESTING;
        i++
        ) {
        if (smb2->tree_id[i] == tree_id) {
            break;
        }
    }
    if (i <= smb2->tree_id_top) {
        smb2->tree_id_cur = i;
    }
    else {
        smb2_set_error(smb2, "No connected tree-id %08X to select", tree_id);
        return -1;
    }
    return 0;
}

int
smb2_get_tree_id_for_pdu(struct smb2_context* smb2, struct smb2_pdu* pdu, uint32_t* tree_id)
{
    if (pdu) {
        switch (pdu->header.command) {
        case SMB2_NEGOTIATE:
        case SMB2_SESSION_SETUP:
        case SMB2_LOGOFF:
        case SMB2_ECHO:
        case SMB2_TREE_CONNECT:
            *tree_id = 0;
            return 0;
        default:
            break;
        }
    }
    if (smb2->tree_id_top > 0) {
        *tree_id = smb2->tree_id[smb2->tree_id_cur];
    }
    else {
        smb2_set_error(smb2, "No tree-id connected");
        *tree_id = 0xdeadbeef;
        return -1;
    }
    return 0;
}

int
smb2_set_tree_id_for_pdu(struct smb2_context* smb2, struct smb2_pdu* pdu, uint32_t tree_id)
{
    if (pdu) {
        if (pdu->header.flags & SMB2_FLAGS_ASYNC_COMMAND) {
            smb2_set_error(smb2, "no tree id for async pdu");
            return 0;
        }
        switch (pdu->header.command) {
        case SMB2_NEGOTIATE:
        case SMB2_SESSION_SETUP:
        case SMB2_LOGOFF:
        case SMB2_ECHO:
            break;
        case SMB2_TREE_CONNECT:
            break;
        default:
            pdu->header.sync.tree_id = tree_id;
        }
        return 0;
    }
    return -1;
}

int smb2_get_session_id(struct smb2_context* smb2, uint64_t* session_id)
{
    *session_id = smb2->session_id;

    return 0;
}

int
smb2_connect_tree_id(struct smb2_context* smb2, uint32_t tree_id)
{
    if (smb2->tree_id_top < (SMB2_MAX_TREE_NESTING - 1)) {
        smb2->tree_id[++smb2->tree_id_top] = tree_id;
        smb2->tree_id_cur = smb2->tree_id_top;
    }
    else {
        smb2_set_error(smb2, "Tree nesting too deep");
        return -1;
    }
    return 0;
}

int
smb2_disconnect_tree_id(struct smb2_context* smb2, uint32_t tree_id)
{
    int i, j;

    if (smb2->tree_id_top > 0) {
        for (
            i = 1;
            i <= smb2->tree_id_top && i <= SMB2_MAX_TREE_NESTING;
            i++
            ) {
            if (smb2->tree_id[i] == tree_id) {
                break;
            }
        }
        if (i <= smb2->tree_id_top) {
            for (j = i; j < smb2->tree_id_top; j++) {
                smb2->tree_id[j] = smb2->tree_id[j + 1];
            }
            smb2->tree_id_top--;
            /* not sure what tree id should be after a disconnect but
             * this makes sure its not invalid */
            if (smb2->tree_id_cur > smb2->tree_id_top) {
                smb2->tree_id_cur = smb2->tree_id_top;
            }
            return 0;
        }
    }

    smb2_set_error(smb2, "No tree-id %08X to remove", tree_id);
    return -1;
}