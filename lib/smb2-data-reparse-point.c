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

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

/*
 * Pull one of the utf16 names out of the path buffer of a symlink or
 * mount point reparse buffer and return it as a utf8 string allocated
 * off memctx. offset and len are relative to the start of the path
 * buffer, which itself starts at pathbuffer bytes into the reparse
 * data buffer.
 */
static char *
decode_reparse_name(struct smb2_context *smb2, void *memctx,
                    struct smb2_iovec *vec, size_t pathbuffer,
                    uint16_t offset, uint16_t len)
{
        const char *tmp;
        char *name;

        if (pathbuffer + offset + len > vec->len) {
                return NULL;
        }

        tmp = smb2_utf16_to_utf8((uint16_t *)(void *)
                                 (&vec->buf[pathbuffer + offset]), len / 2);
        if (tmp == NULL) {
                return NULL;
        }
        name = smb2_alloc_data(smb2, memctx, strlen(tmp) + 1);
        if (name == NULL) {
                free(discard_const(tmp));
                return NULL;
        }
        strcpy(name, tmp);
        free(discard_const(tmp));

        return name;
}

/*
 * Encode a reparse data buffer into vec, returning the number of bytes
 * used or -1 on failure. Only the tags that we can create are supported.
 */
int
smb2_encode_reparse_data_buffer(struct smb2_context *smb2,
                                struct smb2_reparse_data_buffer *rp,
                                struct smb2_iovec *vec)
{
        struct smb2_utf16 *sub = NULL, *print = NULL;
        size_t sublen, printlen, pathlen, len;

        switch (rp->reparse_tag) {
        case SMB2_REPARSE_TAG_SYMLINK:
                break;
        default:
                smb2_set_error(smb2, "Can not encode reparse tag 0x%08x",
                               rp->reparse_tag);
                return -1;
        }

        sub = smb2_utf8_to_utf16(rp->symlink.subname ?
                                 rp->symlink.subname : "");
        if (sub == NULL) {
                smb2_set_error(smb2, "Could not convert substitute name "
                               "into UTF-16");
                return -1;
        }
        print = smb2_utf8_to_utf16(rp->symlink.printname ?
                                   rp->symlink.printname : "");
        if (print == NULL) {
                smb2_set_error(smb2, "Could not convert print name "
                               "into UTF-16");
                free(sub);
                return -1;
        }

        sublen = 2 * (size_t)sub->len;
        printlen = 2 * (size_t)print->len;
        /* Both names are stored nul terminated, the nul is not counted
         * in the name lengths. */
        pathlen = sublen + 2 + printlen + 2;
        len = 8 + 12 + pathlen;

        if (len > 65535 || vec->len < len) {
                smb2_set_error(smb2, "Reparse data buffer does not fit");
                free(sub);
                free(print);
                return -1;
        }

        memset(vec->buf, 0, len);
        smb2_set_uint32(vec, 0, rp->reparse_tag);
        smb2_set_uint16(vec, 4, (uint16_t)(12 + pathlen));
        smb2_set_uint16(vec, 8, 0);                       /* subname offset */
        smb2_set_uint16(vec, 10, (uint16_t)sublen);
        smb2_set_uint16(vec, 12, (uint16_t)(sublen + 2)); /* printname off */
        smb2_set_uint16(vec, 14, (uint16_t)printlen);
        smb2_set_uint32(vec, 16, rp->symlink.flags);
        memcpy(&vec->buf[20], sub->val, sublen);
        memcpy(&vec->buf[20 + sublen + 2], print->val, printlen);

        free(sub);
        free(print);

        return (int)len;
}

int
smb2_decode_reparse_data_buffer(struct smb2_context *smb2,
                                void *memctx,
                                struct smb2_reparse_data_buffer *rp,
                                struct smb2_iovec *vec)
{
        uint16_t suboffset, sublen, printoffset, printlen;
        size_t pathbuffer, targetlen;

        if (vec->len < 8) {
                return -1;
        }

        smb2_get_uint32(vec, 0, &rp->reparse_tag);
        smb2_get_uint16(vec, 4, &rp->reparse_data_length);

        /* Do not truncate vec->len to 16 bits for this comparison. */
        if (vec->len < (size_t)rp->reparse_data_length + 8) {
                return -1;
        }
        switch (rp->reparse_tag) {
        case SMB2_REPARSE_TAG_SYMLINK:
        case SMB2_REPARSE_TAG_MOUNT_POINT:
                /*
                 * The two buffers are the same except that the symlink
                 * has an additional 32 bit flags field just before the
                 * path buffer. [MS-FSCC] 2.1.2.4 and 2.1.2.5
                 */
                if (rp->reparse_tag == SMB2_REPARSE_TAG_SYMLINK) {
                        pathbuffer = 20;
                        if (vec->len < pathbuffer) {
                                return -1;
                        }
                        smb2_get_uint32(vec, 16, &rp->symlink.flags);
                } else {
                        pathbuffer = 16;
                        if (vec->len < pathbuffer) {
                                return -1;
                        }
                        rp->symlink.flags = 0;
                }
                rp->symlink.subname = NULL;
                rp->symlink.printname = NULL;

                smb2_get_uint16(vec, 8, &suboffset);
                smb2_get_uint16(vec, 10, &sublen);
                smb2_get_uint16(vec, 12, &printoffset);
                smb2_get_uint16(vec, 14, &printlen);

                /* The names must fit inside the path buffer. */
                if ((size_t)suboffset + sublen + pathbuffer - 8 >
                    rp->reparse_data_length) {
                        return -1;
                }
                if ((size_t)printoffset + printlen + pathbuffer - 8 >
                    rp->reparse_data_length) {
                        return -1;
                }

                rp->symlink.subname = decode_reparse_name(smb2, memctx, vec,
                                                          pathbuffer,
                                                          suboffset, sublen);
                if (rp->symlink.subname == NULL) {
                        return -1;
                }
                rp->symlink.printname = decode_reparse_name(smb2, memctx, vec,
                                                            pathbuffer,
                                                            printoffset,
                                                            printlen);
                if (rp->symlink.printname == NULL) {
                        return -1;
                }
                break;
        case SMB2_REPARSE_TAG_LX_SYMLINK:
                /*
                 * A 32 bit version followed by the target as utf8.
                 * The target is not nul terminated. [MS-FSCC] 2.1.2.7
                 */
                if (rp->reparse_data_length < 4) {
                        return -1;
                }
                smb2_get_uint32(vec, 8, &rp->lx_symlink.version);
                targetlen = rp->reparse_data_length - 4;

                rp->lx_symlink.target = smb2_alloc_data(smb2, memctx,
                                                        targetlen + 1);
                if (rp->lx_symlink.target == NULL) {
                        return -1;
                }
                memcpy(rp->lx_symlink.target, &vec->buf[12], targetlen);
                rp->lx_symlink.target[targetlen] = 0;
                break;
        default:
                /*
                 * A tag we have no decoder for. The tag itself has still
                 * been filled in, which is all the caller needs to tell
                 * what kind of object this is.
                 */
                break;
        }

        return 0;
}
