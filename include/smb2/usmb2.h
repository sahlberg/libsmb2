/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2025 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#ifndef _USMB2_H_
#define _USMB2_H_

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

/* largest pdu
 *   4 bytes SPL
 *  64 bytes SMB2 header
 *   8 bytes GETINFO reply header
 * 142 bytes SMB2_FILE_ALL_INFO structure
 */
#define USMB2_SIZE (4 + 64 + 8 + 142)
struct usmb2_context {
        int fd;
        uint64_t message_id;
        uint64_t session_id;
        uint32_t tree_id;
        uint8_t buf[USMB2_SIZE];
};

/* Read in units of 512 bytes */
int usmb2_pread(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, int offset);
/* Size in units of 512 bytes */
int usmb2_size(struct usmb2_context *usmb2, uint8_t *fid);
/* Write in units of 512 bytes */
int usmb2_pwrite(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, int offset);
        
#endif /* !_USMB2_H_ */
