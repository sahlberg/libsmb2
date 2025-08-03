/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

#include "usmb2.h"

#define CMD_READ     8
#define CMD_WRITE    9
#define CMD_GETINFO 16

static int usmb2_build_request(struct usmb2_context *usmb2, int command,
                               uint32_t struct_size, uint32_t length,
                               uint64_t offset, uint8_t *fid, int fid_extra_offset,
                               int spl,
                               uint8_t *outdata, int outcount,
                               int incount)
{
        int len;
        uint8_t *buf = &usmb2->buf[0];
        uint32_t status;

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * SPL
         */
        *(uint32_t *)&usmb2->buf[0] = htobe32(spl);
        buf += 4;
        
        /*
         * SMB2 header
         */
       
        /* signature */
        *(uint32_t *)buf = htole32(0x424d53fe);
        buf += 4;

        /* header length (16 bits) + credit charge (16 bits)
         * Credit charge in smb2 is 1 per 64kb requested but we never read > 2048 bytes
         * so we can hardcode it to 1.
         */
        *(uint32_t *)buf = htole32(0x00010040);
        buf += 8; /* status, 4 bytes, is zero */
        
        /* command + credit request */
        *(uint32_t *)buf = htole32(0x00010000 + command);
        buf += 12; /* flags and next command are both 0, 8 bytes */

        /* message id */
        *(uint64_t *)buf = htole64(usmb2->message_id++);
        buf += 12; /* 4 extra reserved bytes */

        /* tree id */
        *(uint32_t *)buf = htole32(usmb2->tree_id);
        buf += 4;

        /* session id */
        *(uint64_t *)buf = htole64(usmb2->session_id);
        buf += 24; /* 16 byte signature is all zero */

        /*
         * Command header
         */
        /* struct size (16 bits) + FILE_INFO + SMB2_FILE_STANDARD_INFO */
        *(uint32_t *)buf = htole32(struct_size);
        buf += 4;
        
        /* length */
        *(uint32_t *)buf = htole32(length);
        buf += 4;

        /* offset */
        *(uint64_t *)buf = htole64(offset);
        buf += 8 + fid_extra_offset;

        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(buf, fid, 16);


        /*
         * Write the request to the socket
         */
        buf = &usmb2->buf[0];
        spl = spl + 4;
        while (spl) {
                len = write(usmb2->fd, buf, spl);
                if (len < 0) {
                        return -1;
                }
                spl -= len;
                buf += len;
        }


        /*
         * Write payload data to the socket
         */
        if (outdata) {
                while (outcount) {
                        len = write(usmb2->fd, outdata, outcount);
                        if (len < 0) {
                                return -1;
                        }
                        outcount -= len;
                        outdata += len;
                }
        }


        /*
         * Read SPL, SMB2 header and command reply header (and file info blob) from socket
         */
        buf = &usmb2->buf[0];
        while (incount) {
                len = read(usmb2->fd, buf, incount);
                if (len < 0) {
                        continue;
                }
                incount -= len;
                buf += len;
        }

        /*
         * Status, fail hard if not successful.  Might need to add a check for pending here.
         */
        status = le32toh(*(uint32_t *)&usmb2->buf[4 + 8]);
        if (status) {
                return -1;
        }
        
        return 0;
}

/* READ in units of 512 bytes */
int usmb2_pread(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, int offset)
{
        int spl, len;
        uint32_t u32;

        count  *= 512;
        offset *= 512;
        
        if (usmb2_build_request(usmb2, CMD_READ, 0x00000031, count, offset, fid, 0,
                            64 + 48 + 8, NULL, 0,
                                4 + 64 + 16)) {
                   return -1;
        }

        /* number of bytes returned */
        u32 = le32toh(*(uint32_t *)&usmb2->buf[4 + 64 + 4]);

        /* Read data from socket */
        spl = u32;
        while (spl) {
                len = read(usmb2->fd, buf, spl);
                if (len < 0) {
                        continue;
                }
                spl -= len;
                buf += len;
        }

        /* We only read in 512 byte chunks so we will never need to worry about padding until next pdu*/
        return u32 / 512;
}

/* WRITE in units of 512 bytes */
int usmb2_pwrite(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, int offset)
{
        count  *= 512;
        offset *= 512;
        
        if (usmb2_build_request(usmb2, CMD_WRITE, 0x00700031, count, offset, fid, 0,
                            64 + 48 + count, buf, count,
                                4 + 64 + 16)) {
                   return -1;
        }

        /* number of bytes returned */
        /* We only read in 512 byte chunks so we will never need to worry about padding until next pdu*/
        return le32toh(*(uint32_t *)&usmb2->buf[4 + 64 + 4]) / 512;
}

/* return units of 512 bytes */
int usmb2_size(struct usmb2_context *usmb2, uint8_t *fid)
{
        if (usmb2_build_request(usmb2, CMD_GETINFO, 0x05010029, 0x0000ffff, 0x00000068, fid, 8,
                            64 + 40, NULL, 0,
                                4 + 64 + 8 + 24)) {
                   return -1;
        }

        /* We only read in 512 byte chunks so we will never need to worry about padding until next pdu*/
        return le64toh(*(uint32_t *)&usmb2->buf[4 + 64 + 8 + 8]) / 512;
}
