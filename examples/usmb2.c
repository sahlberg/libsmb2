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

static void usmb2_build_hdr(struct usmb2_context *usmb2, int command)
{
        uint64_t u64;
        uint32_t u32;
        uint8_t *buf = &usmb2->buf[4];

        /* signature */
        u32 = htole32(0x424d53fe);
        *(uint32_t *)buf = u32;
        buf += 4;

        /* header length (16 bits) + credit charge (16 bits)
         * Credit charge in smb2 is 1 per 64kb requested but we never read > 2048 bytes
         * so we can hardcode it to 1.
         */
        u32 = htole32(0x00010040);
        *(uint32_t *)buf = u32;
        buf += 8; /* status, 4 bytes, is zero */
        
        /* command + credit request */
        u32 = htole32(0x00010000 + command);
        *(uint32_t *)buf = u32;
        buf += 12; /* flags and next command are both 0, 8 bytes */

        /* message id */
        u64 = htole64(usmb2->message_id++);
        *(uint64_t *)buf = u64;
        buf += 12; /* 4 extra reserved bytes */

        /* tree id */
        u32 = htole32(usmb2->tree_id);
        *(uint32_t *)buf = u32;
        buf += 4;

        /* session id */
        u64 = htole64(usmb2->session_id);
        *(uint64_t *)buf = u64;
}

/* READ in units of 512 bytes */
int usmb2_pread(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, int offset)
{
        int spl, len;
        uint32_t u32;
        uint64_t u64;
        uint8_t *hdr = &usmb2->buf[4 + 64];

        count  *= 512;
        offset *= 512;
        
        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        usmb2_build_hdr(usmb2, CMD_READ);

        /* struct size (16 bits) + padding (8 bits) + flags (8 bits) */
        u32 = htole32(0x00000031);
        *(uint32_t *)hdr = u32;
        hdr += 4;

        /* length */
        u32 = htole32(count);
        *(uint32_t *)hdr = u32;
        hdr += 4;

        /* offset */
        u64 = htole64(offset);
        *(uint64_t *)hdr = u64;
        hdr += 8;

        /* file id */
        memcpy(hdr, fid, 16);
        hdr += 16;

        /* spl */
        spl = 64 + 48 + 8;
        u32 = htobe32(spl);
        *(uint32_t *)usmb2->buf = u32;


        /* Write the request to the socket */
        hdr = &usmb2->buf[0];
        spl = spl + 4;
        while (spl) {
                len = write(usmb2->fd, hdr, spl);
                if (len < 0) {
                        return -1;
                }
                spl -= len;
                hdr += len;
        }

        /* Read SPL, SMB2 header and read reply header from socket */
        spl = 4 + 64 + 16;
        hdr = &usmb2->buf[0];
        while (spl) {
                len = read(usmb2->fd, hdr, spl);
                if (len < 0) {
                        continue;
                }
                spl -= len;
                hdr += len;
        }

        spl = be32toh(*(uint32_t *)&usmb2->buf[0]);
        
        /* status, fail hard if not successful */
        u32 = le32toh(*(uint32_t *)&usmb2->buf[4 + 8]);
        if (u32) {
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
        int spl, len;
        uint32_t u32;
        uint64_t u64;
        uint8_t *hdr = &usmb2->buf[4 + 64];

        count  *= 512;
        offset *= 512;
        
        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        usmb2_build_hdr(usmb2, CMD_WRITE);

        
        /* struct size (16 bits) + data offset (16 bits) */
        u32 = htole32(0x00700031);
        *(uint32_t *)hdr = u32;
        hdr += 4;

        /* length */
        u32 = htole32(count);
        *(uint32_t *)hdr = u32;
        hdr += 4;

        /* offset */
        u64 = htole64(offset);
        *(uint64_t *)hdr = u64;
        hdr += 8;

        /* file id */
        memcpy(hdr, fid, 16);
        hdr += 16;

        /* spl */
        spl = 64 + 48 + count;
        u32 = htobe32(spl);
        *(uint32_t *)usmb2->buf = u32;


        /* Write the request to the socket */
        hdr = &usmb2->buf[0];
        spl = 64 + 48 + 4;
        while (spl) {
                len = write(usmb2->fd, hdr, spl);
                if (len < 0) {
                        return -1;
                }
                spl -= len;
                hdr += len;
        }

        /* Write the data to the socket */
        while (count) {
                len = write(usmb2->fd, buf, count);
                if (len < 0) {
                        return -1;
                }
                count -= len;
                buf += len;
        }
        
        /* Read SPL, SMB2 header and read reply header from socket */
        spl = 4 + 64 + 16;
        hdr = &usmb2->buf[0];
        while (spl) {
                len = read(usmb2->fd, hdr, spl);
                if (len < 0) {
                        continue;
                }
                spl -= len;
                hdr += len;
        }

        spl = be32toh(*(uint32_t *)&usmb2->buf[0]);
        
        /* status, fail hard if not successful */
        u32 = le32toh(*(uint32_t *)&usmb2->buf[4 + 8]);
        if (u32) {
                return -1;
        }

        /* number of bytes returned */
        u32 = le32toh(*(uint32_t *)&usmb2->buf[4 + 64 + 4]);

        /* We only read in 512 byte chunks so we will never need to worry about padding until next pdu*/
        return u32 / 512;
}

/* return units of 512 bytes */
int usmb2_size(struct usmb2_context *usmb2, uint8_t *fid)
{
        int spl, len;
        uint32_t u32;
        //uint64_t u64;
        uint8_t *hdr = &usmb2->buf[4 + 64];

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        usmb2_build_hdr(usmb2, CMD_GETINFO);

        /* struct size (16 bits) + FILE_INFO + SMB2_FILE_STANDARD_INFO */
        u32 = htole32(0x05010029);
        *(uint32_t *)hdr = u32;
        hdr += 4;

        /* output buffer length */
        u32 = htole32(0x0000ffff);
        *(uint32_t *)hdr = u32;
        hdr += 4;
        
        /* input buffer offset */
        u32 = htole32(0x00000068);
        *(uint32_t *)hdr = u32;
        hdr += 16; /* input size is zero, additional info is zero, flags are zero */

        /* file id */
        memcpy(hdr, fid, 16);


        /* spl */
        spl = 64 + 40;
        u32 = htobe32(spl);
        *(uint32_t *)usmb2->buf = u32;

        /* Write the request to the socket */
        hdr = &usmb2->buf[0];
        spl = spl + 4;
        while (spl) {
                len = write(usmb2->fd, hdr, spl);
                if (len < 0) {
                        return -1;
                }
                spl -= len;
                hdr += len;
        }

        /* Read SPL, SMB2 header and getinfo reply header and file info blob from socket */
        spl = 4 + 64 + 8 + 24;
        hdr = &usmb2->buf[0];
        while (spl) {
                len = read(usmb2->fd, hdr, spl);
                if (len < 0) {
                        continue;
                }
                spl -= len;
                hdr += len;
        }

        /* status, fail hard if not successful */
        u32 = le32toh(*(uint32_t *)&usmb2->buf[4 + 8]);
        if (u32) {
                return -1;
        }

        /* We only read in 512 byte chunks so we will never need to worry about padding until next pdu*/
        return le64toh(*(uint32_t *)&usmb2->buf[4 + 64 + 8 + 8]) / 512;
}
