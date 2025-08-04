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

#define CMD_CREATE   5
#define CMD_READ     8
#define CMD_WRITE    9
#define CMD_GETINFO 16

static int usmb2_build_request(struct usmb2_context *usmb2, int command,
                               int spl,
                               uint8_t *outdata, int outcount,
                               int incount)
{
        int len;
        uint8_t *buf = &usmb2->buf[0];
        uint32_t status;

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

        /* handle padding ? */
        
        /*
         * Status, fail hard if not successful.  Might need to add a check for pending here.
         */
        status = le32toh(*(uint32_t *)&usmb2->buf[4 + 8]);
        if (status) {
                return -1;
        }
        
        return 0;
}

/* OPEN */
uint8_t *usmb2_open(struct usmb2_context *usmb2, const char *name, int mode)
{
        int len = strlen(name) * 2;
        uint8_t *ptr;

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) */
        usmb2->buf[4 + 64] = 0x39;
        /* impersonation level 2 */
        usmb2->buf[4 + 64 +  4] = 0x02;
        /* desided access : READ, READ EA, READ ATTRIBUTES */
        usmb2->buf[4 + 64 + 24] = 0x89;
        /* share access : READ, WRITE */
        usmb2->buf[4 + 64 + 32] = 0x03;
        /* create disposition: open  if file exist open it, else fail */
        usmb2->buf[4 + 64 + 36] = 0x01;
        /* create options: non-direcotry.  must not be a directory */
        usmb2->buf[4 + 64 + 40] = 0x40;
        /* name offset */
        usmb2->buf[4 + 64 + 44] = 0x78;
        /* name length in bytes. i.e. 2 times the number of ucs2 characters */
        usmb2->buf[4 + 64 + 46] = len;

        ptr = &usmb2->buf[4 + 0x78];
        while (*name) {
                *ptr = *name++;
                ptr += 2;
        }


        if (usmb2_build_request(usmb2, CMD_CREATE,
                                0x78 + len, NULL, 0,
                                4 + 64 + 88)) {
                   return NULL;
        }

        ptr = malloc(16);
        if (ptr) {
                memcpy(ptr, &usmb2->buf[4 + 64 + 64], 16);
        }
        return ptr;
}


/* READ */
int usmb2_pread(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, int offset)
{
        int spl, len;
        uint32_t u32;
        uint8_t *ptr = &usmb2->buf[4 + 64];

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) + FILE_INFO + SMB2_FILE_STANDARD_INFO */
        *(uint32_t *)ptr = htole32(0x00000031);
        ptr += 4;
        
        /* length */
        *(uint32_t *)ptr = htole32(count);
        ptr += 4;

        /* offset */
        *(uint64_t *)ptr = htole64(offset);
        ptr += 8;

        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(ptr, fid, 16);

        
        if (usmb2_build_request(usmb2, CMD_READ,
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

        return u32;
}

/* WRITE */
int usmb2_pwrite(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, int offset)
{
        uint8_t *ptr = &usmb2->buf[4 + 64];

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) + data offset == 0x70 */
        *(uint32_t *)ptr = htole32(0x00700031);
        ptr += 4;
        
        /* length */
        *(uint32_t *)ptr = htole32(count);
        ptr += 4;

        /* offset */
        *(uint64_t *)ptr = htole64(offset);
        ptr += 8;

        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(ptr, fid, 16);
        
        if (usmb2_build_request(usmb2, CMD_WRITE,
                                64 + 48 + count, buf, count,
                                4 + 64 + 16)) {
                   return -1;
        }

        /* number of bytes returned */
        return le32toh(*(uint32_t *)&usmb2->buf[4 + 64 + 4]);
}

/* SIZE in bytes */
int usmb2_size(struct usmb2_context *usmb2, uint8_t *fid)
{
        uint8_t *ptr = &usmb2->buf[4 + 64];

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) + FILE_INFO + SMB2_FILE_STANDARD_INFO */
        *(uint32_t *)ptr = htole32(0x05010029);
        ptr += 4;
        
        /* length */
        *(uint32_t *)ptr = htole32(0x0000ffff);
        ptr += 4;

        /* offset */
        *(uint64_t *)ptr = htole64(0x00000068);
        ptr += 16;

        /* fid. fid is stored 8 bytes further into the pdu for getinfo vs read/write */
        memcpy(ptr, fid, 16);

        if (usmb2_build_request(usmb2, CMD_GETINFO,
                                64 + 40, NULL, 0,
                                4 + 64 + 8 + 24)) {
                   return -1;
        }

        return le64toh(*(uint32_t *)&usmb2->buf[4 + 64 + 8 + 8]);
}
