/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* PS2IOP does not use read/write to access the socket but lwip calls.
   it will need this:

#define write(a,b,c) lwip_send(a,b,c,0)
#define read(a,b,c) lwip_recv(a,b,c,0)

*/
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "usmb2.h"

#define CMD_NEGOTIATE_PROTOCOL  0
#define CMD_SESSION_SETUP       1
#define CMD_TREE_CONNECT        3
#define CMD_CREATE              5
#define CMD_READ                8
#define CMD_WRITE               9
#define CMD_GETINFO            16

#define STATUS_SUCCESS          0x00000000
#define STATUS_MORE_PROCESSING  0xc0000016

static int write_to_socket(struct usmb2_context *usmb2, uint8_t *buf, int len)
{
        int count;
        
        while (len) {
                count = write(usmb2->fd, buf, len);
                if (count < 0) {
                        return -1;
                }
                len -= count;
                buf += count;
        }
        return 0;
}

static int read_from_socket(struct usmb2_context *usmb2, uint8_t *buf, int len)
{ 
        int count;
        
        while (len) {
                count = read(usmb2->fd, buf, len);
                if (count < 0) {
                        return -1;
                }
                len -= count;
                buf += count;
        }
        return 0;
}
        
static int usmb2_build_request(struct usmb2_context *usmb2,
                               int command, int commandoutcount, int commandincount,
                               uint8_t *outdata, int outdatacount,
                               uint8_t *indata, int indatacount)
{
        uint32_t spl;
        uint8_t *buf = &usmb2->buf[0];
        uint32_t status;

        /*
         * SPL
         */
        spl = 64 + commandoutcount + outdatacount;
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
        if (command != CMD_NEGOTIATE_PROTOCOL) {
                *(uint32_t *)buf = htole32(0x00010040);
        } else {
                *(uint32_t *)buf = htole32(0x00000040);
        }
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
        *(uint64_t *)buf = usmb2->session_id;
        buf += 24; /* 16 byte signature is all zero */


        /*
         * Write the request to the socket
         */
        write_to_socket(usmb2, &usmb2->buf[0], 4 + 64 + commandoutcount);
        spl -= 64 + commandoutcount;
        
        /*
         * Write payload data to the socket
         */
        if (outdata) {
                write_to_socket(usmb2, outdata, outdatacount);
                spl -= outdatacount;
        }

        /*
         * Write padding
         */
        if (spl) {
                write_to_socket(usmb2, &usmb2->buf[0], spl);
        }

        
        /*
         * Read SPL, SMB2 header and command reply header (and file info blob) from socket
         */
        read_from_socket(usmb2, (uint8_t *)&spl, 4);
        spl = ntohl(spl);

        /*
         * Read SMB2 header
         */
        read_from_socket(usmb2, &usmb2->buf[0], 64);
        spl -= 64;

        if (command == CMD_SESSION_SETUP) {
                usmb2->session_id = *(uint64_t *)&usmb2->buf[0x28];
        }
        if (command == CMD_TREE_CONNECT) {
                usmb2->tree_id = *(uint32_t *)&usmb2->buf[0x24];
        }

        //qqq handle keepalives
        
        /*
         * Status, fail hard if not successful.  Might need to add a check for pending here.
         * Read status before we read all the padding data into buf, potentially overwriting the smb2 header.
         * .. NegotiateProtocol contexts entered the chat ...
         */
        status = le32toh(*(uint32_t *)&usmb2->buf[8]);

        /*
         * Read command header
         */
        if (commandincount > spl) {
                commandincount = spl;
        }
        read_from_socket(usmb2, &usmb2->buf[0], commandincount);
        spl -= commandincount;

        /*
         * Read data
         */
        if (indata) {
                if (indatacount > spl) {
                        indatacount = spl;
                }
                read_from_socket(usmb2, indata, indatacount);
                spl -= indatacount;
        }
        
        /*
         * Read padding
         */
        read_from_socket(usmb2, &usmb2->buf[commandincount], spl);

        return status;
}

/* NEGOTIATE PROTOCOL */
int usmb2_negotiateprotocol(struct usmb2_context *usmb2)
{
        uint8_t *ptr = &usmb2->buf[4 + 64];

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) + DialectCount=1 */
        *(uint32_t *)ptr = htole32(0x00010024);
        ptr += 12; /* SecurityMode=0, Capabilities=0 */

        /* client guid */
        ptr[0] = 0xaa;
        ptr[15] = 0xbb;
        ptr += 24;

        /* dialects 3.00 */
         *(uint32_t *)ptr = htole32(0x0000300);

        if (usmb2_build_request(usmb2,
                                CMD_NEGOTIATE_PROTOCOL, 40, 64,
                                NULL, 0, NULL, 0)) {
                   return -1;
        }
        /* reply is in usmb2->buf */
        
        return 0;
}

static int create_ntlmssp_blob(struct usmb2_context *usmb2, int cmd)
{
        uint8_t *ptr = &usmb2->buf[4 + 64 + 12];

        ptr = &usmb2->buf[4 + 64 + 24];
        memcpy(ptr, "NTLMSSP", 7);
        ptr += 8;
        if (cmd == 1) {
                /* NTLMSSP_NEGOTIATE */
                *ptr = cmd;
                ptr += 4;
                /* flags qqq trim this down  */
                *(uint32_t *)ptr = htole32(0x20080227);
                
                return 32;
        }
        if (cmd == 3) {
                /* NTLMSSP_AUTH */
                *ptr = cmd;
                ptr += 0x34;
                /* flags qqq trim this down */
                *(uint32_t *)ptr = htole32(0x20088817);
                
                return 72;
        }
        return -1;
}

/* SESSION_SETUP */
int usmb2_sessionsetup(struct usmb2_context *usmb2)
{
        int len, cmd;
        uint32_t status;
        uint8_t *ptr;

        cmd = 1;

 again:
        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        len = create_ntlmssp_blob(usmb2, cmd);

        /*
         * Command header
         */
        /* struct size (16 bits) + Flags=0 */
        *(uint32_t *)&usmb2->buf[4 + 64] = htole32(0x00000019);

        /* buffer offset and buffer length */
        ptr = &usmb2->buf[4 + 64 + 12];
        *ptr = 0x58;
        ptr += 2;
        *(uint16_t *)ptr = htole16(len);

        
        status = usmb2_build_request(usmb2,
                                     CMD_SESSION_SETUP, 24 + len, 64,
                                     NULL, 0, NULL, 0);
        if (cmd == 1 && status == STATUS_MORE_PROCESSING) {
                cmd = 3;
                goto again;
        }
        if (status) {
                   return -1;
        }
        /* reply is in usmb2->buf */
        
        return 0;
}

/* TREE CONNECT */
int usmb2_treeconnect(struct usmb2_context *usmb2, const char *unc)
{
        int len = strlen(unc) * 2;
        uint8_t *ptr;

        memset(usmb2->buf, 0, sizeof(usmb2->buf));
        /*
         * Command header
         */
        /* struct size (16 bits) */
        usmb2->buf[4 + 64] = 0x09;
        /* unc offset */
        usmb2->buf[4 + 64 + 4] = 0x48;
        /* unc length in bytes. i.e. 2 times the number of ucs2 characters */
        usmb2->buf[4 + 64 + 6] = len;


        ptr = &usmb2->buf[4 + 0x48];
        while (*unc) {
                *ptr = *unc++;
                ptr += 2;
        }

        if (usmb2_build_request(usmb2,
                                CMD_TREE_CONNECT, 8 + len, 16,
                                NULL, 0, NULL, 0)) {
                   return -1;
        }

        return 0;
}

/* OPEN */
/* qqq TODO add support for O_RDWR */
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


        if (usmb2_build_request(usmb2,
                                CMD_CREATE, 0x38 + len, 88,
                                NULL, 0, NULL, 0)) {
                   return NULL;
        }

        ptr = malloc(16);
        if (ptr) {
                memcpy(ptr, &usmb2->buf[64], 16);
        }
        return ptr;
}


/* READ */
int usmb2_pread(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, int offset)
{
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

        
        if (usmb2_build_request(usmb2,
                                CMD_READ, 48 + 8, 16,
                                NULL, 0, buf, count)) {
                   return -1;
        }

        /* number of bytes returned */
        u32 = le32toh(*(uint32_t *)&usmb2->buf[4]);

        return u32;
}

#if 0
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
        
        if (usmb2_build_request(usmb2, CMD_WRITE, qqq
                                48 + count, buf, count, NULL, 0)) {
                   return -1;
        }

        /* number of bytes returned */
        return le32toh(*(uint32_t *)&usmb2->buf[4 + 64 + 4]);
}
#endif

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

        if (usmb2_build_request(usmb2,
                                CMD_GETINFO, 40, 8,
                                NULL, 0, NULL, 0)) {
                   return -1;
        }

        return le64toh(*(uint32_t *)&usmb2->buf[8 + 8]);
}

struct usmb2_context *usmb2_init_context(uint32_t ip)
{
        struct usmb2_context *usmb2;
        struct sockaddr_in sin;
        int socksize = sizeof(struct sockaddr_in);
        
        usmb2 = calloc(1, sizeof(struct usmb2_context));
        if (usmb2 == NULL) {
                return NULL;
        }

        usmb2->fd = socket(AF_INET, SOCK_STREAM, 0);

        sin.sin_family = AF_INET;
        sin.sin_port = htons(445);
        memcpy(&sin.sin_addr, &ip, 4);
#ifdef HAVE_SOCK_SIN_LEN
        sin.sin_len = socksize;
#endif
        if (connect(usmb2->fd, (struct sockaddr *)&sin, socksize) != 0) {
                free(usmb2);
                return NULL;
        }

        if (usmb2_negotiateprotocol(usmb2)) {
                free(usmb2);
                return NULL;
        }

        if (usmb2_sessionsetup(usmb2)) {
                free(usmb2);
                return NULL;
        }
        
        return usmb2;
}
