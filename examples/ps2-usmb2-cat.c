/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#if !defined(__amigaos4__) && !defined(__AMIGA__) && !defined(__AROS__)
#include <poll.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "usmb2.h"

#define MAXBUF 16 * 1024 * 1024
uint8_t buf[MAXBUF];
uint32_t pos;

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-cat-sync <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>/<path>\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        uint8_t *fh;
        int rc = 0;
        struct usmb2_context *usmb2;
        
        if (argc < 2) {
                usage();
        }


        usmb2 = usmb2_init_context(htonl(0x0a0a0a0b)); /* 10.10.10.11 */
        printf("usmb2:%p\n", usmb2);

        /* Map the share */
        if (usmb2_treeconnect(usmb2, "\\\\10.10.10.11\\SNAP-1")) {
                printf("failed to map share\n");
                exit(10);
        }
        
        /* Open the file */
        fh = usmb2_open(usmb2, "advancedsettings.xml", O_RDONLY);
        if (fh == NULL) {
		printf("usmb2_open failed\n");
		exit(10);
        }
        
        usmb2_pread(usmb2, fh, buf, 30, 0);
        printf("BUF: %s\n", buf);
        usmb2_pread(usmb2, fh, buf, 30, 2);
        printf("BUF: %s\n", buf);
        printf("Size: %d bytes\n", usmb2_size(usmb2, fh));

	return rc;
}
