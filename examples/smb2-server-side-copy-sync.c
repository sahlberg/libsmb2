/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 Rida Shamasneh

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"

/*
Ths example was tested with an SMB server of with following limits:
  - max chunk size: 1 MiB
  - max total request size: 16 MiB
  - max chunk count: 256
*/
#define COPYCHUNK_SIZE (1024 * 1024)
#define MAX_COPYCHUNKS_PER_REQUEST 16

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-server-side-copy-sync <source-url> <destination-url>\n\n"
                "Both URLs must point to the same server/share.\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/<share>/<path>\n");
        exit(1);
}

static int same_or_null(const char *a, const char *b)
{
        if (a == NULL || b == NULL) {
                return a == b;
        }

        return strcmp(a, b) == 0;
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *src_url;
        struct smb2_url *dst_url;
        struct smb2fh *srcfh;
        struct smb2fh *dstfh;
        struct smb2_stat_64 st;
        struct smb2_srv_copychunk_resume_key resume_key;
        struct smb2_srv_copychunk chunks[MAX_COPYCHUNKS_PER_REQUEST];
        struct smb2_srv_copychunk_reply reply;
        uint64_t copied = 0;
        uint64_t remaining;
        uint32_t batch_count;
        uint32_t i;
        int rc = 0;

        if (argc < 3) {
                usage();
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                return 1;
        }

        src_url = smb2_parse_url(smb2, argv[1]);
        if (src_url == NULL) {
                fprintf(stderr, "Failed to parse source url: %s\n",
                        smb2_get_error(smb2));
                smb2_destroy_context(smb2);
                return 1;
        }

        dst_url = smb2_parse_url(smb2, argv[2]);
        if (dst_url == NULL) {
                fprintf(stderr, "Failed to parse destination url: %s\n",
                        smb2_get_error(smb2));
                smb2_destroy_url(src_url);
                smb2_destroy_context(smb2);
                return 1;
        }

        if (!same_or_null(src_url->domain, dst_url->domain) ||
            !same_or_null(src_url->server, dst_url->server) ||
            !same_or_null(src_url->share, dst_url->share) ||
            !same_or_null(src_url->user, dst_url->user)) {
                fprintf(stderr, "Source and destination URLs must use the same domain, server, share, and user\n");
                rc = 1;
                goto out;
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (smb2_connect_share(smb2, src_url->server, src_url->share, src_url->user) != 0) {
                fprintf(stderr, "smb2_connect_share failed. %s\n",
                        smb2_get_error(smb2));
                rc = 10;
                goto out;
        }

        srcfh = smb2_open(smb2, src_url->path, O_RDONLY);
        if (srcfh == NULL) {
                fprintf(stderr, "Failed to open source file. %s\n",
                        smb2_get_error(smb2));
                rc = 10;
                goto out_disconnect;
        }

        if (smb2_fstat(smb2, srcfh, &st) < 0) {
                fprintf(stderr, "smb2_fstat failed. %s\n", smb2_get_error(smb2));
                rc = 10;
                goto out_close_src;
        }

        dstfh = smb2_open(smb2, dst_url->path, O_RDWR | O_CREAT | O_TRUNC);
        if (dstfh == NULL) {
                fprintf(stderr, "Failed to open destination file. %s\n",
                        smb2_get_error(smb2));
                rc = 10;
                goto out_close_src;
        }

        if (smb2_request_resume_key(smb2, srcfh, &resume_key) < 0) {
                fprintf(stderr, "smb2_request_resume_key failed. %s\n",
                        smb2_get_error(smb2));
                rc = 10;
                goto out_close_dst;
        }

        if (st.smb2_size == 0) {
                printf("Copied 0 bytes\n");
                goto out_close_dst;
        }

        remaining = st.smb2_size;
        while (remaining > 0) {
                uint64_t batch_offset = copied;

                memset(chunks, 0, sizeof(chunks));
                memset(&reply, 0, sizeof(reply));

                batch_count = 0;
                for (i = 0;
                     i < MAX_COPYCHUNKS_PER_REQUEST && remaining > 0;
                     i++) {
                        uint32_t chunk_size = COPYCHUNK_SIZE;

                        if (remaining < COPYCHUNK_SIZE) {
                                chunk_size = (uint32_t)remaining;
                        }

                        chunks[i].source_offset = copied;
                        chunks[i].target_offset = copied;
                        chunks[i].length = chunk_size;

                        copied += chunk_size;
                        remaining -= chunk_size;
                        batch_count++;
                }

                if (smb2_copychunk(smb2,
                                   SMB2_FSCTL_SRV_COPYCHUNK_WRITE,
                                   &resume_key, dstfh, chunks,
                                   batch_count, &reply) < 0) {
                        fprintf(stderr,
                                "smb2_copychunk failed at offset %" PRIu64 ". %s\n",
                                batch_offset, smb2_get_error(smb2));
                        rc = 10;
                        goto out_close_dst;
                }
        }

        printf("Copied %" PRIu64 " bytes\n", st.smb2_size);
        printf("Last request chunks written:%" PRIu32 "\n",
               reply.chunks_written);
        printf("Last request chunk bytes written:%" PRIu32 "\n",
               reply.chunk_bytes_written);
        printf("Last request total bytes written:%" PRIu32 "\n",
               reply.total_bytes_written);

out_close_dst:
        smb2_close(smb2, dstfh);
out_close_src:
        smb2_close(smb2, srcfh);
out_disconnect:
        smb2_disconnect_share(smb2);
out:
        smb2_destroy_url(dst_url);
        smb2_destroy_url(src_url);
        smb2_destroy_context(smb2);

        return rc;
}
