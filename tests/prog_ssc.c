/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 Rida Shamasneh

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

#define DEFAULT_CHUNK_SIZE (1024 * 1024)
#define DEFAULT_MAX_CHUNKS 16

enum copy_api {
        API_COPYCHUNK,
        API_SERVER_SIDE_COPY,
};

enum copy_mode {
        MODE_SYNC,
        MODE_ASYNC,
};

struct async_state {
        int done;
        int status;
        void *ptr;
};

int usage(void)
{
        fprintf(stderr,
                "Usage:\n"
                "prog_ssc <copychunk|server-side-copy> <sync|async> "
                "<copychunk|copychunk_write|0xhex> <source-url> <destination-url> "
                "[chunk-size] [max-chunks-per-request] [start-offset] [length]\n\n"
                "Examples:\n"
                "  prog_ssc server-side-copy sync copychunk_write \\\n"
                "    smb://user@host/share/src.bin smb://user@host/share/dst.bin\n"
                "  prog_ssc copychunk async copychunk \\\n"
                "    smb://user@host/share/src.bin smb://user@host/share/dst.bin 1048576 17\n");
        exit(1);
}

static int same_or_null(const char *a, const char *b)
{
        if (a == NULL || b == NULL) {
                return a == b;
        }

        return strcmp(a, b) == 0;
}

static int wait_for_reply(struct smb2_context *smb2, struct async_state *state)
{
        while (!state->done) {
                struct pollfd pfd;

                memset(&pfd, 0, sizeof(pfd));
                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);

                if (poll(&pfd, 1, 1000) < 0) {
                        smb2_set_error(smb2, "Poll failed");
                        return -1;
                }
                if (pfd.revents == 0) {
                        continue;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        return -1;
                }
        }

        return state->status;
}

static void copy_cb(struct smb2_context *smb2 _U_, int status,
                    void *command_data, void *private_data)
{
        struct async_state *state = private_data;

        state->done = 1;
        state->status = status;
        state->ptr = command_data;
}

static int parse_ctl_code(const char *arg, uint32_t *ctl_code)
{
        char *endptr = NULL;
        unsigned long value;

        if (!strcmp(arg, "copychunk")) {
            *ctl_code = SMB2_FSCTL_SRV_COPYCHUNK;
            return 0;
        }
        if (!strcmp(arg, "copychunk_write")) {
            *ctl_code = SMB2_FSCTL_SRV_COPYCHUNK_WRITE;
            return 0;
        }

        errno = 0;
        value = strtoul(arg, &endptr, 0);
        if (errno != 0 || endptr == arg || *endptr != '\0' ||
            value > UINT32_MAX) {
                return -1;
        }

        *ctl_code = (uint32_t)value;
        return 0;
}

static int parse_u32(const char *arg, uint32_t *value)
{
        char *endptr = NULL;
        unsigned long parsed;

        errno = 0;
        parsed = strtoul(arg, &endptr, 0);
        if (errno != 0 || endptr == arg || *endptr != '\0' ||
            parsed > UINT32_MAX) {
                return -1;
        }

        *value = (uint32_t)parsed;
        return 0;
}

static int parse_u64(const char *arg, uint64_t *value)
{
        char *endptr = NULL;
        unsigned long long parsed;

        errno = 0;
        parsed = strtoull(arg, &endptr, 0);
        if (errno != 0 || endptr == arg || *endptr != '\0') {
                return -1;
        }

        *value = (uint64_t)parsed;
        return 0;
}

static uint32_t build_batch(struct smb2_srv_copychunk *chunks,
                            uint64_t start_offset, uint64_t remaining,
                            uint32_t chunk_size, uint32_t max_chunks,
                            uint64_t *batch_bytes)
{
        uint32_t count = 0;
        uint64_t offset = start_offset;
        uint64_t total = 0;

        while (count < max_chunks && remaining > 0) {
                uint32_t length = chunk_size;

                if (remaining < length) {
                        length = (uint32_t)remaining;
                }

                chunks[count].source_offset = offset;
                chunks[count].target_offset = offset;
                chunks[count].length = length;
                chunks[count].reserved = 0;

                offset += length;
                remaining -= length;
                total += length;
                count++;
        }

        *batch_bytes = total;
        return count;
}

static int run_copychunk_async(struct smb2_context *smb2, uint32_t ctl_code,
                               const struct smb2_srv_copychunk_resume_key *resume_key,
                               struct smb2fh *dstfh,
                               const struct smb2_srv_copychunk *chunks,
                               uint32_t chunk_count,
                               struct smb2_srv_copychunk_reply *reply)
{
        struct async_state state;
        int rc;

        memset(&state, 0, sizeof(state));

        rc = smb2_copychunk_async(smb2, ctl_code, resume_key, dstfh, chunks,
                                  chunk_count, copy_cb, &state);
        if (rc < 0) {
                return rc;
        }

        rc = wait_for_reply(smb2, &state);
        if (state.ptr != NULL) {
                if (reply != NULL) {
                        memcpy(reply, state.ptr, sizeof(*reply));
                }
                smb2_free_data(smb2, state.ptr);
        }

        return rc;
}

static int run_server_side_copy_async(struct smb2_context *smb2,
                                      uint32_t ctl_code,
                                      struct smb2fh *srcfh,
                                      struct smb2fh *dstfh,
                                      const struct smb2_srv_copychunk *chunks,
                                      uint32_t chunk_count,
                                      struct smb2_srv_copychunk_reply *reply)
{
        struct async_state state;
        int rc;

        memset(&state, 0, sizeof(state));

        rc = smb2_server_side_copy_async(smb2, ctl_code, srcfh, dstfh, chunks,
                                         chunk_count, copy_cb, &state);
        if (rc < 0) {
                return rc;
        }

        rc = wait_for_reply(smb2, &state);
        if (state.ptr != NULL) {
                if (reply != NULL) {
                        memcpy(reply, state.ptr, sizeof(*reply));
                }
                smb2_free_data(smb2, state.ptr);
        }

        return rc;
}

int main(int argc, char *argv[])
{
        enum copy_api api;
        enum copy_mode mode;
        struct smb2_context *smb2;
        struct smb2_url *src_url;
        struct smb2_url *dst_url;
        struct smb2fh *srcfh = NULL;
        struct smb2fh *dstfh = NULL;
        struct smb2_stat_64 st;
        struct smb2_srv_copychunk_resume_key resume_key;
        struct smb2_srv_copychunk_reply reply;
        struct smb2_srv_copychunk *chunks = NULL;
        uint32_t ctl_code;
        uint32_t chunk_size = DEFAULT_CHUNK_SIZE;
        uint32_t max_chunks = DEFAULT_MAX_CHUNKS;
        uint64_t start_offset = 0;
        uint64_t requested_length = 0;
        uint64_t offset;
        uint64_t remaining;
        int rc = 1;

        if (argc < 6 || argc > 10) {
                usage();
        }

        if (!strcmp(argv[1], "copychunk")) {
                api = API_COPYCHUNK;
        } else if (!strcmp(argv[1], "server-side-copy")) {
                api = API_SERVER_SIDE_COPY;
        } else {
                usage();
        }

        if (!strcmp(argv[2], "sync")) {
                mode = MODE_SYNC;
        } else if (!strcmp(argv[2], "async")) {
                mode = MODE_ASYNC;
        } else {
                usage();
        }

        if (parse_ctl_code(argv[3], &ctl_code) != 0) {
                fprintf(stderr, "Invalid ctl_code: %s\n", argv[3]);
                return 1;
        }
        if (argc > 6 && parse_u32(argv[6], &chunk_size) != 0) {
                fprintf(stderr, "Invalid chunk-size: %s\n", argv[6]);
                return 1;
        }
        if (argc > 7 && parse_u32(argv[7], &max_chunks) != 0) {
                fprintf(stderr, "Invalid max-chunks-per-request: %s\n", argv[7]);
                return 1;
        }
        if (argc > 8 && parse_u64(argv[8], &start_offset) != 0) {
                fprintf(stderr, "Invalid start-offset: %s\n", argv[8]);
                return 1;
        }
        if (argc > 9 && parse_u64(argv[9], &requested_length) != 0) {
                fprintf(stderr, "Invalid length: %s\n", argv[9]);
                return 1;
        }
        if (chunk_size == 0 || max_chunks == 0) {
                fprintf(stderr, "chunk-size and max-chunks-per-request must be non-zero\n");
                return 1;
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                return 1;
        }

        src_url = smb2_parse_url(smb2, argv[4]);
        if (src_url == NULL) {
                fprintf(stderr, "Failed to parse source url: %s\n",
                        smb2_get_error(smb2));
                smb2_destroy_context(smb2);
                return 1;
        }

        dst_url = smb2_parse_url(smb2, argv[5]);
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
                fprintf(stderr,
                        "Source and destination URLs must use the same domain, server, share, and user\n");
                goto out;
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
        if (smb2_connect_share(smb2, src_url->server, src_url->share,
                               src_url->user) != 0) {
                fprintf(stderr, "smb2_connect_share failed. %s\n",
                        smb2_get_error(smb2));
                goto out;
        }

        srcfh = smb2_open(smb2, src_url->path, O_RDONLY);
        if (srcfh == NULL) {
                fprintf(stderr, "Failed to open source file. %s\n",
                        smb2_get_error(smb2));
                goto out_disconnect;
        }

        if (smb2_fstat(smb2, srcfh, &st) < 0) {
                fprintf(stderr, "smb2_fstat failed. %s\n", smb2_get_error(smb2));
                goto out_close_src;
        }

        if (start_offset > st.smb2_size) {
                fprintf(stderr, "start-offset is beyond end of source file\n");
                goto out_close_src;
        }

        /*
         * If source and destination name the same file (e.g. to provoke a
         * server-side rejection of overlapping copy ranges within a single
         * file), opening the destination with O_TRUNC would truncate the
         * file out from under the already-open source handle before any
         * copy is attempted. The file already exists (we just fstat'd it
         * through srcfh), so just reopen it for read/write.
         */
        if (!strcmp(src_url->path, dst_url->path)) {
                dstfh = smb2_open(smb2, dst_url->path, O_RDWR);
        } else {
                dstfh = smb2_open(smb2, dst_url->path, O_RDWR | O_CREAT | O_TRUNC);
        }
        if (dstfh == NULL) {
                fprintf(stderr, "Failed to open destination file. %s\n",
                        smb2_get_error(smb2));
                goto out_close_src;
        }

        remaining = st.smb2_size - start_offset;
        if (requested_length > 0 && requested_length < remaining) {
                remaining = requested_length;
        }
        offset = start_offset;

        chunks = calloc(max_chunks, sizeof(*chunks));
        if (chunks == NULL) {
                fprintf(stderr, "Failed to allocate chunk array\n");
                goto out_close_dst;
        }

        if (api == API_COPYCHUNK) {
                if (smb2_request_resume_key(smb2, srcfh, &resume_key) < 0) {
                        fprintf(stderr, "smb2_request_resume_key failed. %s\n",
                                smb2_get_error(smb2));
                        goto out_free_chunks;
                }
        }

        while (remaining > 0) {
                uint64_t batch_bytes;
                uint32_t batch_count;
                int op_rc;

                memset(chunks, 0, max_chunks * sizeof(*chunks));
                memset(&reply, 0, sizeof(reply));

                batch_count = build_batch(chunks, offset, remaining, chunk_size,
                                          max_chunks, &batch_bytes);
                if (batch_count == 0) {
                        fprintf(stderr, "Failed to build chunk batch\n");
                        goto out_free_chunks;
                }

                if (api == API_COPYCHUNK) {
                        if (mode == MODE_SYNC) {
                                op_rc = smb2_copychunk(smb2, ctl_code,
                                                       &resume_key, dstfh,
                                                       chunks, batch_count,
                                                       &reply);
                        } else {
                                op_rc = run_copychunk_async(smb2, ctl_code,
                                                            &resume_key, dstfh,
                                                            chunks, batch_count,
                                                            &reply);
                        }
                } else {
                        if (mode == MODE_SYNC) {
                                op_rc = smb2_server_side_copy(smb2, ctl_code,
                                                              srcfh, dstfh,
                                                              chunks,
                                                              batch_count,
                                                              &reply);
                        } else {
                                op_rc = run_server_side_copy_async(smb2,
                                                                   ctl_code,
                                                                   srcfh, dstfh,
                                                                   chunks,
                                                                   batch_count,
                                                                   &reply);
                        }
                }

                printf("offset=%" PRIu64 " chunks=%" PRIu32 " bytes=%" PRIu64
                       " status=%d reply={chunks=%" PRIu32
                       ",chunk_bytes=%" PRIu32 ",total_bytes=%" PRIu32 "}\n",
                       offset, batch_count, batch_bytes, op_rc,
                       reply.chunks_written, reply.chunk_bytes_written,
                       reply.total_bytes_written);

                if (op_rc < 0) {
                        fprintf(stderr, "copy operation failed. %s\n",
                                smb2_get_error(smb2));
                        goto out_free_chunks;
                }

                offset += batch_bytes;
                remaining -= batch_bytes;
        }

        printf("Copied %" PRIu64 " bytes using %s/%s ctl=0x%08" PRIx32 "\n",
               offset - start_offset,
               api == API_COPYCHUNK ? "copychunk" : "server-side-copy",
               mode == MODE_SYNC ? "sync" : "async", ctl_code);
        rc = 0;

out_free_chunks:
        free(chunks);
out_close_dst:
        if (dstfh != NULL) {
                smb2_close(smb2, dstfh);
        }
out_close_src:
        if (srcfh != NULL) {
                smb2_close(smb2, srcfh);
        }
out_disconnect:
        smb2_disconnect_share(smb2);
out:
        smb2_destroy_url(dst_url);
        smb2_destroy_url(src_url);
        smb2_destroy_context(smb2);
        return rc;
}
