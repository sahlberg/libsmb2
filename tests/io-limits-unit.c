/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "../lib/compat.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

static void done(struct smb2_context *smb2 _U_, int status _U_,
                 void *result _U_, void *data _U_)
{
}

static void check_length(enum smb2_command command, uint32_t limit,
                         int credits, uint32_t requested, uint32_t expected)
{
        struct smb2_context *smb2 = smb2_init_context();
        smb2_file_id id = {1};
        struct smb2fh *fh;
        struct smb2_pdu *pdu;
        const uint8_t *wire;
        uint8_t *buf = calloc(requested ? requested : 1, 1);
        uint32_t length;
        int rc;

        assert(smb2 && buf);
        assert(!smb2_connect_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        smb2->max_read_size = limit;
        smb2->max_write_size = limit;
        smb2->dialect = SMB2_VERSION_0311;
        smb2->supports_multi_credit = 1;
        smb2->credits = credits;
        if (command == SMB2_READ) {
                rc = smb2_pread_async(smb2, fh, buf, requested, 0, done, NULL);
        } else {
                rc = smb2_pwrite_async(smb2, fh, buf, requested, 0, done, NULL);
        }
        assert(rc == 0);
        pdu = smb2->outqueue;
        assert(pdu && pdu->header.command == command && pdu->out.iov[1].len >= 8);
        wire = pdu->out.iov[1].buf + 4;
        length = wire[0] | ((uint32_t)wire[1] << 8) |
                 ((uint32_t)wire[2] << 16) | ((uint32_t)wire[3] << 24);
        assert(length == expected);

        smb2_destroy_context(smb2);
        free(buf);
}

int main(void)
{
        const enum smb2_command commands[] = {SMB2_READ, SMB2_WRITE};
        size_t i;

        for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
                check_length(commands[i], 0, 2, 4096, 4096);
                check_length(commands[i], 1024, 2, 4096, 1024);
                check_length(commands[i], 0, 0, 131072, 65536);
        }
        return 0;
}
