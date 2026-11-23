/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "smb2.h"
#include "libsmb2.h"

struct completion {
        int calls;
        int status;
        uint64_t offset;
};

static void read_done(struct smb2_context *smb2 _U_, int status, void *data, void *priv)
{
        struct completion *c = priv;
        struct smb2_read_cb_data *read = data;

        c->calls++;
        c->status = status;
        c->offset = read->offset;
}

static void write_done(struct smb2_context *smb2 _U_, int status, void *data, void *priv)
{
        struct completion *c = priv;
        struct smb2_write_cb_data *write = data;

        c->calls++;
        c->status = status;
        c->offset = write->offset;
}

static int completed(struct completion *c, int status, uint64_t offset)
{
        return c->calls == 1 && c->status == status && c->offset == offset;
}

static int check_io(struct smb2_context *smb2, const char *path)
{
        /* Cleanup in main can deliver callbacks after an early return. */
        static struct completion w[3], r[3];
        static const uint8_t first[] = "AAAA", second[] = "BBBB", patch[] = "CC";
        static uint8_t buf[18];
        struct smb2fh *fh = smb2_open(smb2, path, O_RDWR | O_CREAT | O_TRUNC);

        if (!fh ||
            smb2_write_async(smb2, fh, first, 4, write_done, &w[0]) ||
            smb2_write_async(smb2, fh, second, 4, write_done, &w[1]) ||
            smb2_lseek(smb2, fh, 2, SEEK_SET, NULL) != 2 ||
            smb2_write_async(smb2, fh, patch, 2, write_done, &w[2]) ||
            smb2_fsync(smb2, fh) || smb2_close(smb2, fh)) {
                return -1;
        }
        if (!completed(&w[0], 4, 0) || !completed(&w[1], 4, 4) || !completed(&w[2], 2, 2)) {
                return -1;
        }
        fh = smb2_open(smb2, path, O_RDONLY);
        if (!fh || smb2_lseek(smb2, fh, 1, SEEK_SET, NULL) != 1 ||
            smb2_lseek(smb2, fh, -9, SEEK_END, NULL) != -EINVAL ||
            smb2_lseek(smb2, fh, 0, SEEK_CUR, NULL) != 1 ||
            smb2_lseek(smb2, fh, INT64_MAX, SEEK_END, NULL) != -EINVAL ||
            smb2_lseek(smb2, fh, 0, SEEK_SET, NULL) != 0 ||
            smb2_read_async(smb2, fh, buf, 6, read_done, &r[0]) ||
            smb2_read_async(smb2, fh, buf + 6, 6, read_done, &r[1]) ||
            smb2_read_async(smb2, fh, buf + 12, 6, read_done, &r[2]) ||
            smb2_close(smb2, fh)) {
                return -1;
        }
        if (!completed(&r[0], 6, 0) || !completed(&r[1], 2, 6) ||
            !completed(&r[2], 0, 8) || memcmp(buf, "AACCBBBB", 8)) {
                return -1;
        }
        fh = smb2_open(smb2, path, O_RDWR);
        if (!fh || smb2_write_async(smb2, fh, first, 4, write_done, &w[0]) ||
            smb2_write_async(smb2, fh, second, 4, write_done, &w[1]) ||
            smb2_ftruncate(smb2, fh, 2) || smb2_close(smb2, fh)) {
                return -1;
        }
        {
                struct smb2_stat_64 st;
                return !smb2_stat(smb2, path, &st) && st.smb2_size == 2 ? 0 : -1;
        }
}

int main(int argc, char **argv)
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        int rc = -1;

        if (argc != 2 || (smb2 = smb2_init_context()) == NULL) {
                return 1;
        }
        url = smb2_parse_url(smb2, argv[1]);
        if (url && url->domain) {
                smb2_set_domain(smb2, url->domain);
        }
        smb2_set_timeout(smb2, 10);
        if (url && !smb2_connect_share(smb2, url->server, url->share, url->user)) {
                rc = check_io(smb2, url->path);
                smb2_unlink(smb2, url->path);
                smb2_disconnect_share(smb2);
        }
        if (rc) {
                fprintf(stderr, "Sequential file I/O check failed: %s\n", smb2_get_error(smb2));
        }
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);
        return rc != 0;
}
