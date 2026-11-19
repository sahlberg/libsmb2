/* SPDX-License-Identifier: LGPL-2.1-or-later */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "smb2.h"
#include "libsmb2.h"

int main(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        smb2_file_id id = {1};
        struct smb2fh *fh;
        uint64_t position = 99;

        assert(smb2);
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh && smb2_lseek(smb2, fh, 1, SEEK_SET, NULL) == 1);
        assert(smb2_lseek(smb2, fh, -1, SEEK_END, &position) == -EINVAL);
        assert(position == 99);
        assert(smb2_lseek(smb2, fh, INT64_MAX, SEEK_CUR, &position) == -EINVAL);
        assert(position == 99 && smb2_lseek(smb2, fh, 0, SEEK_CUR, &position) == 1);
        assert(position == 1);
        assert(smb2_lseek(smb2, fh, INT64_MAX, SEEK_SET, NULL) == INT64_MAX);
        assert(smb2_lseek(smb2, fh, INT64_MIN, SEEK_CUR, NULL) == -EINVAL);
        assert(smb2_lseek(smb2, fh, -INT64_MAX, SEEK_CUR, NULL) == 0);
        smb2_destroy_context(smb2);
        return 0;
}
