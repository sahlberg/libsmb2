/* SPDX-License-Identifier: LGPL-2.1-or-later */
#undef NDEBUG
#include <assert.h>

/* Drive the synchronous wrappers without a server or a real poll timeout. */
#define smb2_stat_async capture_stat
#define smb2_fstat_async capture_fstat
#define smb2_statvfs_async capture_statvfs
#define smb2_timeout_pdus unexpected_timeout
#define smb2_finish_dispatch unexpected_finish_dispatch
#define smb2_file_io_length unexpected_file_io_length
#define smb2_start_file_io unexpected_start_file_io
#define poll fail_poll
#include "../lib/sync.c"

static void *submitted_result, *completion_data;
static smb2_command_cb completion;
static int complete_without_data;

int fail_poll(struct pollfd *fds _U_, nfds_t n _U_, int timeout _U_)
{
        errno = EIO;
        return -1;
}

int unexpected_timeout(struct smb2_context *smb2 _U_)
{
        abort();
}

void unexpected_finish_dispatch(struct smb2_context *smb2 _U_)
{
        abort();
}

uint32_t unexpected_file_io_length(struct smb2_context *smb2 _U_,
                                   enum smb2_command command _U_, uint32_t count _U_)
{
        abort();
}

int unexpected_start_file_io(struct smb2_context *smb2 _U_, struct smb2fh *fh _U_,
                             enum smb2_command command _U_, void *buf _U_,
                             uint32_t count _U_, uint64_t offset _U_, int positioned _U_,
                             smb2_command_cb cb _U_, void *data _U_)
{
        abort();
}

static int capture(void *result, smb2_command_cb cb, void *data)
{
        submitted_result = result;
        completion = cb;
        completion_data = data;
        return 0;
}

int capture_stat(struct smb2_context *smb2, const char *path _U_,
                 struct smb2_stat_64 *st, smb2_command_cb cb, void *data)
{
        if (complete_without_data) {
                cb(smb2, 0, st, data);
                return 0;
        }
        return capture(st, cb, data);
}

int capture_fstat(struct smb2_context *smb2 _U_, struct smb2fh *fh _U_,
                  struct smb2_stat_64 *st, smb2_command_cb cb, void *data)
{
        return capture(st, cb, data);
}

int capture_statvfs(struct smb2_context *smb2 _U_, const char *path _U_,
                    struct smb2_statvfs *st, smb2_command_cb cb, void *data)
{
        return capture(st, cb, data);
}

static void finish_late(struct smb2_context *smb2, void *caller_result, size_t size)
{
        assert(completion && submitted_result && submitted_result != caller_result);
        memset(submitted_result, 0xa5, size);
        completion(smb2, 0, submitted_result, completion_data);
        completion = NULL;
}

int main(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        struct smb2_stat_64 file = {0};
        struct smb2_statvfs fs = {0};

        assert(smb2);
        smb2_set_timeout(smb2, 0);
        file.smb2_size = 42;
        fs.f_bsize = 4096;
        assert(smb2_stat(smb2, "file", &file) < 0);
        finish_late(smb2, &file, sizeof(file));
        assert(file.smb2_size == 42);
        assert(smb2_fstat(smb2, NULL, &file) < 0);
        finish_late(smb2, &file, sizeof(file));
        assert(file.smb2_size == 42);
        assert(smb2_statvfs(smb2, "", &fs) < 0);
        finish_late(smb2, &fs, sizeof(fs));
        assert(fs.f_bsize == 4096);

        /* The async status mapping can report success without writing data. */
        complete_without_data = 1;
        assert(smb2_stat(smb2, "file", &file) == 0);
        assert(file.smb2_size == 42);
        smb2_destroy_context(smb2);
        return 0;
}
