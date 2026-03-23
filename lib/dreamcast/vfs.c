// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Samba (SMB) virtual file-system for KallistiOS
 *
 * Copyright (C) 2026 Paul Cercueil <paul@crapouillou.net>
 */

#include <errno.h>
#include <kos.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>

#include "vfs.h"

static mutex_t lock = MUTEX_INITIALIZER;

static struct smb2_context *cxt;
static struct smb2_url *smb_url;

struct smb_fd {
	bool is_dir;
	void *hdl;
	dirent_t dirent[];
};

static void * smb_open(vfs_handler_t *vfs, const char *fn, int mode)
{
	struct smb_fd *fd;
	size_t size = sizeof(*fd);

	mutex_lock_scoped(&lock);

	if (mode & O_DIR)
		size += sizeof(dirent_t);

	fd = malloc(size);
	if (!fd)
		return NULL;

	fd->is_dir = mode & O_DIR;

	if (fd->is_dir)
		fd->hdl = smb2_opendir(cxt, fn);
	else
		fd->hdl = smb2_open(cxt, fn, mode);
	if (!fd->hdl) {
		dbglog(DBG_WARNING, "smb: Unable to open %s: %s\n", fn, smb2_get_error(cxt));
		free(fd);
		return NULL;
	}

	return fd;
}

static int smb_close(void *hnd)
{
	struct smb_fd *fd = hnd;

	mutex_lock_scoped(&lock);

	if (fd->is_dir)
		smb2_closedir(cxt, fd->hdl);
	else
		smb2_close(cxt, fd->hdl);
	free(fd);

	return 0;
}

static ssize_t smb_read(void *hnd, void *buffer, size_t cnt)
{
	struct smb_fd *fd = hnd;
	ssize_t ret;

	mutex_lock_scoped(&lock);

	ret = smb2_read(cxt, fd->hdl, buffer, cnt);
	if (ret < 0)
		dbglog(DBG_WARNING, "smb: Unable to read: %s\n", smb2_get_error(cxt));

	return ret;
}

static ssize_t smb_write(void *hnd, const void *buffer, size_t cnt)
{
	struct smb_fd *fd = hnd;
	ssize_t ret;

	mutex_lock_scoped(&lock);

	ret = smb2_write(cxt, fd->hdl, buffer, cnt);
	if (ret < 0)
		dbglog(DBG_WARNING, "smb: Unable to write: %s\n", smb2_get_error(cxt));

	return ret;
}

static const dirent_t *smb_readdir(void *hnd)
{
	const struct smb2dirent *dir;
	struct smb_fd *fd = hnd;

	mutex_lock_scoped(&lock);

	dir = smb2_readdir(cxt, fd->hdl);
	if (!dir) {
		dbglog(DBG_WARNING, "smb: Unable to readdir: %s\n", smb2_get_error(cxt));
		return NULL;
	}

	fd->dirent[0].size = dir->st.smb2_size;
	strncpy(fd->dirent[0].name, dir->name, NAME_MAX - 1);
	fd->dirent[0].attr = 0;
	fd->dirent[0].time = 0;

	return fd->dirent;
}

static int smb_rename(struct vfs_handler *vfs, const char *fn1, const char *fn2)
{
	mutex_lock_scoped(&lock);

	return smb2_rename(cxt, fn1, fn2);
}

static int smb_unlink(struct vfs_handler *vfs, const char *path)
{
	mutex_lock_scoped(&lock);

	return smb2_unlink(cxt, path);
}

static void smb2_stat_convert(struct stat *buf, const struct smb2_stat_64 *st)
{
	memset(buf, 0, sizeof(*buf));
	buf->st_ino = st->smb2_ino;
	buf->st_nlink = st->smb2_nlink;
	buf->st_size = st->smb2_size;
	buf->st_atime = st->smb2_atime;
	buf->st_mtime = st->smb2_mtime;
	buf->st_ctime = st->smb2_ctime;

	if (st->smb2_type == SMB2_TYPE_FILE)
		buf->st_mode = S_IFREG;
	else if (st->smb2_type == SMB2_TYPE_DIRECTORY)
		buf->st_mode = S_IFDIR;
	else
		buf->st_mode = S_IFLNK;
}

static int smb_stat(struct vfs_handler *vfs, const char *path,
		    struct stat *buf, int flag)
{
	struct smb2_stat_64 st;
	int ret;

	mutex_lock_scoped(&lock);

	ret = smb2_stat(cxt, path, &st);
	if (ret) {
		dbglog(DBG_WARNING, "smb: Unable to stat: %s\n", smb2_get_error(cxt));
		return ret;
	}

	smb2_stat_convert(buf, &st);

	return 0;
}

static int smb_mkdir(struct vfs_handler *vfs, const char *fn)
{
	mutex_lock_scoped(&lock);

	return smb2_mkdir(cxt, fn);
}

static int smb_rmdir(struct vfs_handler *vfs, const char *fn)
{
	mutex_lock_scoped(&lock);

	return smb2_rmdir(cxt, fn);
}

static _off64_t smb_seek64(void *hnd, _off64_t offset, int whence)
{
	struct smb_fd *fd = hnd;
	_off64_t ret;

	mutex_lock_scoped(&lock);

	ret = smb2_lseek(cxt, fd->hdl, offset, whence, NULL);
	if (ret < 0)
		dbglog(DBG_WARNING, "smb: Unable to seek: %s\n", smb2_get_error(cxt));

	return ret;
}

static _off64_t smb_tell64(void *hnd)
{
	struct smb_fd *fd = hnd;
	_off64_t ret;
	uint64_t curr;

	mutex_lock_scoped(&lock);

	ret = smb2_lseek(cxt, fd->hdl, 0, SEEK_CUR, &curr);
	if (ret < 0) {
		dbglog(DBG_WARNING, "smb: Unable to tell: %s\n", smb2_get_error(cxt));
		return ret;
	}

	return (_off64_t)curr;
}

static ssize_t smb_readlink(struct vfs_handler *vfs, const char *path,
			    char *buf, size_t bufsize)
{
	mutex_lock_scoped(&lock);

	return smb2_readlink(cxt, path, buf, bufsize);
}

static int smb_rewinddir(void *hnd)
{
	struct smb_fd *fd = hnd;

	mutex_lock_scoped(&lock);

	smb2_rewinddir(cxt, fd->hdl);
	return 0;
}

static int smb_fstat(void *hnd, struct stat *buf)
{
	struct smb_fd *fd = hnd;
	struct smb2_stat_64 st;
	int ret;

	mutex_lock_scoped(&lock);

	ret = smb2_fstat(cxt, fd->hdl, &st);
	if (ret) {
		dbglog(DBG_WARNING, "smb: Unable to fstat: %s\n", smb2_get_error(cxt));
		return ret;
	}

	smb2_stat_convert(buf, &st);

	return 0;
}

static vfs_handler_t vh = {
	.nmmgr = {
		"/smb",
		0,
		0x00010000,
		0,
		NMMGR_TYPE_VFS,
		NMMGR_LIST_INIT
	},
	.cache = 1,

	.open = smb_open,
	.close = smb_close,
	.read = smb_read,
	.write = smb_write,

	.readdir = smb_readdir,

	.rename = smb_rename,
	.unlink = smb_unlink,

	.stat = smb_stat,

	.mkdir = smb_mkdir,
	.rmdir = smb_rmdir,

	.seek64 = smb_seek64,
	.tell64 = smb_tell64,

	.readlink = smb_readlink,
	.rewinddir = smb_rewinddir,

	.fstat = smb_fstat,
};

int kos_smb_init(const char *url)
{
	int ret;

	cxt = smb2_init_context();
	if (!cxt) {
		dbglog(DBG_WARNING, "smb: Unable to init libsmb2\n");
		return -EIO;
	}

	smb_url = smb2_parse_url(cxt, url);
	if (!smb_url) {
		dbglog(DBG_WARNING, "smb: Could not parse SMB URL: %s\n", smb2_get_error(cxt));
		smb2_close_context(cxt);
		return -EINVAL;
	}

	ret = smb2_connect_share(cxt, smb_url->server,
				 smb_url->share,
				 smb_url->user);
	if (ret) {
		dbglog(DBG_WARNING, "smb: Could not connect to SMB share: %d\n", ret);
		smb2_destroy_url(smb_url);
		smb2_close_context(cxt);
		return ret;
	}

	dbglog(DBG_NOTICE, "smb: Connected to %s\n", url);

	nmmgr_handler_add(&vh.nmmgr);

	return 0;
}

void kos_smb_shutdown(void)
{
	nmmgr_handler_remove(&vh.nmmgr);

	smb2_disconnect_share(cxt);
	smb2_destroy_url(smb_url);
	smb2_close_context(cxt);
}
