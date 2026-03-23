/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Samba (SMB) virtual file-system for KallistiOS
 *
 * Copyright (C) 2026 Paul Cercueil <paul@crapouillou.net>
 */

#ifndef __KOS_SMB_VFS_H__
#define __KOS_SMB_VFS_H__

int kos_smb_init(const char *url);

void kos_smb_shutdown(void);

#endif /* __KOS_SMB_VFS_H__ */
