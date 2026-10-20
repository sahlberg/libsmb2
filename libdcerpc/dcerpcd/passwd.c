/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Load the dcerpcd YAML passwd file via dcerpc_read_yaml_file() and
 * passwd.idl coders.
 *
 * The decoded PASSWD structure is kept as-is for the process lifetime
 * (strings and entry[] live in the YAML mem-tree). Free with
 * dcerpcd_passwd_free() at shutdown.
 *
 * File format (see passwd.idl / passwd.example):
 *   PASSWD:
 *     count: 2
 *     entry:
 *       - user: alice
 *         password: secret
 *       - user: bob
 *         password: none
 *
 */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"

#include <dcerpc/dcerpc.h>

#include "dcerpcd.h"

/* Decoded PASSWD root; NULL until a successful load. */
static dcerpcd_passwd *g_passwd;

/*
 * Validate path is a regular file owned by this process euid with mode 0600.
 * Opens with O_NOFOLLOW so a symlink cannot swap in another file after the
 * check. Returns an open fd on success, or -1 after printing an error.
 */
static int
passwd_open_secure(const char *path)
{
        struct stat st;
        int fd;

        fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd < 0) {
                fprintf(stderr, "passwd: open %s: %s\n", path, strerror(errno));
                return -1;
        }
        if (fstat(fd, &st) != 0) {
                fprintf(stderr, "passwd: fstat %s: %s\n", path, strerror(errno));
                close(fd);
                return -1;
        }
        if (!S_ISREG(st.st_mode)) {
                fprintf(stderr, "passwd: %s is not a regular file\n", path);
                close(fd);
                return -1;
        }
        if (st.st_uid != geteuid()) {
                fprintf(stderr,
                        "passwd: %s owner uid %u does not match process euid %u\n",
                        path, (unsigned)st.st_uid, (unsigned)geteuid());
                close(fd);
                return -1;
        }
        if ((st.st_mode & 0777) != 0600) {
                fprintf(stderr,
                        "passwd: %s has mode %04o, expected 0600\n",
                        path, (unsigned)(st.st_mode & 0777));
                close(fd);
                return -1;
        }
        return fd;
}

int
dcerpcd_passwd_load(const char *path)
{
        dcerpcd_passwd *db;
        int fd;
        uint32_t i;

        /* Replace any previous YAML root first. */
        dcerpcd_passwd_free();

        if (path == NULL || path[0] == '\0') {
                return -1;
        }

        /*
         * Security check first. We close the fd before read_yaml_file reopens
         * the path; TOCTOU is accepted for this local config path (same as
         * most daemons that re-open after a permission probe). O_NOFOLLOW on
         * the probe still blocks symlink games at check time.
         */
        fd = passwd_open_secure(path);
        if (fd < 0) {
                return -1;
        }
        close(fd);

        db = dcerpc_read_yaml_file(path, passwd_PASSWD_coder,
                                   sizeof(dcerpcd_passwd));
        if (db == NULL) {
                fprintf(stderr, "passwd: failed to decode YAML from %s\n",
                        path);
                return -1;
        }
        if (db->count == 0 || db->entry == NULL) {
                fprintf(stderr, "passwd: no user entries in %s\n", path);
                dcerpc_free_data(NULL, db);
                return -1;
        }

        /*
         * An empty or missing password would let NTLM authenticate with
         * no password at all. YAML makes one easy to get by accident:
         * everything from a '#' is a comment, so quote such a password.
         */
        for (i = 0; i < db->count; i++) {
                if (db->entry[i].user == NULL ||
                    db->entry[i].user[0] == '\0' ||
                    db->entry[i].password == NULL ||
                    db->entry[i].password[0] == '\0') {
                        fprintf(stderr, "passwd: entry %u in %s has no "
                                "user or no password\n", i, path);
                        dcerpc_free_data(NULL, db);
                        return -1;
                }
        }

        g_passwd = db;

        printf("passwd: loaded %u user(s) from %s\n", db->count, path);
        for (i = 0; i < db->count; i++) {
                printf("passwd:   user=%s\n",
                       db->entry[i].user ? db->entry[i].user : "(null)");
        }
        return 0;
}

const dcerpcd_passwd *
dcerpcd_passwd_get(void)
{
        return g_passwd;
}

void
dcerpcd_passwd_free(void)
{
        if (g_passwd != NULL) {
                dcerpc_free_data(NULL, g_passwd);
                g_passwd = NULL;
        }
}

const dcerpcd_user *
dcerpcd_passwd_find(const dcerpcd_passwd *db, const char *user)
{
        uint32_t i;

        if (db == NULL || user == NULL || db->entry == NULL) {
                return NULL;
        }
        for (i = 0; i < db->count; i++) {
                if (db->entry[i].user &&
                    strcasecmp(db->entry[i].user, user) == 0) {
                        return &db->entry[i];
                }
        }
        return NULL;
}
