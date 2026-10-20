/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Load dcerpcd config via dcerpc_read_yaml_file() and config.idl coders.
 *
 * The decoded CONFIG structure is kept as-is for the process lifetime
 * (strings point into the YAML mem-tree). Free with dcerpcd_config_free()
 * at shutdown.
 *
 * File format (see config.idl / config.example):
 *   CONFIG:
 *     port: 445
 *     krb5: 1
 *     keytab: /etc/krb5.keytab
 *     hostname: fileserver
 *     domain: EXAMPLE.COM
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"

#include <dcerpc/dcerpc.h>

#include "dcerpcd.h"

/* Built-in defaults when the config file is absent or path is empty. */
static dcerpcd_config g_defaults = {
        .port = DEFAULT_PORT,
        .krb5 = 1,              /* Kerberos on unless config says 0 */
        .keytab = NULL,
        .hostname = NULL,
        .domain = NULL,
        .svc_group = NULL,      /* control socket open to every local user */
};

static dcerpcd_config *g_config = &g_defaults;
static int g_config_from_yaml;  /* 1 ⇒ g_config is a dcerpc_free_data() root */

int
dcerpcd_config_load(const char *path)
{
        dcerpcd_config *cfg;

        /* Replace any previous YAML root with defaults first. */
        dcerpcd_config_free();

        if (path == NULL || path[0] == '\0') {
                return 0;
        }

        /* Optional file: missing path keeps defaults. */
        if (access(path, R_OK) != 0) {
                if (errno == ENOENT) {
                        return 0;
                }
                fprintf(stderr, "config: open %s: %s\n", path, strerror(errno));
                return -1;
        }

        cfg = dcerpc_read_yaml_file(path, config_CONFIG_coder,
                                    sizeof(dcerpcd_config));
        if (cfg == NULL) {
                fprintf(stderr, "config: failed to decode YAML from %s\n",
                        path);
                return -1;
        }

        g_config = cfg;
        g_config_from_yaml = 1;
        return 0;
}

const dcerpcd_config *
dcerpcd_config_get(void)
{
        return g_config;
}

void
dcerpcd_config_free(void)
{
        if (g_config_from_yaml && g_config != NULL) {
                dcerpc_free_data(NULL, g_config);
        }
        g_config = &g_defaults;
        g_config_from_yaml = 0;
}
