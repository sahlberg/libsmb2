/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * axpy service stubs (hand-maintained after idlcomp --stubs skeleton).
 *
 * Defines axpy_stubs[] (dispatch table) and the *_stub implementations.
 * The table is not in the generated coder so clients can link coders only.
 *
 * Config is loaded into axpy_config via axpy_init() / freed via axpy_exit().
 * GCC constructor/destructor attributes run those automatically around
 * main() (before serviced registers with dcerpcd, and on process exit).
 *
 * Re-running idlcomp with --stubs will refuse to overwrite this file
 * unless --force-stubs is also given.
 */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "axpy_server.h"
#include "config_coder.h"

/* Default path when axpy_init(NULL) / AXPY_CONFIG is unset. */
#define AXPY_DEFAULT_CONFIG "config"

/*
 * Process-lifetime CONFIG root from config.idl / YAML.
 * Strings (prefix) point into the dcerpc mem-tree; free only via axpy_exit()
 * or by replacing with another successful axpy_init().
 * NULL until axpy_init() succeeds.
 */
struct config_CONFIG *axpy_config;

int
axpy_compute_stub(struct dcerpc_context *dce,
                  struct dcerpc_pdu *pdu,
                  void *reqv, void *repv)
{
        struct axpy_compute_req *req = reqv;
        struct axpy_compute_rep *rep = repv;
        const char *prefix;
        char *buf;
        int n;

        (void)dce;

        if (req == NULL || rep == NULL || pdu == NULL) {
                return -1;
        }
        memset(rep, 0, sizeof(*rep));

        if (axpy_config == NULL) {
                fprintf(stderr, "axpy: compute: config not loaded\n");
                return -1;
        }

        /* BLAS AXPY: y := a*x + y (uint32 wrap is fine for this example). */
        rep->y = axpy_config->a * req->x + req->y;
        prefix = axpy_config->prefix ? axpy_config->prefix : "";

        buf = dcerpc_alloc_data(pdu, 128);
        if (buf == NULL) {
                return -1;
        }

        switch (axpy_config->base) {
        case CONFIG_BASE_HEX:
                n = snprintf(buf, 128, "%s0x%x", prefix, rep->y);
                break;
        case CONFIG_BASE_OCT:
                n = snprintf(buf, 128, "%s0%o", prefix, rep->y);
                break;
        case CONFIG_BASE_DEC:
        default:
                n = snprintf(buf, 128, "%s%u", prefix, rep->y);
                break;
        }
        if (n < 0 || n >= 128) {
                return -1;
        }

        rep->result = buf;
        rep->status = 0; /* WERROR / NERR_Success */

        printf("axpy: compute a=%u x=%u y=%u → y=%u \"%s\"\n",
               axpy_config->a, req->x, req->y, rep->y, rep->result);
        return 0;
}

/*
 * Stub dispatch table (server only). Keep next to the implementations;
 * regenerating the coder must not reintroduce this into axpy_coder.c.
 */
struct dcerpc_stub axpy_stubs[] = {
        {AXPY_COMPUTE, "compute", axpy_compute_stub},
        {-1, NULL, NULL}
};

/* ------------------------------------------------------------------ */
/* Config load / free and process lifetime hooks (after stubs)        */
/* ------------------------------------------------------------------ */

/*
 * Load CONFIG YAML into axpy_config.
 *
 * path may be NULL or empty → use $AXPY_CONFIG if set, else "config".
 * Replaces any previous config (frees the old mem-tree).
 * Returns 0 on success, -1 on error (axpy_config left NULL).
 */
int
axpy_init(const char *path)
{
        struct config_CONFIG *cfg;
        const char *env;

        if (path == NULL || path[0] == '\0') {
                env = getenv("AXPY_CONFIG");
                if (env != NULL && env[0] != '\0') {
                        path = env;
                } else {
                        path = AXPY_DEFAULT_CONFIG;
                }
        }

        if (access(path, R_OK) != 0) {
                fprintf(stderr, "axpy: config %s: %s\n", path, strerror(errno));
                return -1;
        }

        cfg = dcerpc_read_yaml_file(path, config_CONFIG_coder,
                                    sizeof(struct config_CONFIG));
        if (cfg == NULL) {
                fprintf(stderr, "axpy: failed to decode CONFIG from %s\n",
                        path);
                return -1;
        }

        if (axpy_config != NULL) {
                dcerpc_free_data(NULL, axpy_config);
                axpy_config = NULL;
        }
        axpy_config = cfg;

        printf("axpy: loaded config from %s (a=%u base=%d prefix=\"%s\")\n",
               path,
               axpy_config->a,
               (int)axpy_config->base,
               axpy_config->prefix ? axpy_config->prefix : "");
        return 0;
}

/*
 * Free the CONFIG mem-tree held in axpy_config.
 * Safe to call more than once; leaves axpy_config NULL.
 */
void
axpy_exit(void)
{
        if (axpy_config != NULL) {
                dcerpc_free_data(NULL, axpy_config);
                axpy_config = NULL;
        }
}

/*
 * axpy_init() is serviced's SERVICE_INIT, called with -c's path before it
 * registers; free the config when the process ends (GCC/clang).
 */
static void __attribute__((destructor))
axpy_dtor(void)
{
        axpy_exit();
}
