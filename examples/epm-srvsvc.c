/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Query the DCE/RPC endpoint mapper for all endpoints registered for
 * the Server Service (srvsvc).
 *
 * Connects to IPC$/epmapper over SMB2, then calls ept_Lookup with
 * RPC_C_EP_MATCH_BY_IF for the srvsvc interface UUID.
 *
 * Usage:
 *   epm-srvsvc <smb2-url>
 *   epm-srvsvc smb://[[domain;]user@]host/
 */

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-epm.h>

#define MAX_ENTS 64

static int is_finished;
static int total_printed;
static struct dcerpc_context_handle entry_handle;
static int have_entry_handle;

static int usage(void)
{
        fprintf(stderr,
                "Usage:\n"
                "  epm-srvsvc <smb2-url>\n\n"
                "URL format: smb://[<domain>;][<username>@]<host>[:<port>]/\n\n"
                "Connects to IPC$/epmapper on the host and lists all endpoints\n"
                "registered for the srvsvc interface\n"
                "(4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0).\n");
        exit(1);
}

static void
print_uuid(const dcerpc_uuid_t *u)
{
        printf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               u->v1, u->v2, u->v3,
               u->v4[0], u->v4[1],
               u->v4[2], u->v4[3], u->v4[4], u->v4[5], u->v4[6], u->v4[7]);
}

static void
print_tower(const struct epm_twr_t *twr)
{
        char *pipe = NULL, *host = NULL, *ipv4 = NULL;
        uint16_t port = 0;

        if (epm_tower_get_ncacn_np(twr, &pipe, &host) == 0) {
                printf("    transport: ncacn_np\n");
                printf("    pipe:      %s\n", pipe ? pipe : "");
                printf("    host:      %s\n", host ? host : "");
                free(pipe);
                free(host);
                return;
        }
        if (epm_tower_get_ncacn_ip_tcp(twr, &ipv4, &port) == 0) {
                printf("    transport: ncacn_ip_tcp\n");
                printf("    address:   %s\n", ipv4 ? ipv4 : "");
                printf("    port:      %u\n", (unsigned)port);
                free(ipv4);
                return;
        }
        printf("    transport: (unrecognized tower, %u octets)\n",
               twr->tower_length);
}

static int
handle_is_null(const struct dcerpc_context_handle *h)
{
        int i;

        if (h->context_handle_attributes != 0) {
                return 0;
        }
        if (h->context_handle_uuid.v1 || h->context_handle_uuid.v2 ||
            h->context_handle_uuid.v3) {
                return 0;
        }
        for (i = 0; i < 8; i++) {
                if (h->context_handle_uuid.v4[i]) {
                        return 0;
                }
        }
        return 1;
}

static void lookup_cb(struct dcerpc_context *dce, int status,
                      void *command_data, void *cb_data);

static void
free_handle_cb(struct dcerpc_context *dce, int status,
               void *command_data, void *cb_data)
{
        struct epm_LookupHandleFree_rep *rep = command_data;

        (void)status;
        (void)cb_data;
        if (rep) {
                dcerpc_free_data(dce, rep);
        }
        is_finished = 1;
}

static void
finish_or_free_handle(struct dcerpc_context *dce)
{
        struct epm_LookupHandleFree_req free_req;

        if (!have_entry_handle || handle_is_null(&entry_handle)) {
                is_finished = 1;
                return;
        }

        memset(&free_req, 0, sizeof(free_req));
        free_req.entry_handle = entry_handle;
        if (dcerpc_call_async(dce, EPM_LOOKUP_HANDLE_FREE,
                              epm_LookupHandleFree_req_coder, &free_req,
                              epm_LookupHandleFree_rep_coder,
                              sizeof(struct epm_LookupHandleFree_rep),
                              free_handle_cb, NULL) != 0) {
                fprintf(stderr, "LookupHandleFree failed: %s\n",
                        dcerpc_get_error(dce));
                is_finished = 1;
        }
}

static int
send_lookup(struct dcerpc_context *dce)
{
        struct epm_Lookup_req req;

        memset(&req, 0, sizeof(req));
        req.inquiry_type = RPC_C_EP_MATCH_BY_IF;
        req.object_null = 1;
        req.interface_id.uuid = srvsvc_interface.uuid;
        req.interface_id.vers_major = srvsvc_interface.vers;
        req.interface_id.vers_minor = srvsvc_interface.vers_minor;
        req.interface_id_null = 0;
        req.vers_option = RPC_C_VERS_ALL;
        req.max_ents = MAX_ENTS;
        if (have_entry_handle) {
                req.entry_handle = entry_handle;
        }

        if (dcerpc_call_async(dce, EPM_LOOKUP,
                              epm_Lookup_req_coder, &req,
                              epm_Lookup_rep_coder,
                              sizeof(struct epm_Lookup_rep),
                              lookup_cb, NULL) != 0) {
                fprintf(stderr, "ept_Lookup failed: %s\n",
                        dcerpc_get_error(dce));
                return -1;
        }
        return 0;
}

static void
lookup_cb(struct dcerpc_context *dce, int status,
          void *command_data, void *cb_data)
{
        struct epm_Lookup_rep *rep = command_data;
        uint32_t i;

        (void)cb_data;

        if (status) {
                if (rep) {
                        dcerpc_free_data(dce, rep);
                }
                fprintf(stderr, "ept_Lookup failed (%s) %s\n",
                        strerror(-status), dcerpc_get_error(dce));
                is_finished = 1;
                return;
        }

        if (rep->status != EPMAPPER_STATUS_OK &&
            rep->status != EPMAPPER_STATUS_NO_MORE_ENTRIES) {
                fprintf(stderr, "ept_Lookup status 0x%08x\n", rep->status);
                dcerpc_free_data(dce, rep);
                finish_or_free_handle(dce);
                return;
        }

        entry_handle = rep->entry_handle;
        have_entry_handle = 1;

        for (i = 0; i < rep->num_ents; i++) {
                struct epm_entry_t *e = &rep->entries[i];

                total_printed++;
                printf("Endpoint %d\n", total_printed);
                printf("  object:     ");
                print_uuid(&e->object);
                printf("\n");
                printf("  annotation: %s\n",
                       e->annotation ? e->annotation : "");
                if (!e->tower_null && e->tower.tower_octet_string) {
                        print_tower(&e->tower);
                } else {
                        printf("    tower:     (null)\n");
                }
                printf("\n");
        }

        /* More entries available? */
        if (rep->num_ents == MAX_ENTS &&
            rep->status == EPMAPPER_STATUS_OK &&
            !handle_is_null(&rep->entry_handle)) {
                dcerpc_free_data(dce, rep);
                if (send_lookup(dce) != 0) {
                        is_finished = 1;
                }
                return;
        }

        dcerpc_free_data(dce, rep);
        finish_or_free_handle(dce);
}

static void
bind_cb(struct dcerpc_context *dce, int status,
        void *command_data, void *cb_data)
{
        (void)command_data;
        (void)cb_data;

        if (status != SMB2_STATUS_SUCCESS) {
                fprintf(stderr, "Failed to bind epmapper: %s\n",
                        dcerpc_get_error(dce));
                is_finished = 1;
                return;
        }

        printf("srvsvc interface: ");
        print_uuid(&srvsvc_interface.uuid);
        printf(" v%u.%u\n\n",
               (unsigned)srvsvc_interface.vers,
               (unsigned)srvsvc_interface.vers_minor);

        if (send_lookup(dce) != 0) {
                is_finished = 1;
        }
}

int
main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct dcerpc_context *dce;
        struct smb2_url *url;
        struct pollfd pfd;

        if (argc < 2) {
                usage();
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init smb2 context\n");
                return 1;
        }

        url = smb2_parse_url(smb2, argv[1]);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(smb2));
                smb2_destroy_context(smb2);
                return 1;
        }
        if (url->user) {
                smb2_set_user(smb2, url->user);
        }
        if (url->domain) {
                smb2_set_domain(smb2, url->domain);
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

        if (smb2_connect_share(smb2, url->server, "IPC$", NULL) < 0) {
                fprintf(stderr, "Failed to connect to IPC$: %s\n",
                        smb2_get_error(smb2));
                smb2_destroy_url(url);
                smb2_destroy_context(smb2);
                return 1;
        }

        dce = dcerpc_create_context(smb2);
        if (dce == NULL) {
                fprintf(stderr, "Failed to create dce context: %s\n",
                        smb2_get_error(smb2));
                smb2_disconnect_share(smb2);
                smb2_destroy_url(url);
                smb2_destroy_context(smb2);
                return 1;
        }

        if (dcerpc_connect_context_async(dce, "epmapper", &epm_interface,
                                         bind_cb, NULL) != 0) {
                fprintf(stderr, "Failed to open epmapper: %s\n",
                        dcerpc_get_error(dce));
                dcerpc_destroy_context(dce);
                smb2_disconnect_share(smb2);
                smb2_destroy_url(url);
                smb2_destroy_context(smb2);
                return 1;
        }

        while (!is_finished) {
                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);

                if (poll(&pfd, 1, 1000) < 0) {
                        fprintf(stderr, "poll failed\n");
                        break;
                }
                if (pfd.revents == 0) {
                        continue;
                }
                if (smb2_service(smb2, pfd.revents) < 0) {
                        fprintf(stderr, "smb2_service failed: %s\n",
                                smb2_get_error(smb2));
                        break;
                }
        }

        if (total_printed == 0) {
                printf("No endpoints found for srvsvc.\n");
        } else {
                printf("Total: %d endpoint(s)\n", total_printed);
        }

        dcerpc_destroy_context(dce);
        smb2_disconnect_share(smb2);
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);

        return 0;
}
