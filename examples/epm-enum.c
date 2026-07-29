/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Dump every endpoint registered with the DCE/RPC endpoint mapper.
 *
 * Connects to IPC$/epmapper over SMB2, then calls ept_Lookup with
 * RPC_C_EP_ALL_ELTS.
 *
 * Usage:
 *   epm-enum <smb2-url>
 *   epm-enum smb://[[domain;]user@]host/
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

/* Well-known interface UUIDs for a friendly name when annotation is empty */
struct known_if {
        const char *name;
        dcerpc_uuid_t uuid;
        uint16_t vers;
        uint16_t vers_minor;
};

static const struct known_if known_ifs[] = {
        { "srvsvc",
          { 0x4b324fc8, 0x1670, 0x01d3,
            { 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 } }, 3, 0 },
        { "lsarpc",
          { 0x12345778, 0x1234, 0xabcd,
            { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab } }, 0, 0 },
        { "wkssvc",
          { 0x6bffd098, 0xa112, 0x3610,
            { 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a } }, 1, 0 },
        { "winreg",
          { 0x338cd001, 0x2244, 0x31f1,
            { 0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03 } }, 1, 0 },
        { "epmapper",
          { 0xe1af8308, 0x5d1f, 0x11c9,
            { 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa } }, 3, 0 },
        { "samr",
          { 0x12345778, 0x1234, 0xabcd,
            { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac } }, 1, 0 },
        { "netlogon",
          { 0x12345678, 0x1234, 0xabcd,
            { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb } }, 1, 0 },
        { "spoolss",
          { 0x12345678, 0x1234, 0xabcd,
            { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab } }, 1, 0 },
        { "svcctl",
          { 0x367abb81, 0x9844, 0x35f1,
            { 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03 } }, 2, 0 },
        { "atsvc",
          { 0x1ff70682, 0x0a51, 0x30e8,
            { 0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce, 0xe9, 0x8b } }, 1, 0 },
        { "eventlog",
          { 0x82273fdc, 0xe32a, 0x18c3,
            { 0x3f, 0x78, 0x82, 0x79, 0x29, 0xdc, 0x23, 0xea } }, 0, 0 },
        { "browser",
          { 0x6bffd098, 0xa112, 0x3610,
            { 0x98, 0x33, 0x01, 0x28, 0x92, 0x02, 0x01, 0x62 } }, 0, 0 },
        { "IObjectExporter",
          { 0x99fcfec4, 0x5260, 0x101b,
            { 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a } }, 0, 0 },
        { "ISystemActivator",
          { 0x000001a0, 0x0000, 0x0000,
            { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } }, 0, 0 },
        { NULL, { 0, 0, 0, { 0 } }, 0, 0 }
};

static int usage(void)
{
        fprintf(stderr,
                "Usage:\n"
                "  epm-enum <smb2-url>\n\n"
                "URL format: smb://[<domain>;][<username>@]<host>[:<port>]/\n\n"
                "Connects to IPC$/epmapper and lists every registered endpoint\n"
                "(ept_Lookup RPC_C_EP_ALL_ELTS).\n");
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

static int
uuid_equal(const dcerpc_uuid_t *a, const dcerpc_uuid_t *b)
{
        return a->v1 == b->v1 && a->v2 == b->v2 && a->v3 == b->v3 &&
               !memcmp(a->v4, b->v4, 8);
}

static const char *
lookup_if_name(const dcerpc_uuid_t *uuid, uint16_t maj, uint16_t min)
{
        const struct known_if *k;

        (void)maj;
        (void)min;
        for (k = known_ifs; k->name; k++) {
                if (uuid_equal(uuid, &k->uuid)) {
                        return k->name;
                }
        }
        return NULL;
}

static uint16_t
get_le16(const uint8_t *p)
{
        return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
get_le32(const uint8_t *p)
{
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * Parse tower floor 0 (interface UUID + version). Layout matches
 * epm_write_floor_uuid in dcerpc-epm.c.
 */
static int
tower_get_interface(const struct epm_twr_t *twr,
                    dcerpc_uuid_t *uuid, uint16_t *maj, uint16_t *min)
{
        const uint8_t *data;
        uint32_t len;
        uint16_t nfloors, lh, rh;
        uint32_t o;

        if (twr == NULL || twr->tower_octet_string == NULL ||
            twr->tower_length < 2) {
                return -1;
        }
        data = twr->tower_octet_string;
        len = twr->tower_length;
        nfloors = get_le16(data);
        if (nfloors < 1) {
                return -1;
        }
        o = 2;
        if (o + 2 > len) {
                return -1;
        }
        lh = get_le16(data + o);
        o += 2;
        if (o + lh + 2 > len || lh < 19) {
                return -1;
        }
        /* lhs: proto(1) + uuid(16) + major(2) */
        if (data[o] != EPM_PROTOCOL_UUID) {
                return -1;
        }
        uuid->v1 = get_le32(data + o + 1);
        uuid->v2 = get_le16(data + o + 5);
        uuid->v3 = get_le16(data + o + 7);
        memcpy(uuid->v4, data + o + 9, 8);
        if (maj) {
                *maj = get_le16(data + o + 17);
        }
        o += lh;
        rh = get_le16(data + o);
        o += 2;
        if (o + rh > len || rh < 2) {
                return -1;
        }
        if (min) {
                *min = get_le16(data + o);
        }
        return 0;
}

static void
print_tower(const struct epm_twr_t *twr)
{
        char *pipe = NULL, *host = NULL, *ipv4 = NULL;
        uint16_t port = 0;

        if (epm_tower_get_ncacn_np(twr, &pipe, &host) == 0) {
                printf("  transport:  ncacn_np\n");
                printf("  pipe:       %s\n", pipe ? pipe : "");
                if (host && host[0]) {
                        printf("  host:       %s\n", host);
                }
                free(pipe);
                free(host);
                return;
        }
        if (epm_tower_get_ncacn_ip_tcp(twr, &ipv4, &port) == 0) {
                printf("  transport:  ncacn_ip_tcp\n");
                printf("  address:    %s\n", ipv4 ? ipv4 : "");
                printf("  port:       %u\n", (unsigned)port);
                free(ipv4);
                return;
        }
        printf("  transport:  (unrecognized tower, %u octets)\n",
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
        req.inquiry_type = RPC_C_EP_ALL_ELTS;
        req.object_null = 1;
        req.interface_id_null = 1;
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
print_entry(const struct epm_entry_t *e)
{
        dcerpc_uuid_t if_uuid;
        uint16_t maj = 0, min = 0;
        const char *name = NULL;

        total_printed++;
        printf("Endpoint %d\n", total_printed);

        if (!e->tower_null && e->tower.tower_octet_string &&
            tower_get_interface(&e->tower, &if_uuid, &maj, &min) == 0) {
                name = lookup_if_name(&if_uuid, maj, min);
                printf("  interface:  ");
                print_uuid(&if_uuid);
                printf(" v%u.%u", (unsigned)maj, (unsigned)min);
                if (name) {
                        printf(" (%s)", name);
                }
                printf("\n");
        }

        printf("  object:     ");
        print_uuid(&e->object);
        printf("\n");
        printf("  annotation: %s\n",
               e->annotation ? e->annotation : "");

        if (!e->tower_null && e->tower.tower_octet_string) {
                print_tower(&e->tower);
        } else {
                printf("  tower:      (null)\n");
        }
        printf("\n");
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
                print_entry(&rep->entries[i]);
        }

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
                printf("No endpoints found.\n");
        } else {
                printf("Total: %d endpoint(s)\n", total_printed);
        }

        dcerpc_destroy_context(dce);
        smb2_disconnect_share(smb2);
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);

        return 0;
}
