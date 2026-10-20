/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Endpoint mapper registry for dcerpcd (ncacn_np / named pipe only).
 * Keeps the list of registered endpoints and implements ept_lookup,
 * ept_map and ept_lookup_handle_free against that list for the named-pipe
 * transport, with libdcerpc's epm coders. Endpoints are registered by
 * dcerpcd itself and by external services over the control socket.
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
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"
#include <dcerpc/dcerpc.h>
#include <dcerpc/epm.h>

#include "dcerpcd.h"

#ifndef _U_
#define _U_ __attribute__((unused))
#endif

/* NDR transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0 */
static const dcerpc_uuid_t ndr_transfer_uuid = {
        0x8a885d04, 0x1ceb, 0x11c9,
        {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
};

struct dcerpcd_ep {
        struct dcerpcd_ep *next;
        dcerpc_uuid_t object;
        dcerpc_uuid_t iface;
        uint16_t vers_major;
        uint16_t vers_minor;
        char *annotation;
        char *pipe;             /* pipe name, e.g. "epmapper" or "\\pipe\\srvsvc" */
        char *host;             /* NetBIOS / host for tower floor (may be "") */
        int owner_fd;           /* >=0: external service UDS fd; -1: builtin */
};

static struct dcerpcd_ep *ep_list;
static uint32_t ep_count;
static char epm_hostname[128];
static pthread_mutex_t epm_lock = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/* UUID helpers                                                        */
/* ------------------------------------------------------------------ */

static int
uuid_is_nil(const dcerpc_uuid_t *u)
{
        int i;

        if (u == NULL) {
                return 1;
        }
        if (u->v1 || u->v2 || u->v3) {
                return 0;
        }
        for (i = 0; i < 8; i++) {
                if (u->v4[i]) {
                        return 0;
                }
        }
        return 1;
}

static int
uuid_equal(const dcerpc_uuid_t *a, const dcerpc_uuid_t *b)
{
        return a->v1 == b->v1 && a->v2 == b->v2 && a->v3 == b->v3 &&
               !memcmp(a->v4, b->v4, 8);
}

static void
uuid_clear(dcerpc_uuid_t *u)
{
        memset(u, 0, sizeof(*u));
}

static int
handle_is_null(const struct dcerpc_context_handle *h)
{
        if (h == NULL) {
                return 1;
        }
        if (h->context_handle_attributes != 0) {
                return 0;
        }
        return uuid_is_nil(&h->context_handle_uuid);
}

/*
 * Encode a resume index in the context handle. attributes holds a magic
 * tag; uuid.v1 holds the next entry index.
 */
#define EPM_HANDLE_MAGIC 0x45504d31  /* 'EPM1' */

static void
handle_set_index(struct dcerpc_context_handle *h, uint32_t index)
{
        memset(h, 0, sizeof(*h));
        if (index == 0) {
                return; /* null handle = start */
        }
        h->context_handle_attributes = EPM_HANDLE_MAGIC;
        h->context_handle_uuid.v1 = index;
}

static uint32_t
handle_get_index(const struct dcerpc_context_handle *h)
{
        if (handle_is_null(h)) {
                return 0;
        }
        if (h->context_handle_attributes != EPM_HANDLE_MAGIC) {
                return 0;
        }
        return h->context_handle_uuid.v1;
}

/* ------------------------------------------------------------------ */
/* Tower building for ncacn_np (with pipe name)                        */
/* ------------------------------------------------------------------ */

static void
put_le16(uint8_t *p, uint16_t v)
{
        p[0] = (uint8_t)(v & 0xff);
        p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void
put_le32(uint8_t *p, uint32_t v)
{
        p[0] = (uint8_t)(v & 0xff);
        p[1] = (uint8_t)((v >> 8) & 0xff);
        p[2] = (uint8_t)((v >> 16) & 0xff);
        p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void
put_uuid(uint8_t *p, const dcerpc_uuid_t *u)
{
        put_le32(p, u->v1);
        put_le16(p + 4, u->v2);
        put_le16(p + 6, u->v3);
        memcpy(p + 8, u->v4, 8);
}

static size_t
write_floor_uuid(uint8_t *p, const dcerpc_uuid_t *u,
                 uint16_t major, uint16_t minor)
{
        put_le16(p, 19);
        p[2] = EPM_PROTOCOL_UUID;
        put_uuid(p + 3, u);
        put_le16(p + 19, major);
        put_le16(p + 21, 2);
        put_le16(p + 23, minor);
        return 25;
}

static size_t
write_floor_proto(uint8_t *p, uint8_t proto, uint16_t rhs_val)
{
        put_le16(p, 1);
        p[2] = proto;
        put_le16(p + 3, 2);
        put_le16(p + 5, rhs_val);
        return 7;
}

static size_t
write_floor_string(uint8_t *p, uint8_t proto, const char *s)
{
        size_t len = s ? strlen(s) + 1 : 1;

        put_le16(p, 1);
        p[2] = proto;
        put_le16(p + 3, (uint16_t)len);
        if (s) {
                memcpy(p + 5, s, len);
        } else {
                p[5] = 0;
        }
        return 5 + len;
}

/*
 * Build a full ncacn_np tower for a registered endpoint:
 *   floors: iface UUID, NDR UUID, NCACN, SMB/pipe name, NetBIOS host
 */
static int
build_np_tower(struct dcerpc_pdu *pdu,
               const dcerpc_uuid_t *iface, uint16_t maj, uint16_t min,
               const char *pipe, const char *host, struct epm_twr_t *out)
{
        size_t pipe_len = pipe ? strlen(pipe) + 1 : 1;
        size_t host_len = host ? strlen(host) + 1 : 1;
        size_t total;
        uint8_t *buf;
        size_t o = 0;

        if (iface == NULL || out == NULL) {
                return -1;
        }
        total = 2 + 25 + 25 + 7 + (5 + pipe_len) + (5 + host_len);
        buf = dcerpc_alloc_data(pdu, total);
        if (buf == NULL) {
                return -1;
        }
        put_le16(buf, 5);
        o = 2;
        o += write_floor_uuid(buf + o, iface, maj, min);
        o += write_floor_uuid(buf + o, &ndr_transfer_uuid, 2, 0);
        o += write_floor_proto(buf + o, EPM_PROTOCOL_NCACN, 0);
        /*
         * Floor 3: named-pipe protocol with the pipe path. Clients accept
         * either EPM_PROTOCOL_SMB or EPM_PROTOCOL_NAMED_PIPE here.
         */
        o += write_floor_string(buf + o, EPM_PROTOCOL_NAMED_PIPE,
                                pipe ? pipe : "");
        o += write_floor_string(buf + o, EPM_PROTOCOL_NETBIOS,
                                host ? host : "");
        out->TowerOctetString = buf;
        out->TowerLength = (uint32_t)o;
        return 0;
}

/* A tower for ep, allocated on pdu */
static struct epm_twr_t *
new_np_tower(struct dcerpc_pdu *pdu, const struct dcerpcd_ep *ep)
{
        struct epm_twr_t *twr = dcerpc_alloc_data(pdu, sizeof(*twr));

        if (twr == NULL) {
                return NULL;
        }
        if (build_np_tower(pdu, &ep->iface, ep->vers_major, ep->vers_minor,
                           ep->pipe, ep->host, twr)) {
                return NULL;
        }
        return twr;
}

static int
tower_get_iface(const struct epm_twr_t *twr,
                dcerpc_uuid_t *uuid, uint16_t *maj, uint16_t *min)
{
        const uint8_t *data;
        uint32_t len, o;
        uint16_t nfloors, lh, rh;

        if (twr == NULL || twr->TowerOctetString == NULL ||
            twr->TowerLength < 2) {
                return -1;
        }
        data = twr->TowerOctetString;
        len = twr->TowerLength;
        nfloors = (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
        if (nfloors < 1) {
                return -1;
        }
        o = 2;
        if (o + 2 > len) {
                return -1;
        }
        lh = (uint16_t)(data[o] | ((uint16_t)data[o + 1] << 8));
        o += 2;
        if (o + lh + 2 > len || lh < 19 || data[o] != EPM_PROTOCOL_UUID) {
                return -1;
        }
        uuid->v1 = (uint32_t)data[o + 1] | ((uint32_t)data[o + 2] << 8) |
                   ((uint32_t)data[o + 3] << 16) | ((uint32_t)data[o + 4] << 24);
        uuid->v2 = (uint16_t)(data[o + 5] | ((uint16_t)data[o + 6] << 8));
        uuid->v3 = (uint16_t)(data[o + 7] | ((uint16_t)data[o + 8] << 8));
        memcpy(uuid->v4, data + o + 9, 8);
        if (maj) {
                *maj = (uint16_t)(data[o + 17] | ((uint16_t)data[o + 18] << 8));
        }
        o += lh;
        rh = (uint16_t)(data[o] | ((uint16_t)data[o + 1] << 8));
        o += 2;
        if (o + rh > len || rh < 2) {
                return -1;
        }
        if (min) {
                *min = (uint16_t)(data[o] | ((uint16_t)data[o + 1] << 8));
        }
        return 0;
}

/* ------------------------------------------------------------------ */
/* Registry                                                            */
/* ------------------------------------------------------------------ */

static void
ep_free(struct dcerpcd_ep *ep)
{
        if (ep == NULL) {
                return;
        }
        free(ep->annotation);
        free(ep->pipe);
        free(ep->host);
        free(ep);
}

/* Must be called with epm_lock held. */
static int
register_np_locked(const dcerpc_uuid_t *iface,
                   uint16_t vers_major, uint16_t vers_minor,
                   const dcerpc_uuid_t *object,
                   const char *pipe,
                   const char *annotation,
                   const char *host,
                   int owner_fd)
{
        struct dcerpcd_ep *ep;

        if (iface == NULL || pipe == NULL || pipe[0] == '\0') {
                return -1;
        }

        ep = calloc(1, sizeof(*ep));
        if (ep == NULL) {
                return -1;
        }
        ep->iface = *iface;
        ep->vers_major = vers_major;
        ep->vers_minor = vers_minor;
        ep->owner_fd = owner_fd;
        if (object) {
                ep->object = *object;
        } else {
                uuid_clear(&ep->object);
        }
        ep->pipe = strdup(pipe);
        ep->annotation = strdup(annotation ? annotation : "");
        ep->host = strdup(host ? host : epm_hostname);
        if (ep->pipe == NULL || ep->annotation == NULL || ep->host == NULL) {
                ep_free(ep);
                return -1;
        }

        ep->next = ep_list;
        ep_list = ep;
        ep_count++;

        printf("epm: register np pipe=%s iface=%08x-%04x-%04x v%u.%u "
               "owner_fd=%d (%s)\n",
               pipe,
               iface->v1, iface->v2, iface->v3,
               (unsigned)vers_major, (unsigned)vers_minor,
               owner_fd,
               annotation ? annotation : "");
        return 0;
}

static int
vers_matches(uint16_t maj, uint16_t min,
             uint16_t want_maj, uint16_t want_min, uint32_t vers_option)
{
        switch (vers_option) {
        case EPM_RPC_C_VERS_ALL:
                return 1;
        case EPM_RPC_C_VERS_COMPATIBLE:
                return maj == want_maj && min >= want_min;
        case EPM_RPC_C_VERS_EXACT:
                return maj == want_maj && min == want_min;
        case EPM_RPC_C_VERS_MAJOR_ONLY:
                return maj == want_maj;
        case EPM_RPC_C_VERS_UPTO:
                if (maj < want_maj) {
                        return 1;
                }
                if (maj == want_maj && min <= want_min) {
                        return 1;
                }
                return 0;
        default:
                return maj == want_maj && min == want_min;
        }
}

static int
ep_matches_lookup(const struct dcerpcd_ep *ep, const struct epm_Lookup_req *req)
{
        const struct epm_rpc_if_id *ifid = req->InterfaceId;

        switch (req->InquiryType) {
        case EPM_RPC_C_EP_ALL_ELTS:
                return 1;
        case EPM_RPC_C_EP_MATCH_BY_IF:
                if (ifid == NULL) {
                        return 1;
                }
                if (!uuid_equal(&ep->iface, &ifid->Uuid)) {
                        return 0;
                }
                return vers_matches(ep->vers_major, ep->vers_minor,
                                    ifid->VersMajor, ifid->VersMinor,
                                    req->VersOption);
        case EPM_RPC_C_EP_MATCH_BY_OBJ:
                if (req->Object == NULL) {
                        return 1;
                }
                return uuid_equal(&ep->object, req->Object);
        case EPM_RPC_C_EP_MATCH_BY_BOTH:
                if (req->Object != NULL &&
                    !uuid_equal(&ep->object, req->Object)) {
                        return 0;
                }
                if (ifid != NULL) {
                        if (!uuid_equal(&ep->iface, &ifid->Uuid)) {
                                return 0;
                        }
                        if (!vers_matches(ep->vers_major, ep->vers_minor,
                                          ifid->VersMajor, ifid->VersMinor,
                                          req->VersOption)) {
                                return 0;
                        }
                }
                return 1;
        default:
                return 0;
        }
}

static int
fill_epm_entry(struct dcerpc_pdu *pdu, const struct dcerpcd_ep *ep,
               struct epm_entry_t *out)
{
        const char *annotation = ep->annotation ? ep->annotation : "";

        memset(out, 0, sizeof(*out));
        out->Object = ep->object;
        out->Annotation = dcerpc_alloc_data(pdu, strlen(annotation) + 1);
        if (out->Annotation == NULL) {
                return -1;
        }
        strcpy(out->Annotation, annotation);
        out->Tower = new_np_tower(pdu, ep);
        if (out->Tower == NULL) {
                return -1;
        }
        return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int
dcerpcd_epm_init(const char *hostname)
{
        dcerpc_uuid_t epm_uuid = epm_interface.uuid;

        pthread_mutex_lock(&epm_lock);
        ep_list = NULL;
        ep_count = 0;
        if (hostname && hostname[0]) {
                strncpy(epm_hostname, hostname, sizeof(epm_hostname) - 1);
        } else {
                if (gethostname(epm_hostname, sizeof(epm_hostname)) != 0) {
                        strncpy(epm_hostname, "dcerpcd",
                                sizeof(epm_hostname) - 1);
                }
        }
        epm_hostname[sizeof(epm_hostname) - 1] = '\0';
        pthread_mutex_unlock(&epm_lock);

        /*
         * Always register the endpoint mapper itself on \pipe\epmapper so
         * clients can discover at least this interface via ept_Lookup.
         */
        if (dcerpcd_epm_register_np(&epm_uuid, epm_interface.vers,
                                    epm_interface.vers_minor,
                                    NULL,
                                    "\\pipe\\epmapper",
                                    "Endpoint Mapper",
                                    epm_hostname,
                                    -1)) {
                fprintf(stderr, "epm: failed to register epmapper pipe\n");
                return -1;
        }
        printf("epm: registered ncacn_np endpoint mapper on \\\\pipe\\\\epmapper "
               "(%u endpoint(s))\n", dcerpcd_epm_count());
        return 0;
}

void
dcerpcd_epm_shutdown(void)
{
        struct dcerpcd_ep *ep;

        pthread_mutex_lock(&epm_lock);
        while (ep_list) {
                ep = ep_list;
                ep_list = ep->next;
                ep_free(ep);
        }
        ep_count = 0;
        pthread_mutex_unlock(&epm_lock);
}

int
dcerpcd_epm_register_np(const dcerpc_uuid_t *iface,
                        uint16_t vers_major, uint16_t vers_minor,
                        const dcerpc_uuid_t *object,
                        const char *pipe,
                        const char *annotation,
                        const char *host,
                        int owner_fd)
{
        int rc;

        pthread_mutex_lock(&epm_lock);
        rc = register_np_locked(iface, vers_major, vers_minor, object,
                                pipe, annotation, host, owner_fd);
        pthread_mutex_unlock(&epm_lock);
        return rc;
}

void
dcerpcd_epm_unregister_by_owner(int owner_fd)
{
        struct dcerpcd_ep **pp;
        struct dcerpcd_ep *ep;
        int removed = 0;

        if (owner_fd < 0) {
                return;
        }

        pthread_mutex_lock(&epm_lock);
        pp = &ep_list;
        while (*pp) {
                ep = *pp;
                if (ep->owner_fd == owner_fd) {
                        *pp = ep->next;
                        printf("epm: unregister np pipe=%s owner_fd=%d\n",
                               ep->pipe ? ep->pipe : "?", owner_fd);
                        ep_free(ep);
                        if (ep_count) {
                                ep_count--;
                        }
                        removed++;
                        continue;
                }
                pp = &ep->next;
        }
        pthread_mutex_unlock(&epm_lock);

        if (removed) {
                printf("epm: removed %d endpoint(s) for owner_fd=%d (%u left)\n",
                       removed, owner_fd, dcerpcd_epm_count());
        }
}

uint32_t
dcerpcd_epm_count(void)
{
        uint32_t n;

        pthread_mutex_lock(&epm_lock);
        n = ep_count;
        pthread_mutex_unlock(&epm_lock);
        return n;
}

/* ------------------------------------------------------------------ */
/* EPM procedure handlers                                              */
/* ------------------------------------------------------------------ */

int
dcerpcd_epm_Lookup(struct dcerpc_pdu *pdu, const struct epm_Lookup_req *req,
                   struct epm_Lookup_rep *rep)
{
        struct dcerpcd_ep *ep;
        uint32_t start;
        uint32_t nmatch;
        uint32_t max_ents;
        struct epm_entry_t *out = NULL;
        uint32_t filled = 0;

        if (req == NULL || rep == NULL) {
                return -1;
        }
        memset(rep, 0, sizeof(*rep));
        max_ents = req->MaxEnts ? req->MaxEnts : 1;
        start = handle_get_index(&req->EntryHandle);

        pthread_mutex_lock(&epm_lock);

        /* Count matches after start, and collect up to max_ents */
        nmatch = 0;
        for (ep = ep_list; ep; ep = ep->next) {
                if (!ep_matches_lookup(ep, req)) {
                        continue;
                }
                nmatch++;
        }

        if (nmatch <= start) {
                handle_set_index(&rep->EntryHandle, 0);
                rep->NumEnts = 0;
                rep->Entries = NULL;
                rep->status = EPM_STATUS_NO_MORE_ENTRIES;
                pthread_mutex_unlock(&epm_lock);
                return 0;
        }

        /*
         * MaxEnts is the client's: never allocate for more entries than
         * there are to return.
         */
        if (max_ents > nmatch - start) {
                max_ents = nmatch - start;
        }
        out = dcerpc_alloc_data(pdu, (size_t)max_ents * sizeof(*out));
        if (out == NULL) {
                rep->status = EPM_STATUS_NO_MEMORY;
                pthread_mutex_unlock(&epm_lock);
                return 0;
        }

        nmatch = 0;
        filled = 0;
        for (ep = ep_list; ep && filled < max_ents; ep = ep->next) {
                if (!ep_matches_lookup(ep, req)) {
                        continue;
                }
                if (nmatch < start) {
                        nmatch++;
                        continue;
                }
                if (fill_epm_entry(pdu, ep, &out[filled]) != 0) {
                        rep->status = EPM_STATUS_NO_MEMORY;
                        pthread_mutex_unlock(&epm_lock);
                        return 0;
                }
                filled++;
                nmatch++;
        }

        /* More remaining? */
        {
                uint32_t total_match = 0;

                for (ep = ep_list; ep; ep = ep->next) {
                        if (ep_matches_lookup(ep, req)) {
                                total_match++;
                        }
                }
                if (start + filled < total_match) {
                        handle_set_index(&rep->EntryHandle, start + filled);
                        rep->status = EPM_STATUS_OK;
                } else {
                        handle_set_index(&rep->EntryHandle, 0);
                        rep->status = EPM_STATUS_OK;
                }
        }

        rep->NumEnts = filled;
        rep->Entries = out;
        pthread_mutex_unlock(&epm_lock);
        return 0;
}

int
dcerpcd_epm_Map(struct dcerpc_pdu *pdu, const struct epm_Map_req *req,
                struct epm_Map_rep *rep)
{
        dcerpc_uuid_t iface;
        uint16_t maj = 0, min = 0;
        struct dcerpcd_ep *ep;
        uint32_t start;
        uint32_t max_towers;
        uint32_t filled = 0;
        uint32_t nmatch = 0;
        struct epm_twr_t **towers = NULL;

        if (req == NULL || rep == NULL) {
                return -1;
        }
        memset(rep, 0, sizeof(*rep));
        max_towers = req->MaxTowers ? req->MaxTowers : 1;

        if (req->MapTower == NULL || req->MapTower->TowerOctetString == NULL) {
                rep->status = EPM_STATUS_CANT_PERFORM_OP;
                return 0;
        }
        if (tower_get_iface(req->MapTower, &iface, &maj, &min) != 0) {
                rep->status = EPM_STATUS_CANT_PERFORM_OP;
                return 0;
        }

        /* Map only matches named-pipe registered endpoints for this iface */
        start = handle_get_index(&req->EntryHandle);

        pthread_mutex_lock(&epm_lock);

        for (ep = ep_list; ep; ep = ep->next) {
                if (!uuid_equal(&ep->iface, &iface)) {
                        continue;
                }
                /* Compatible version: same major, minor >= requested */
                if (ep->vers_major != maj || ep->vers_minor < min) {
                        continue;
                }
                if (req->Object != NULL &&
                    !uuid_equal(&ep->object, req->Object) &&
                    !uuid_is_nil(req->Object)) {
                        continue;
                }
                nmatch++;
        }

        if (nmatch <= start) {
                handle_set_index(&rep->EntryHandle, 0);
                rep->NumTowers = 0;
                rep->status = EPM_STATUS_NO_MORE_ENTRIES;
                pthread_mutex_unlock(&epm_lock);
                return 0;
        }

        /* As in Lookup: no more than there are to return */
        if (max_towers > nmatch - start) {
                max_towers = nmatch - start;
        }
        towers = dcerpc_alloc_data(pdu, (size_t)max_towers * sizeof(*towers));
        if (towers == NULL) {
                rep->status = EPM_STATUS_NO_MEMORY;
                pthread_mutex_unlock(&epm_lock);
                return 0;
        }

        nmatch = 0;
        for (ep = ep_list; ep && filled < max_towers; ep = ep->next) {
                if (!uuid_equal(&ep->iface, &iface)) {
                        continue;
                }
                if (ep->vers_major != maj || ep->vers_minor < min) {
                        continue;
                }
                if (req->Object != NULL &&
                    !uuid_equal(&ep->object, req->Object) &&
                    !uuid_is_nil(req->Object)) {
                        continue;
                }
                if (nmatch < start) {
                        nmatch++;
                        continue;
                }
                towers[filled] = new_np_tower(pdu, ep);
                if (towers[filled] == NULL) {
                        rep->status = EPM_STATUS_NO_MEMORY;
                        pthread_mutex_unlock(&epm_lock);
                        return 0;
                }
                filled++;
                nmatch++;
        }

        {
                uint32_t total = 0;

                for (ep = ep_list; ep; ep = ep->next) {
                        if (!uuid_equal(&ep->iface, &iface)) {
                                continue;
                        }
                        if (ep->vers_major != maj || ep->vers_minor < min) {
                                continue;
                        }
                        total++;
                }
                if (start + filled < total) {
                        handle_set_index(&rep->EntryHandle, start + filled);
                } else {
                        handle_set_index(&rep->EntryHandle, 0);
                }
        }

        rep->Towers = towers;
        rep->NumTowers = filled;
        rep->status = EPM_STATUS_OK;
        pthread_mutex_unlock(&epm_lock);
        return 0;
}

int
dcerpcd_epm_LookupHandleFree(const struct epm_LookupHandleFree_req *req,
                             struct epm_LookupHandleFree_rep *rep)
{
        if (req == NULL || rep == NULL) {
                return -1;
        }
        memset(rep, 0, sizeof(*rep));
        handle_set_index(&rep->EntryHandle, 0);
        rep->status = EPM_STATUS_OK;
        return 0;
}
