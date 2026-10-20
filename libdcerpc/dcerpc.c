/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2018 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef STDC_HEADERS
#include <stddef.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_UNISTD_H
#include <sys/unistd.h>
#endif

#include <endian.h>
#include <errno.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
/* PS2 IOP and other minimal libc environments lack inttypes.h */
#ifndef PRIu64
#define PRIu64 "llu"
#endif
#endif


#include <stdarg.h>
#include <stdio.h>
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif
#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#else
#include <sys/fcntl.h>
#endif
#ifdef HAVE_LIBSMB2
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#endif
#include <dcerpc/dcerpc.h>
#include <dcerpc/dcerpc-dtyp.h>
#include <dcerpc/srvsvc.h>
#include <dcerpc/lsa.h>
#include <dcerpc/wkssvc.h>
#include <dcerpc/samr.h>
#include <dcerpc/dssetup.h>
#include <dcerpc/netlogon.h>
#include <dcerpc/winreg.h>
#include <dcerpc/schannel.h>
#include <dcerpc/epm.h>
#include "dcerpc-private.h"

struct dcerpc_service *dcerpc_services = NULL;

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)(void *)( (char *)__mptr - offsetof(type,member) );})

/*
 * PDU-local memory allocator (no libsmb2 dependency).
 *
 * The primary buffer (pdu->payload) is a dcerpc_mem_header::buf.  Child
 * allocations hang off that header.  free_pdu frees the whole tree.
 * dcerpc_free_data() frees a transferred tree after steal (callback reply).
 */
struct dcerpc_alloc_entry {
        struct dcerpc_alloc_entry *next;
        char buf[0];
};

struct dcerpc_mem_header {
        struct dcerpc_alloc_entry *mem;
        char buf[0];
};

static void *
dcerpc_mem_init(size_t size)
{
        struct dcerpc_mem_header *hdr;

        size += offsetof(struct dcerpc_mem_header, buf);
        hdr = calloc(1, size);
        if (hdr == NULL) {
                return NULL;
        }
        return &hdr->buf[0];
}

static struct dcerpc_mem_header *
dcerpc_mem_hdr_from_ptr(void *ptr)
{
#ifndef _MSC_VER
        return (struct dcerpc_mem_header *)(void *)
                container_of(ptr, struct dcerpc_mem_header, buf);
#else
        {
                const char *__mptr = ptr;
                return (struct dcerpc_mem_header *)
                        ((char *)__mptr - offsetof(struct dcerpc_mem_header, buf));
        }
#endif
}

static void
dcerpc_mem_free(void *ptr)
{
        struct dcerpc_mem_header *hdr;
        struct dcerpc_alloc_entry *ent;

        if (ptr == NULL) {
                return;
        }
        hdr = dcerpc_mem_hdr_from_ptr(ptr);
        while ((ent = hdr->mem)) {
                hdr->mem = ent->next;
                free(ent);
        }
        free(hdr);
}

struct dcerpc_deferred_pointer {
        dcerpc_coder coder;
        void *ptr;
        /*
         * size_is/length_is/switch_is in effect when the pointer was
         * queued. The referent is coded later, after sibling and nested
         * coders may have changed them, so they are restored before
         * coding it.
         */
        uint32_t size_is;
        uint32_t length_is;
        int switch_is;
};


#define NDR32_UUID     0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
#define NDR64_UUID     0x71710533, 0xbeba, 0x4937, {0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36}
/*
 * NDR64 is only supported for LITTLE_ENDIAN encodings:
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/b1af93c7-f988-4a1a-ac74-063179942f32
 */

p_syntax_id_t ndr32_syntax = {
        {NDR32_UUID}, 2, 0
};

p_syntax_id_t ndr64_syntax = {
        {NDR64_UUID}, 1, 0
};

/*
 * An SMB2 request in flight on behalf of a dcerpc context. Tracked so that
 * dcerpc_destroy_context() can cancel it: the user callback is invoked
 * with -ECANCELED and the request is marked orphaned, so that when SMB2
 * later completes (or cancels) it, the SMB2 callback only frees it.
 */
struct dcerpc_pending {
        struct dcerpc_pending *next;
        int orphaned;
        dcerpc_cb cb;
        void *cb_data;
};

struct dcerpc_context {
        struct smb2_context *smb2;
        struct dcerpc_pending *pending;
        int destroying;
        /*
         * Set when dcerpc_create_context_smb() allocated/connected the
         * smb2 context. dcerpc_destroy_context() will then disconnect
         * the IPC$ share and free smb2.
         */
        int owns_smb2;
        const char *path;
        p_syntax_id_t *syntax;
#ifdef HAVE_LIBSMB2
        smb2_file_id file_id;
#endif

        uint8_t tctx_id; /* presentation context ID: 0 NDR32, 1 NDR64 */
        uint8_t packed_drep[4];
        uint32_t call_id;
        uint16_t max_xmit_frag; /* server's max_recv_frag from BIND_ACK */
        /*
         * RPC-level security, from dcerpc_set_schannel(): the secure
         * channel (the caller's), the auth level, and the names the bind
         * gives for it. header_sign is set when the BIND_ACK agreed to
         * sign PDU headers too.
         */
        struct dcerpc_schannel *sch;
        uint8_t auth_level;
        char *auth_domain;
        char *auth_computer;
        int header_sign;
        char error_string[1024];
};

static void dcerpc_set_error(struct dcerpc_context *dce,
                             const char *error_string, ...)
        __attribute__((format(printf, 2, 3)));

/*
 * Errors are kept in the dcerpc context, and are also copied to the
 * smb2 context when there is one, so smb2_get_error() still sees them.
 */
static void
dcerpc_set_error(struct dcerpc_context *dce, const char *error_string, ...)
{
        va_list ap;

        if (dce == NULL) {
                return;
        }
        va_start(ap, error_string);
        vsnprintf(dce->error_string, sizeof(dce->error_string),
                  error_string, ap);
        va_end(ap);
#ifdef HAVE_LIBSMB2
        if (dce->smb2) {
                smb2_set_error(dce->smb2, "%s", dce->error_string);
        }
#endif
}

/*
 * A context created without an smb2 context can only encode and decode.
 */
static int
dcerpc_need_smb2(struct dcerpc_context *dce)
{
        if (dce->smb2 == NULL) {
                dcerpc_set_error(dce, "No smb2 context, this dcerpc context "
                                 "can only be used to encode and decode");
                return -EINVAL;
        }
        return 0;
}

struct dcerpc_header {
        uint8_t  rpc_vers;
        uint8_t  rpc_vers_minor;
        uint8_t  PTYPE;
        uint8_t  pfc_flags;
        uint8_t  packed_drep[4];
        uint16_t frag_length;
        uint16_t auth_length;
        uint32_t call_id;
};

struct p_cont_elem_t {
          uint16_t          p_cont_id;
          uint8_t           n_transfer_syn;     /* number of items */
          uint8_t           reserved;           /* alignment pad, m.b.z. */
          p_syntax_id_t     *abstract_syntax;   /* transfer syntax list */
          p_syntax_id_t     **transfer_syntaxes;
};

struct dcerpc_bind_pdu {
        uint16_t max_xmit_frag;
        uint16_t max_recv_frag;
        uint32_t assoc_group_id;

        /* presentation context list */
        uint8_t          n_context_elem;      /* number of items */
        //u_int8          reserved;            /* alignment pad, m.b.z. */
        //u_short         reserved2;           /* alignment pad, m.b.z. */
        struct p_cont_elem_t *p_cont_elem;
        //p_cont_elem_t [size_is(n_cont_elem)] p_cont_elem[];
        //p_syntax_id_t *abstract_syntax;
};

#define ACK_RESULT_ACCEPTANCE         0
#define ACK_RESULT_USER_REJECTION     1
#define ACK_RESULT_PROVIDER_REJECTION 2

#define ACK_REASON_REASON_NOT_SPECIFIED                     0
#define ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED            1
#define ACK_REASON_PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED 2
#define ACK_REASON_PROTOCOL_VERSION_NOT_SUPPORTED           4

struct dcerpc_bind_context_results {
        uint16_t ack_result;
        uint16_t ack_reason;
        dcerpc_uuid_t uuid;
        uint32_t syntax_version;
};

#define MAX_ACK_RESULTS 4
struct dcerpc_bind_ack_pdu {
        uint16_t max_xmit_frag;
        uint16_t max_recv_frag;
        uint32_t assoc_group_id;

        /* presentation context list */
        uint8_t num_results;
        struct dcerpc_bind_context_results results[MAX_ACK_RESULTS];
};

struct dcerpc_request_pdu {
        uint32_t alloc_hint;
        uint16_t context_id;
        uint16_t opnum;

      /* optional field for request, only present if the PFC_OBJECT_UUID
         * field is non-zero */
      /*  dcerpc_uuid_t  object;              24:16 object UID */

      /* stub data, 8-octet aligned 
                   .
                   .
                   .                 */
};

struct dcerpc_response_pdu {
        uint32_t alloc_hint;
        uint16_t context_id;
        uint8_t cancel_count;
        uint8_t reserved;
      /* stub data, 8-octet aligned 
                   .
                   .
                   .                 */
};

/* PDU Types */
#define PDU_TYPE_REQUEST             0
#define PDU_TYPE_PING                1
#define PDU_TYPE_RESPONSE            2
#define PDU_TYPE_FAULT               3
#define PDU_TYPE_WORKING             4
#define PDU_TYPE_NOCALL              5
#define PDU_TYPE_REJECT              6
#define PDU_TYPE_ACK                 7
#define PDU_TYPE_CL_CANCEL           8
#define PDU_TYPE_FACK                9
#define PDU_TYPE_CANCEL_ACK         10
#define PDU_TYPE_BIND               11
#define PDU_TYPE_BIND_ACK           12
#define PDU_TYPE_BIND_NAK           13
#define PDU_TYPE_ALTER_CONTEXT      14
#define PDU_TYPE_ALTER_CONTEXT_RESP 15
#define PDU_TYPE_SHUTDOWN           17
#define PDU_TYPE_CO_CANCEL          18
#define PDU_TYPE_ORPHANED           19


/* Flags */
#define PFC_FIRST_FRAG      0x01
#define PFC_LAST_FRAG       0x02
#define PFC_PENDING_CANCEL  0x04
/* In a BIND/BIND_ACK the same bit offers/accepts header signing ([MS-RPCE]) */
#define PFC_SUPPORT_HEADER_SIGN 0x04
#define PFC_RESERVED_1      0x08
#define PFC_CONC_MPX        0x10
#define PFC_DID_NOT_EXECUTE 0x20
#define PFC_MAYBE           0x40
#define PFC_OBJECT_UUID     0x80

#define NSE_BUF_SIZE 128*1024
/* Fragment size to use when sending before a BIND_ACK told us one. */
#define DCE_DEFAULT_XMIT_FRAG 4280
/* The smallest fragment every implementation must accept (C706) */
#define DCE_MIN_FRAG 1432

/* sec_trailer: auth_type, auth_level, auth_pad_length, reserved, context id */
#define DCE_SEC_TRAILER_LEN 8
/* Our one security context on the association */
#define DCE_AUTH_CONTEXT_ID 1
/* The stub before an auth trailer is padded to this ([MS-RPCE] 2.2.2.11) */
#define DCE_AUTH_PAD_ALIGN 16

/* NL_AUTH_MESSAGE ([MS-NRPC] 2.2.1.3.1) */
#define NL_NEGOTIATE_REQUEST                0
#define NL_NEGOTIATE_RESPONSE               1
#define NL_FLAG_OEM_NETBIOS_DOMAIN_NAME     0x00000001
#define NL_FLAG_OEM_NETBIOS_COMPUTER_NAME   0x00000002

struct dcerpc_cb_data {
        struct dcerpc_pending pending;
        struct dcerpc_context *dce;
        dcerpc_cb cb;
        void *cb_data;
};

typedef int (*dcerpc_coder_carray)(char *name, struct dcerpc_context *dce,
                                   struct dcerpc_pdu *pdu,
                                   struct dcerpc_iovec *iov,
                                   uint32_t num, void *ptr, int elem_size,
                                   dcerpc_coder coder);
typedef int (*dcerpc_coder_ptr)(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct dcerpc_iovec *iov,
                                void *ptr, enum ptr_type type,
                                dcerpc_coder coder);

struct dcerpc_coders {
        dcerpc_coder     uint8_coder;
        dcerpc_coder     uint16_coder;
        dcerpc_coder_pp  uint16_coder_pp;
        dcerpc_coder     uint32_coder;
        dcerpc_coder_pp  uint32_coder_pp;
        dcerpc_coder     uint64_coder;
        dcerpc_coder     uuid_coder;
        dcerpc_coder     sid_coder;
        dcerpc_coder_cdr struct_coder;
        dcerpc_coder_cdr do_coder;
        dcerpc_coder_union union_coder;
        dcerpc_coder_carray carray_coder;
        /* array of plain values: YAML/JSON show a bare list, no keys */
        dcerpc_coder_carray scalar_carray_coder;
        dcerpc_coder_ptr ptr_coder;
        dcerpc_coder     bytes_coder;
        dcerpc_coder     varying_bytes_coder;
        /* Strings. MS IDLs use two wire formats for strings, each with
         * a plain and a NUL-terminated (z) flavour:
         *   utf16/utf16z:                   [string] wchar_t *
         *   unicode_string/unicode_stringz: MS-DTYP RPC_UNICODE_STRING
         * All four are char * (UTF-8) in C. Only NDR distinguishes them;
         * for every other encoding (YAML, JSON) they are the same coder.
         */
        dcerpc_coder     utf16_coder;
        dcerpc_coder     utf16z_coder;
        dcerpc_coder     unicode_string_coder;
        dcerpc_coder     unicode_stringz_coder;
};

struct dcerpc_coders ndr_coders;
struct dcerpc_coders yaml_coders;
struct dcerpc_coders json_coders;

/*
 * Every encoding must implement every slot in struct dcerpc_coders.
 * Returns the name of the first missing slot, or NULL if the table is
 * complete. When adding a new slot to struct dcerpc_coders, add it here too.
 */
static const char *
dcerpc_coders_missing(const struct dcerpc_coders *coders)
{
#define CHECK_CODER(f) if (coders->f == NULL) return #f
        CHECK_CODER(uint8_coder);
        CHECK_CODER(uint16_coder);
        CHECK_CODER(uint16_coder_pp);
        CHECK_CODER(uint32_coder);
        CHECK_CODER(uint32_coder_pp);
        CHECK_CODER(uint64_coder);
        CHECK_CODER(uuid_coder);
        CHECK_CODER(sid_coder);
        CHECK_CODER(utf16_coder);
        CHECK_CODER(utf16z_coder);
        CHECK_CODER(unicode_string_coder);
        CHECK_CODER(unicode_stringz_coder);
        CHECK_CODER(struct_coder);
        CHECK_CODER(do_coder);
        CHECK_CODER(union_coder);
        CHECK_CODER(carray_coder);
        CHECK_CODER(scalar_carray_coder);
        CHECK_CODER(ptr_coder);
        CHECK_CODER(bytes_coder);
        CHECK_CODER(varying_bytes_coder);
#undef CHECK_CODER
        return NULL;
}

/*
 * Verify that every compiled-in encoding implements every coder, so that
 * an incomplete table for a new encoding fails at context creation rather
 * than deep inside an encode/decode.
 */
static int
dcerpc_check_coders(struct smb2_context *smb2)
{
        static const struct {
                const char *name;
                const struct dcerpc_coders *coders;
        } tables[] = {
                { "NDR", &ndr_coders },
                { "YAML", &yaml_coders },
                { "JSON", &json_coders },
        };
        const char *missing;
        size_t i;

        for (i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
                missing = dcerpc_coders_missing(tables[i].coders);
                if (missing) {
#ifdef HAVE_LIBSMB2
                        if (smb2) {
                                smb2_set_error(smb2, "DCERPC %s encoding "
                                               "has no %s",
                                               tables[i].name, missing);
                        }
#endif
                        return -1;
                }
        }
        return 0;
}

struct dcerpc_pdu {
        struct dcerpc_pending pending;
        struct dcerpc_header hdr;

        union {
                struct dcerpc_bind_pdu bind;
                struct dcerpc_bind_ack_pdu bind_ack;
                struct dcerpc_request_pdu req;
                struct dcerpc_response_pdu rsp;
        };

        /* optional authentication verifier */
        /* following fields present iff auth_length != 0 */
#if 0
        auth_verifier_co_t   auth_verifier; 
#endif
        struct dcerpc_context *dce;
        dcerpc_cb cb;
        void *cb_data;

        dcerpc_coder coder;
        int decode_size;
        void *payload;

        /*
         * The call_id the request was sent with: decoding the reply
         * overwrites hdr, and every PDU of the reply must carry it.
         */
        uint32_t call_id;

        /*
         * Multi-fragment REQUEST: all fragments back to back. Fragments
         * before the last are sent with WRITE, the last with TRANSCEIVE.
         */
        uint8_t *frag_buf;
        size_t frag_len;
        size_t frag_pos;

        /* Multi-fragment response reassembly (named-pipe / IOCTL) */
        uint8_t *reasm_buf;
        size_t reasm_len;
        size_t reasm_cap;

        int top_level;
        /*
         * Full pointers are numbered 1, 2, ... and a reply continues after
         * the highest one of its request (dcerpc_set_full_pointer_id()),
         * so this is the highest full pointer id coded so far. Unique and
         * embedded ref pointers always use UPTR/RPTR, which stand out in
         * a hexdump and show NDR32/NDR64.
         */
        uint64_t full_ptr_id;

        int cur_ptr;
        int max_ptr;
        int ptrs_cap;
        struct dcerpc_deferred_pointer *ptrs;
        uint32_t direction; /* DCERPC_ENCODE or DCERPC_DECODE */
        enum dcerpc_encoding encoding;
        int ndr64; /* NDR64, else NDR32 */
        struct dcerpc_coders *coders;
        void *request;
        /* the server call a request PDU was decoded for (server.h) */
        struct dcerpc_server_call *server_call;

        /* All items are parsed twice, first to handle the conformance
         * fields and a second time to handle the data itself.
         * During the first run we also check what the maximum alignment
         * of the fields are.
         */
        int is_conformance_run;
        int max_alignment;

        /*
         * Nesting depth of packet-form (MS-DTYP 2.4.x) data being coded.
         * While non-zero, NDR primitives are little-endian regardless of
         * the data representation in packed_drep.
         */
        int packet_form;

        uint32_t size_is; /* Passing size_is() value through a pointer */
        uint32_t length_is; /* and length_is() */
        int switch_is; /* Passing switch_is() value through a pointer */
        /*
         * Override for RPC_UNICODE_STRING MaximumLength (bytes) and the
         * Buffer max_count (size_is(MaximumLength/2)). 0 = derive from
         * content. Cleared after the Buffer utf16 encode consumes it.
         */
        uint16_t unicode_max_length;

        /* YAML/JSON text codecs — full libdcerpc only */
        int yaml_indentation;
        int yaml_array_prefix; /* next key is the first field of a list item */
        char *yaml_key;
        char *yaml_val;

        int json_indentation;
        int json_need_comma; /* 1 if a comma is required before the next value */
        char *json_key;
};

/*
 * NDR
 */
#define RPTR 0x5270747272747052
#define UPTR 0x5570747272747055
static int ndr_do_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
             struct dcerpc_iovec *iov, void *ptr,  dcerpc_coder coder);
int ndr_uint16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, void *ptr);
int ndr_uint8_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, void *ptr);
int ndr_uint3264_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                       struct dcerpc_iovec *iov, void *ptr);
static int ndr_conformance_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                                 struct dcerpc_iovec *iov, void *ptr);
static int ndr_encode_ptr(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, void *ptr,
                          enum ptr_type type, dcerpc_coder coder);
static int ndr_decode_ptr(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, void *ptr,
                          enum ptr_type type, dcerpc_coder coder);
int ndr_carray_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov,
                     uint32_t num, void *ptr, int elem_size, dcerpc_coder coder);
int ndr_union_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov,
                    uint32_t *switch_is, void *ptr, dcerpc_coder coder);
int ndr_struct_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, void *ptr, dcerpc_coder coder);
int ndr_ptr_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, void *ptr,
                  enum ptr_type type, dcerpc_coder coder);
static int ndr_encode_utf16(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                            struct dcerpc_iovec *iov, void *ptr, int nult);
static int ndr_decode_utf16(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                            struct dcerpc_iovec *iov, void *ptr, int nult);
int _ndr_utf16z_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                      struct dcerpc_iovec *iov, void *ptr, int nult);
int ndr_utf16z_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, void *ptr);
int ndr_utf16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, void *ptr);
int ndr_uuid_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr);

/*
 * YAML
 */
static int yaml_carray_coder(char *name, struct dcerpc_context *ctx,
                      struct dcerpc_pdu *pdu,
                      struct dcerpc_iovec *iov,
                      uint32_t num, void *ptr, int elem_size, dcerpc_coder coder);
static int yaml_ptr_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr,
                   enum ptr_type type, dcerpc_coder coder);
static int yaml_utf16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov,
                     void *ptr);

/*
 * JSON
 */
static int json_carray_coder(char *name, struct dcerpc_context *ctx,
                             struct dcerpc_pdu *pdu,
                             struct dcerpc_iovec *iov,
                             uint32_t num, void *ptr, int elem_size, dcerpc_coder coder);
static int json_ptr_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, void *ptr,
                          enum ptr_type type, dcerpc_coder coder);
static int json_utf16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                            struct dcerpc_iovec *iov,
                            void *ptr);


void
dcerpc_free_iovec(struct dcerpc_iovec *iov)
{
        if (iov->free && iov->buf) {
                iov->free(iov->buf);
        }
        memset(iov, 0, sizeof(*iov));
}

/*
 * Make room to encode n more bytes at iov->offset. A buffer that is still
 * NULL is allocated, with .free = free; a buffer whose .free is free is
 * doubled until the bytes fit, up to DCERPC_IOVEC_MAX_SIZE, with the new
 * space zeroed (NDR padding is skipped over, not written). Any other buffer
 * has a fixed size. dce is only used for the error and may be NULL.
 */
static int
dcerpc_iov_reserve(struct dcerpc_context *dce, struct dcerpc_iovec *iov,
                   size_t n)
{
        size_t need, size;
        uint8_t *buf;

        if (iov->buf != NULL && iov->offset <= iov->max_offset &&
            n <= iov->max_offset - iov->offset) {
                return 0;
        }
        if (iov->buf == NULL) {
                iov->free = free;
                iov->max_offset = 0;
        }
        if (iov->free != free) {
                if (dce) {
                        dcerpc_set_error(dce, "DCERPC encode buffer too "
                                         "small");
                }
                return -1;
        }
        if (iov->offset > DCERPC_IOVEC_MAX_SIZE ||
            n > DCERPC_IOVEC_MAX_SIZE - iov->offset) {
                if (dce) {
                        dcerpc_set_error(dce, "DCERPC encode buffer "
                                         "would exceed %d bytes",
                                         DCERPC_IOVEC_MAX_SIZE);
                }
                return -1;
        }
        need = iov->offset + n;
        size = iov->max_offset ? iov->max_offset : DCERPC_IOVEC_INITIAL_SIZE;
        while (size < need) {
                size *= 2;
        }
        if (size > DCERPC_IOVEC_MAX_SIZE) {
                size = DCERPC_IOVEC_MAX_SIZE;
        }
        buf = realloc(iov->buf, size);
        if (buf == NULL) {
                if (dce) {
                        dcerpc_set_error(dce, "Failed to grow DCERPC "
                                         "encode buffer");
                }
                return -1;
        }
        memset(buf + iov->max_offset, 0, size - iov->max_offset);
        iov->buf = buf;
        iov->max_offset = size;
        return 0;
}

/*
 * Align iov->offset to align (a power of two). When encoding, the padding
 * must lie inside the buffer, so make room for it.
 */
static int
dcerpc_iov_align(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                 size_t align)
{
        iov->offset = (iov->offset + (align - 1)) & ~(align - 1);
        if (pdu->direction == DCERPC_ENCODE) {
                return dcerpc_iov_reserve(pdu->dce, iov, 0);
        }
        return 0;
}

int
dcerpc_set_uint8(struct dcerpc_context *ctx, struct dcerpc_iovec *iov, uint8_t value)
{
        if (dcerpc_iov_reserve(ctx, iov, sizeof(uint8_t))) {
                return -1;
        }
        *(uint8_t *)(iov->buf + iov->offset) = value;
        iov->offset += 1;
        return 0;
}

/*
 * Byte order for multi-byte NDR primitives: the PDU's data representation,
 * except inside packet-form data (see dcerpc_pdu_packet_form_begin()),
 * which is always little-endian.
 */
static int
dcerpc_pdu_little_endian(struct dcerpc_pdu *pdu)
{
        return pdu->packet_form ||
                (pdu->hdr.packed_drep[0] & DCERPC_DR_LITTLE_ENDIAN);
}

static int
dcerpc_set_uint16(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, uint16_t value)
{
        iov->offset = (iov->offset + 1) & ~1;
        
        if (dcerpc_iov_reserve(ctx, iov, sizeof(uint16_t))) {
                return -1;
        }
        if (!dcerpc_pdu_little_endian(pdu)) {
                *(uint16_t *)(void *)(iov->buf + iov->offset) = htobe16(value);
        } else {
                *(uint16_t *)(void *)(iov->buf + iov->offset) = htole16(value);
        }
        iov->offset += 2;

        return 0;
}

static int
dcerpc_set_uint32(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, uint32_t value)
{
        iov->offset = (iov->offset + 3) & ~3;
        
        if (dcerpc_iov_reserve(ctx, iov, sizeof(uint32_t))) {
                return -1;
        }
        if (!dcerpc_pdu_little_endian(pdu)) {
                *(uint32_t *)(void *)(iov->buf + iov->offset) = htobe32(value);
        } else {
                *(uint32_t *)(void *)(iov->buf + iov->offset) = htole32(value);
        }
        iov->offset += 4;
        return 0;
}

static int
dcerpc_set_uint64(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, uint64_t value)
{
        iov->offset = (iov->offset + 7) & ~7;

        if (dcerpc_iov_reserve(ctx, iov, sizeof(uint64_t))) {
                return -1;
        }
        if (!dcerpc_pdu_little_endian(pdu)) {
                *(uint64_t *)(void *)(iov->buf + iov->offset) = htobe64(value);
        } else {
                *(uint64_t *)(void *)(iov->buf + iov->offset) = htole64(value);
        }
        iov->offset += 8;
        return 0;
}

static int
dcerpc_get_uint8(struct dcerpc_context *ctx, struct dcerpc_iovec *iov, uint8_t *value)
{
        if (iov->offset + sizeof(uint8_t) > iov->max_offset) {
                return -1;
        }
        *value = iov->buf[iov->offset];
        iov->offset += 1;
        return 0;
}

static int
dcerpc_get_uint16(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, uint16_t *value)
{
        uint16_t val;

        iov->offset = (iov->offset + 1) & ~1;
        
        if (iov->offset + sizeof(uint16_t) > iov->max_offset) {
                return -1;
        }
        if (!dcerpc_pdu_little_endian(pdu)) {
                val = be16toh(*(uint16_t *)(void *)(iov->buf + iov->offset));
        } else {
                val = le16toh(*(uint16_t *)(void *)(iov->buf + iov->offset));
        }
        *value = val;
        iov->offset += 2;
        return 0;
}

static int
dcerpc_get_uint32(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, uint32_t *value)
{
        uint32_t val;
        
        iov->offset = (iov->offset + 3) & ~3;
        
        if (iov->offset + sizeof(uint32_t) > iov->max_offset) {
                return -1;
        }
        
        if (!dcerpc_pdu_little_endian(pdu)) {
                val = be32toh(*(uint32_t *)(void *)(iov->buf + iov->offset));
        } else {
                val = le32toh(*(uint32_t *)(void *)(iov->buf + iov->offset));
        }
        *value = val;
        iov->offset += 4;
        return 0;
}

static int
dcerpc_get_uint64(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, uint64_t *value)
{
        uint64_t val;

        iov->offset = (iov->offset + 7) & ~7;

        if (iov->offset + sizeof(uint64_t) > iov->max_offset) {
                return -1;
        }
        if (!dcerpc_pdu_little_endian(pdu)) {
                val = be64toh(*(uint64_t *)(void *)(iov->buf + iov->offset));
        } else {
                val = le64toh(*(uint64_t *)(void *)(iov->buf + iov->offset));
        }
        *value = val;
        iov->offset += 8;
        return 0;
}

struct smb2_context *
dcerpc_get_smb2_context(struct dcerpc_context *dce)
{
        return dce->smb2;
}

void *
dcerpc_get_pdu_payload(struct dcerpc_pdu *pdu)
{
        return pdu->payload;
}

int
dcerpc_register_coder(const char *name,
                      p_syntax_id_t *interface,
                      struct dcerpc_procedure *procs)
{
        return dcerpc_register_service(name, NULL, interface, procs);
}

int
dcerpc_register_service(const char *name, const char *pipe,
                        p_syntax_id_t *interface,
                        struct dcerpc_procedure *procs)
{
        struct dcerpc_service *service;

        for (service = dcerpc_services; service; service = service->next) {
                if (!strcmp(name, service->name)) {
                        return -EEXIST;
                }
        }

        service = calloc(1, sizeof(struct dcerpc_service));
        if (service == NULL) {
                return -ENOMEM;
        }

        service->name = strdup(name);
        if (service->name == NULL) {
                free(service);
                return -ENOMEM;
        }
        if (pipe) {
                service->pipe = strdup(pipe);
                if (service->pipe == NULL) {
                        free(discard_const(service->name));
                        free(service);
                        return -ENOMEM;
                }
        }

        service->next = dcerpc_services;
        service->interface = interface;
        service->procs = procs;

        dcerpc_services = service;

        return 0;
}

struct dcerpc_context *
dcerpc_create_context(struct smb2_context *smb2)
{
        struct dcerpc_context *ctx;

#ifndef HAVE_LIBSMB2
        /* Built without libsmb2: only naked contexts */
        if (smb2) {
                return NULL;
        }
#endif
        if (dcerpc_check_coders(smb2)) {
                return NULL;
        }

        ctx = calloc(1, sizeof(struct dcerpc_context));
        if (ctx == NULL) {
#ifdef HAVE_LIBSMB2
                if (smb2) {
                        smb2_set_error(smb2, "Failed to allocate dcercp "
                                       "context.");
                }
#endif
                return NULL;
        }

        ctx->smb2 = smb2;
        ctx->owns_smb2 = 0;
        ctx->packed_drep[0] |= DCERPC_DR_LITTLE_ENDIAN;

        dcerpc_register_coder("srvsvc", &srvsvc_interface, srvsvc_procs);
        dcerpc_register_coder("lsarpc", &lsa_interface, lsa_procs);
        dcerpc_register_coder("wkssvc", &wkssvc_interface, wkssvc_procs);
        dcerpc_register_coder("samr", &samr_interface, samr_procs);
        dcerpc_register_service("dssetup", "lsarpc", &dssetup_interface,
                                dssetup_procs);
        dcerpc_register_coder("netlogon", &netlogon_interface, netlogon_procs);
        dcerpc_register_coder("winreg", &winreg_interface, winreg_procs);
        dcerpc_register_coder("epmapper", &epm_interface, epm_procs);

        return ctx;
}

/*
 * Convenience constructor: create an smb2 context from an SMB URL, apply
 * user/domain and query args from the URL, connect IPC$, and wrap it in a
 * dcerpc context that owns the smb2 lifecycle.
 *
 * URL format (same as smb2_parse_url):
 *   smb://[[domain;]user@]server[:port]/[share[/path]][?args]
 *
 * Query args are applied by smb2_parse_url (e.g. ?sign, ?seal, ?sec=ntlmssp).
 * Signing is not forced here; pass ?sign when the client wants it.
 *
 * The share path is ignored for tree connect; DCE/RPC named pipes always
 * use IPC$. Call dcerpc_connect_context() afterwards to open the pipe.
 *
 * On success the returned context owns smb2; dcerpc_destroy_context() will
 * disconnect IPC$ and destroy the smb2 context. On failure returns NULL.
 */
#ifdef HAVE_LIBSMB2
struct dcerpc_context *
dcerpc_create_context_smb(const char *smb_url)
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct dcerpc_context *dce;

        if (smb_url == NULL) {
                return NULL;
        }

        smb2 = smb2_init_context();
        if (smb2 == NULL) {
                return NULL;
        }

        url = smb2_parse_url(smb2, smb_url);
        if (url == NULL) {
                smb2_destroy_context(smb2);
                return NULL;
        }

        if (url->user) {
                smb2_set_user(smb2, url->user);
        }
        if (url->domain) {
                smb2_set_domain(smb2, url->domain);
        }

        if (smb2_connect_share(smb2, url->server, "IPC$", NULL) < 0) {
                smb2_destroy_url(url);
                smb2_destroy_context(smb2);
                return NULL;
        }
        smb2_destroy_url(url);

        dce = dcerpc_create_context(smb2);
        if (dce == NULL) {
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
                return NULL;
        }

        dce->owns_smb2 = 1;
        return dce;
}

int
dcerpc_connect_context_async(struct dcerpc_context *dce, const char *path,
                             p_syntax_id_t *syntax,
                             dcerpc_cb cb, void *cb_data)
{
        if (dcerpc_need_smb2(dce)) {
                return -EINVAL;
        }
        dce->call_id = 2;
        dce->path = strdup(path);
        if (dce->path == NULL) {
                dcerpc_set_error(dce, "Failed to allocate path for "
                                 "dcercp context.");
                return -ENOMEM;
        }
        dce->syntax = syntax;
        dce->packed_drep[0] = DCERPC_DR_ASCII;
        if (!smb2_get_endianness(dce->smb2)) {
                dce->packed_drep[0] |= DCERPC_DR_LITTLE_ENDIAN;
        }

        if (dcerpc_open_async(dce, cb, cb_data) != 0) {
                return -1;
        }

        return 0;
}

static void
dcerpc_close_cb(struct smb2_context *smb2 _U_, int status _U_,
                void *command_data _U_, void *private_data _U_)
{
        /* best-effort close on destroy; nothing to free */
}

static void
dcerpc_track(struct dcerpc_context *dce, struct dcerpc_pending *p,
             dcerpc_cb cb, void *cb_data)
{
        p->orphaned = 0;
        p->cb = cb;
        p->cb_data = cb_data;
        p->next = dce->pending;
        dce->pending = p;
}

static void
dcerpc_untrack(struct dcerpc_context *dce, struct dcerpc_pending *p)
{
        struct dcerpc_pending **pp;

        for (pp = &dce->pending; *pp; pp = &(*pp)->next) {
                if (*pp == p) {
                        *pp = p->next;
                        p->next = NULL;
                        return;
                }
        }
}

#else /* !HAVE_LIBSMB2 */
struct dcerpc_context *
dcerpc_create_context_smb(const char *smb_url _U_)
{
        return NULL;
}

int
dcerpc_connect_context_async(struct dcerpc_context *dce,
                             const char *path _U_,
                             p_syntax_id_t *syntax _U_,
                             dcerpc_cb cb _U_, void *cb_data _U_)
{
        return dcerpc_need_smb2(dce);
}
#endif /* HAVE_LIBSMB2 */

void
dcerpc_destroy_context(struct dcerpc_context *dce)
{
#ifdef HAVE_LIBSMB2
        struct smb2_context *smb2;
        int owns_smb2;
        int i;
        int opened = 0;
#endif
        struct dcerpc_pending *p;

        if (dce == NULL || dce->destroying) {
                return;
        }
        dce->destroying = 1;

        /*
         * Cancel requests still in flight. Their SMB2 callbacks will run
         * later (reply, or smb2_destroy_context()) and must not touch dce.
         */
        while ((p = dce->pending) != NULL) {
                dce->pending = p->next;
                p->next = NULL;
                p->orphaned = 1;
                if (p->cb) {
                        p->cb(dce, -ECANCELED, NULL, p->cb_data);
                }
        }

#ifdef HAVE_LIBSMB2
        for (i = 0; i < SMB2_FD_SIZE; i++) {
                if (dce->file_id[i]) {
                        opened = 1;
                        break;
                }
        }
        if (opened && dce->smb2) {
                struct smb2_close_request cl_req;
                struct smb2_pdu *pdu;

                memset(&cl_req, 0, sizeof(cl_req));
                memcpy(cl_req.file_id, dce->file_id, SMB2_FD_SIZE);
                pdu = smb2_cmd_close_async(dce->smb2, &cl_req,
                                           dcerpc_close_cb, NULL);
                if (pdu) {
                        smb2_queue_pdu(dce->smb2, pdu);
                }
        }

        smb2 = dce->smb2;
        owns_smb2 = dce->owns_smb2;
#endif

        free(discard_const(dce->path));
        free(dce->auth_domain);
        free(dce->auth_computer);
        free(dce);

#ifdef HAVE_LIBSMB2
        if (owns_smb2 && smb2) {
                smb2_disconnect_share(smb2);
                smb2_destroy_context(smb2);
        }
#endif
}

int
dcerpc_set_schannel(struct dcerpc_context *dce,
                    struct dcerpc_schannel *sch, int auth_level,
                    const char *domain, const char *computer)
{
        char *d, *c;

        if (dce == NULL || sch == NULL || domain == NULL ||
            computer == NULL ||
            (auth_level != DCERPC_AUTH_LEVEL_INTEGRITY &&
             auth_level != DCERPC_AUTH_LEVEL_PRIVACY)) {
                return -EINVAL;
        }
        /* The bind carries the auth: it is too late once bound */
        if (dce->max_xmit_frag != 0) {
                dcerpc_set_error(dce, "DCERPC schannel must be set before "
                                 "the bind");
                return -EINVAL;
        }
        d = strdup(domain);
        c = strdup(computer);
        if (d == NULL || c == NULL) {
                free(d);
                free(c);
                return -ENOMEM;
        }
        free(dce->auth_domain);
        free(dce->auth_computer);
        dce->auth_domain = d;
        dce->auth_computer = c;
        dce->sch = sch;
        dce->auth_level = (uint8_t)auth_level;
        return 0;
}

uint64_t
dcerpc_get_full_pointer_id(struct dcerpc_pdu *pdu)
{
        return pdu->full_ptr_id;
}

void
dcerpc_set_full_pointer_id(struct dcerpc_pdu *pdu, uint64_t id)
{
        pdu->full_ptr_id = id;
}

void *
dcerpc_alloc_data(struct dcerpc_pdu *pdu, size_t size)
{
        struct dcerpc_mem_header *hdr;
        struct dcerpc_alloc_entry *ptr;

        if (pdu == NULL || pdu->payload == NULL) {
                return NULL;
        }

        size += offsetof(struct dcerpc_alloc_entry, buf);
        ptr = calloc(1, size);
        if (ptr == NULL) {
                if (pdu->dce) {
                        dcerpc_set_error(pdu->dce,
                                         "Failed to alloc %zu bytes", size);
                }
                return NULL;
        }

        hdr = dcerpc_mem_hdr_from_ptr(pdu->payload);
        ptr->next = hdr->mem;
        hdr->mem = ptr;

        return &ptr->buf[0];
}

/*
 * An array of count elements of esize bytes for a decoder. On NDR decode
 * count comes from the peer and every element takes at least one byte of
 * what is left of the buffer (the array data follows, if deferred, in the
 * same buffer), so a count larger than that is refused before allocating:
 * otherwise a few bytes could ask for gigabytes.
 */
void *
dcerpc_alloc_array(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                   uint64_t count, size_t esize)
{
        if (esize == 0 || count > SIZE_MAX / esize) {
                return NULL;
        }
        if (pdu->direction == DCERPC_DECODE &&
            pdu->encoding == ENCODING_NDR &&
            (iov->offset > iov->max_offset ||
             count > iov->max_offset - iov->offset)) {
                dcerpc_set_error(pdu->dce, "DCERPC array of %llu elements "
                                 "with %zu bytes left",
                                 (unsigned long long)count,
                                 iov->offset > iov->max_offset ? 0 :
                                 iov->max_offset - iov->offset);
                return NULL;
        }
        return dcerpc_alloc_data(pdu, (size_t)count * esize);
}

void
dcerpc_free_pdu(struct dcerpc_context *dce _U_, struct dcerpc_pdu *pdu)
{
        if (pdu == NULL) {
                return;
        }

        dcerpc_mem_free(pdu->payload);
        free(pdu->frag_buf);
        free(pdu->reasm_buf);
        free(pdu->ptrs);
        free(pdu);
}

struct dcerpc_pdu *
dcerpc_allocate_pdu(struct dcerpc_context *dce, uint32_t flags,
                    int payload_size)
{
        enum dcerpc_encoding encoding = DCERPC_PDU_ENCODING(flags);
        struct dcerpc_pdu *pdu;

        if (flags & ~(DCERPC_DIRECTION_MASK | DCERPC_BIG_ENDIAN |
                      DCERPC_NDR64 | DCERPC_ENCODING_MASK)) {
                dcerpc_set_error(dce, "Invalid DCERPC PDU flags 0x%08x",
                                 flags);
                return NULL;
        }
        if (encoding != ENCODING_NDR && encoding != ENCODING_YAML &&
            encoding != ENCODING_JSON) {
                dcerpc_set_error(dce, "Unknown DCERPC encoding %d",
                                 (int)encoding);
                return NULL;
        }
        if (encoding != ENCODING_NDR &&
            (flags & (DCERPC_BIG_ENDIAN | DCERPC_NDR64))) {
                dcerpc_set_error(dce, "DCERPC_BIG_ENDIAN and "
                                 "DCERPC_NDR64 only apply to ENCODING_NDR");
                return NULL;
        }

        pdu = calloc(1, sizeof(struct dcerpc_pdu));
        if (pdu == NULL) {
                dcerpc_set_error(dce, "Failed to allocate DCERPC PDU");
                return NULL;
        }

        pdu->dce = dce;
        pdu->encoding = encoding;
        switch (pdu->encoding) {
        case ENCODING_NDR:
                pdu->coders = &ndr_coders;
                break;
        case ENCODING_YAML:
                pdu->coders = &yaml_coders;
                break;
        case ENCODING_JSON:
                pdu->coders = &json_coders;
                break;
        }
        pdu->direction = flags & DCERPC_DIRECTION_MASK;
        pdu->ndr64 = !!(flags & DCERPC_NDR64);
        pdu->hdr.packed_drep[0] = DCERPC_DR_ASCII;
        if (!(flags & DCERPC_BIG_ENDIAN)) {
                pdu->hdr.packed_drep[0] |= DCERPC_DR_LITTLE_ENDIAN;
        }
        pdu->top_level = 1;
        pdu->payload = dcerpc_mem_init(payload_size);
        if (pdu->payload == NULL) {
                dcerpc_set_error(dce, "Failed to allocate PDU Payload");
                dcerpc_free_pdu(dce, pdu);
                return NULL;
        }

        return pdu;
}

int
dcerpc_do_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
             struct dcerpc_iovec *iov, void *ptr,
             dcerpc_coder coder)
{
        if (pdu->coders->do_coder) {
                return pdu->coders->do_coder(name, ctx, pdu, iov,
                                             ptr, coder);
        }
        return -1;
}

int
dcerpc_uint32_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->coders->uint32_coder) {
                return pdu->coders->uint32_coder(name, ctx, pdu, iov,
                                                 ptr);
        }
        return -1;
}

int dcerpc_uint32_coder_pp(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov, void *ptr,
                           struct dcerpc_uint32_pretty_printer *pp)
{
        if (pdu->coders->uint32_coder_pp) {
                return pdu->coders->uint32_coder_pp(name, ctx, pdu,
                                                    iov,
                                                    ptr, pp);
        }
        return -1;
}

int
dcerpc_uint64_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->coders->uint64_coder) {
                return pdu->coders->uint64_coder(name, ctx, pdu,
                                                 iov,
                                                 ptr);
        }
        return -1;
}

int
dcerpc_uuid_coder(char *name, struct dcerpc_context *ctx,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->coders->uuid_coder) {
                return pdu->coders->uuid_coder(name, ctx, pdu,
                                               iov, ptr);
        }
        return -1;
}

int
dcerpc_sid_coder(char *name, struct dcerpc_context *ctx,
                 struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->coders->sid_coder) {
                return pdu->coders->sid_coder(name, ctx, pdu,
                                              iov, ptr);
        }
        return -1;
}

int
dcerpc_uint8_coder(char *name, struct dcerpc_context *ctx,
                   struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->coders->uint8_coder) {
                return pdu->coders->uint8_coder(name, ctx, pdu,
                                                iov, ptr);
        }
        return -1;
}

int
dcerpc_uint16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->coders->uint16_coder) {
                return pdu->coders->uint16_coder(name, ctx, pdu,
                                                 iov, ptr);
        }
        return -1;
}

int dcerpc_uint16_coder_pp(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov, void *ptr,
                           struct dcerpc_uint32_pretty_printer *pp)
{
        if (pdu->coders->uint16_coder_pp) {
                return pdu->coders->uint16_coder_pp(name, ctx, pdu,
                                                    iov, ptr, pp);
        }
        return -1;
}

/*
 * An enum without [v1_enum]: NDR32 codes it as 16 bits, but NDR64 codes
 * every enum as 32 bits ([MS-RPCE] 2.2.5.2.2). ptr is a uint16_t *; a
 * decoded value that does not fit is an error. YAML/JSON as
 * dcerpc_uint16_coder_pp.
 */
int dcerpc_enum16_coder(char *name, struct dcerpc_context *ctx,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, void *ptr,
                        struct dcerpc_uint32_pretty_printer *pp)
{
        uint32_t v;

        if (pdu->encoding != ENCODING_NDR || !pdu->ndr64) {
                return dcerpc_uint16_coder_pp(name, ctx, pdu, iov,
                                              ptr, pp);
        }
        v = *(uint16_t *)ptr;
        if (ndr_uint32_coder(name, ctx, pdu, iov, &v)) {
                return -1;
        }
        if (pdu->direction == DCERPC_DECODE && !pdu->is_conformance_run) {
                if (v > UINT16_MAX) {
                        return -1;
                }
                *(uint16_t *)ptr = (uint16_t)v;
        }
        return 0;
}

int
dcerpc_carray_coder(char *name, struct dcerpc_context *ctx,
                 struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov,
                 uint32_t num, void *ptr, int elem_size, dcerpc_coder coder)
{
        if (pdu->coders->carray_coder) {
                return pdu->coders->carray_coder(name, ctx, pdu, iov,
                                                 num, ptr, elem_size, coder);
        }
        return -1;
}

/*
 * Conformant array of plain values (integers, strings, SIDs, ...). Same
 * as dcerpc_carray_coder() in NDR; YAML/JSON show a list of bare values.
 * The element coder is called with a NULL name.
 */
int
dcerpc_scalar_carray_coder(char *name, struct dcerpc_context *ctx,
                           struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov,
                           uint32_t num, void *ptr, int elem_size,
                           dcerpc_coder coder)
{
        if (pdu->coders->scalar_carray_coder) {
                return pdu->coders->scalar_carray_coder(name, ctx, pdu, iov, num, ptr,
                                                        elem_size, coder);
        }
        return -1;
}

int
dcerpc_bytes_coder(char *name, struct dcerpc_context *ctx,
                   struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->coders->bytes_coder) {
                return pdu->coders->bytes_coder(name, ctx, pdu,
                                                iov, ptr);
        }
        return -1;
}

int
dcerpc_varying_bytes_coder(char *name, struct dcerpc_context *ctx,
                           struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->coders->varying_bytes_coder) {
                return pdu->coders->varying_bytes_coder(name, ctx, pdu,
                                                        iov, ptr);
        }
        return -1;
}

/*
 * dcerpc_varying_bytes_coder() for a struct field whose size and length
 * are other fields of the struct (STRING's MaximumLength and Length):
 * the caller sets them as size_is and length_is, which a deferred
 * pointer keeps, and on decode the bytes must be exactly that long, or
 * a reader using the length fields reads past them. YAML/JSON carry only
 * the bytes, so there only the length is checked.
 */
int
dcerpc_varying_bytes_checked_coder(char *name, struct dcerpc_context *ctx,
                                   struct dcerpc_pdu *pdu,
                                   struct dcerpc_iovec *iov, void *ptr)
{
        struct dcerpc_varying_bytes *b = ptr;
        uint32_t size_is = pdu->size_is;
        uint32_t length_is = pdu->length_is;

        if (dcerpc_varying_bytes_coder(name, ctx, pdu, iov, ptr)) {
                return -1;
        }
        if (pdu->direction != DCERPC_DECODE || pdu->is_conformance_run) {
                return 0;
        }
        if (b->len != length_is ||
            (pdu->encoding == ENCODING_NDR && b->max_count != size_is)) {
                dcerpc_set_error(ctx, "DCERPC %s holds %u of %u bytes, "
                                 "its length fields say %u of %u",
                                 name ? name : "array", b->len,
                                 b->max_count, length_is, size_is);
                return -1;
        }
        return 0;
}

int
dcerpc_fixed_bytes_coder(char *name, struct dcerpc_context *ctx,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov,
                         uint8_t *data, uint32_t len)
{
        struct dcerpc_bytes b;
        uint32_t i;

        if (pdu->encoding == ENCODING_NDR) {
                for (i = 0; i < len; i++) {
                        if (ndr_uint8_coder(name, ctx, pdu, iov, &data[i])) {
                                return -1;
                        }
                }
                return 0;
        }

        /* Text encodings: a hex string, which must hold exactly len bytes */
        b.len = len;
        b.data = data;
        if (dcerpc_bytes_coder(name, ctx, pdu, iov, &b)) {
                return -1;
        }
        if (pdu->direction == DCERPC_DECODE) {
                if (b.len != len) {
                        printf("%s must be %u bytes, not %u\n",
                               name, len, b.len);
                        return -1;
                }
                memcpy(data, b.data, len);
        }
        return 0;
}

int dcerpc_union_coder(char *name, struct dcerpc_context *ctx,
                       struct dcerpc_pdu *pdu,
                       struct dcerpc_iovec *iov,
                       uint32_t *switch_is, void *ptr, dcerpc_coder coder)
{
        if (pdu->coders->union_coder) {
                return pdu->coders->union_coder(name, ctx, pdu, iov,
                                                switch_is, ptr, coder);
        }
        return -1;
}

/*
 * On decode the union's discriminant comes from the wire, but the caller
 * already knows which arm it wants: switch_is is the [switch_is] value
 * (the request's level for a reply, the struct's Level field decoded just
 * before an embedded union). A peer sending a different discriminant
 * would have the arm decoded as one type and read by the caller as
 * another, so refuse it. The conformance run decodes ahead of the fields
 * switch_is comes from, so only the data run is checked.
 */
static int
dcerpc_union_check_discriminant(struct dcerpc_context *ctx,
                                struct dcerpc_pdu *pdu,
                                uint64_t switch_is, uint64_t wire)
{
        if (pdu->direction != DCERPC_DECODE || pdu->is_conformance_run) {
                return 0;
        }
        if (wire != switch_is) {
                dcerpc_set_error(ctx, "DCERPC union discriminant %llu, "
                                 "expected %llu",
                                 (unsigned long long)wire,
                                 (unsigned long long)switch_is);
                return -1;
        }
        return 0;
}

/*
 * NDR for a non-encapsulated union with a statically known arm alignment
 * (ndr32_align/ndr64_align, the largest alignment of all the arms): the
 * discriminant, 16 bits in NDR32 and 32 in NDR64 for a plain enum
 * (disc16) or 32 bits otherwise, then the arm. NDR64 aligns the arm to
 * the arms' alignment ([MS-RPCE] 2.2.5.3.4.4); NDR32 only to the selected
 * arm's own, which its coder does: "the NDR alignment of a union is
 * determined by the tag type and the arm actually to be transmitted, not
 * the largest of the union arms" ([C706] 14.3.2; 14.3.8 represents a
 * union as the tag followed by the selected member). The largest arm only
 * counts for the alignment of a structure the union is a member of.
 * Windows' DsRolerGetPrimaryDomainInformation reply for
 * DsRoleOperationState has the 2-aligned arm right after the 16-bit
 * discriminant, although the other arms are 4-aligned.
 */
static int
ndr_aligned_union_coder(char *name, struct dcerpc_context *ctx,
                        struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                        uint32_t *switch_is, void *ptr, dcerpc_coder coder,
                        int disc16, int ndr32_align, int ndr64_align)
{
        int max_alignment;

        /* NDR64 aligns the whole union to its largest alignment */
        if (pdu->ndr64 && !pdu->is_conformance_run &&
            dcerpc_iov_align(pdu, iov, ndr64_align > 4 ? ndr64_align : 4)) {
                return -1;
        }
        if (disc16) {
                uint16_t level;

                if (*switch_is > UINT16_MAX) {
                        return -1;
                }
                level = (uint16_t)*switch_is;
                if (dcerpc_enum16_coder("", ctx, pdu, iov, &level, NULL)) {
                        return -1;
                }
                if (dcerpc_union_check_discriminant(ctx, pdu, *switch_is,
                                                    level)) {
                        return -1;
                }
                *switch_is = level;
        } else {
                uint32_t level = *switch_is;

                if (dcerpc_uint32_coder("", ctx, pdu, iov, &level)) {
                        return -1;
                }
                if (dcerpc_union_check_discriminant(ctx, pdu, *switch_is,
                                                    level)) {
                        return -1;
                }
                *switch_is = level;
        }

        dcerpc_set_switch_is(pdu, *switch_is);
        (void)ndr32_align;
        if (pdu->ndr64 && !pdu->is_conformance_run &&
            dcerpc_iov_align(pdu, iov, ndr64_align)) {
                return -1;
        }
        /*
         * NDR32 aligns the discriminant to its own size and the arm to
         * its own ([C706] 14.3.2), so the arm must not raise the
         * alignment the union starts at (Windows'
         * LsarQueryInformationPolicy replies have the 16-bit discriminant
         * right after the pointer and an 8-aligned arm 8-aligned).
         */
        max_alignment = pdu->max_alignment;
        if (coder(name, ctx, pdu, iov, ptr)) {
                return -1;
        }
        if (pdu->is_conformance_run && !pdu->ndr64) {
                pdu->max_alignment = max_alignment;
        }
        return 0;
}

/*
 * A union whose discriminant is a plain enum (switch_type is not a
 * [v1_enum]): in NDR the discriminant is 16 bits in NDR32 and 32 bits in
 * NDR64, like any plain enum (dcerpc_enum16_coder), and the arm that
 * follows is aligned to ndr64_align, the largest alignment of all the
 * arms, in NDR64 and to its own in NDR32 (ndr32_align is unused). YAML/JSON
 * are the same as dcerpc_union_coder.
 */
int dcerpc_union_enum16_coder(char *name, struct dcerpc_context *ctx,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov,
                              uint32_t *switch_is, void *ptr,
                              dcerpc_coder coder,
                              int ndr32_align, int ndr64_align)
{
        if (pdu->encoding != ENCODING_NDR) {
                return dcerpc_union_coder(name, ctx, pdu, iov, switch_is,
                                          ptr, coder);
        }
        return ndr_aligned_union_coder(name, ctx, pdu, iov, switch_is, ptr,
                                       coder, 1, ndr32_align, ndr64_align);
}

/*
 * A union whose discriminant is 32 bits (a [v1_enum] or an integer
 * switch_type) in both NDR32 and NDR64, with the arm aligned as in
 * dcerpc_union_enum16_coder(). dcerpc_union_coder codes the discriminant as
 * 64 bits in NDR64, which is only the same on the wire when the arms are
 * 8-aligned and the stub is little-endian. YAML/JSON are the same as
 * dcerpc_union_coder.
 */
int dcerpc_union_u32_coder(char *name, struct dcerpc_context *ctx,
                           struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov,
                           uint32_t *switch_is, void *ptr,
                           dcerpc_coder coder,
                           int ndr32_align, int ndr64_align)
{
        if (pdu->encoding != ENCODING_NDR) {
                return dcerpc_union_coder(name, ctx, pdu, iov, switch_is,
                                          ptr, coder);
        }
        return ndr_aligned_union_coder(name, ctx, pdu, iov, switch_is, ptr,
                                       coder, 0, ndr32_align, ndr64_align);
}

int dcerpc_struct_coder(char *name, struct dcerpc_context *ctx,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov,
                        void *ptr, dcerpc_coder coder)
{
        if (pdu->coders->struct_coder) {
                return pdu->coders->struct_coder(name, ctx, pdu, iov,
                                                 ptr, coder);
        }
        return -1;
}

/*
 * An array element that is a structure: in NDR aligned (and in NDR64
 * padded) as dcerpc_aligned_struct_coder does; in YAML/JSON its members
 * are coded directly, as list items are not nested under a key.
 */
int dcerpc_aligned_element_coder(char *name, struct dcerpc_context *ctx,
                                 struct dcerpc_pdu *pdu,
                                 struct dcerpc_iovec *iov,
                                 void *ptr, dcerpc_coder coder,
                                 int ndr32_align, int ndr64_align)
{
        if (pdu->encoding != ENCODING_NDR) {
                return coder(name, ctx, pdu, iov, ptr);
        }
        return dcerpc_aligned_struct_coder(name, ctx, pdu, iov, ptr,
                                           coder, ndr32_align, ndr64_align);
}

/*
 * A structure whose NDR alignment is known statically (idlcomp computes it
 * from the member types): ndr32_align/ndr64_align for NDR32/NDR64. In NDR
 * the structure starts at that alignment and NDR64 pads its end to it
 * ([MS-RPCE] 2.2.5.3.4.1). YAML/JSON are the same as dcerpc_struct_coder.
 */
int dcerpc_aligned_struct_coder(char *name, struct dcerpc_context *ctx,
                                struct dcerpc_pdu *pdu,
                                struct dcerpc_iovec *iov,
                                void *ptr, dcerpc_coder coder,
                                int ndr32_align, int ndr64_align)
{
        int align;

        if (pdu->encoding != ENCODING_NDR) {
                return dcerpc_struct_coder(name, ctx, pdu, iov, ptr,
                                           coder);
        }
        align = pdu->ndr64 ? ndr64_align : ndr32_align;
        if (pdu->is_conformance_run) {
                if (pdu->max_alignment < align) {
                        pdu->max_alignment = align;
                }
                return coder(name, ctx, pdu, iov, ptr);
        }
        if (dcerpc_iov_align(pdu, iov, align)) {
                return -1;
        }
        if (coder(name, ctx, pdu, iov, ptr)) {
                return -1;
        }
        if (pdu->ndr64) {
                return dcerpc_iov_align(pdu, iov, align);
        }
        return 0;
}

int
dcerpc_ptr_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr,
                 enum ptr_type type, dcerpc_coder coder)
{
        if (pdu->coders->ptr_coder) {
                return pdu->coders->ptr_coder(name, dce, pdu, iov,
                                              ptr, type, coder);
        }
        return -1;
}

int
dcerpc_utf16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov,
                   void *ptr)
{
        if (pdu->coders->utf16_coder) {
                return pdu->coders->utf16_coder(name, ctx, pdu,
                                                iov, ptr);
        }
        return -1;
}

int
dcerpc_utf16z_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov,
                    void *ptr)
{
        if (pdu->coders->utf16z_coder) {
                return pdu->coders->utf16z_coder(name, ctx, pdu,
                                                 iov, ptr);
        }
        return -1;
}


int
dcerpc_header_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov,
                    struct dcerpc_header *hdr)
{
        uint8_t saved_drep;
        int rc = 0;

        /* Major Version */
        if (dcerpc_uint8_coder("RpcVersion", ctx, pdu, iov, &hdr->rpc_vers)) {
                return -1;
        }
        /* Minor Version */
        if (dcerpc_uint8_coder("RpcVersionMinor", ctx, pdu, iov, &hdr->rpc_vers_minor)) {
                return -1;
        }
        /* Packet Type */
        if (dcerpc_uint8_coder("PType", ctx, pdu, iov, &hdr->PTYPE)) {
                return -1;
        }
        /* Flags */
        if (dcerpc_uint8_coder("PFCFlags", ctx, pdu, iov, &hdr->pfc_flags)) {
                return -1;
        }

        /* Data Representation */
        if (dcerpc_uint8_coder("DREP", ctx, pdu, iov, &hdr->packed_drep[0])) {
                return -1;
        }
        if (dcerpc_uint8_coder("DREP", ctx, pdu, iov, &hdr->packed_drep[1])) {
                return -1;
        }
        if (dcerpc_uint8_coder("DREP", ctx, pdu, iov, &hdr->packed_drep[2])) {
                return -1;
        }
        if (dcerpc_uint8_coder("DREP", ctx, pdu, iov, &hdr->packed_drep[3])) {
                return -1;
        }

        /*
         * The rest of the header is in the byte order of this header's
         * DREP. When peeking at a reply fragment header (hdr is not
         * pdu->hdr), pdu->hdr still holds the request's DREP, and a server
         * may answer in a different byte order (Windows always replies
         * little-endian), so use the decoded DREP for these fields.
         */
        saved_drep = pdu->hdr.packed_drep[0];
        pdu->hdr.packed_drep[0] = hdr->packed_drep[0];

        /* Fragment len */
        if (dcerpc_uint16_coder("FragmentLength", ctx, pdu, iov, &hdr->frag_length) ||
            /* Auth len */
            dcerpc_uint16_coder("AuthLength", ctx, pdu, iov, &hdr->auth_length) ||
            /* Call id */
            dcerpc_uint32_coder("CallId", ctx, pdu, iov, &hdr->call_id)) {
                rc = -1;
        }

        if (hdr != &pdu->hdr) {
                pdu->hdr.packed_drep[0] = saved_drep;
        }
        return rc;
}

/*
 * The connection-oriented PDUs after the header (bind, request,
 * response, ...) and the transport that sends them over an SMB2 named
 * pipe. Built without libsmb2 only the stubs at the end of this block
 * remain.
 */
#ifdef HAVE_LIBSMB2

/*
 * p_syntax_id_t.if_version is a single u_int32 with the major version in
 * the low 16 bits and the minor version in the high 16 bits, so it must be
 * coded as one 32-bit value to come out right in big-endian PDUs.
 */
static int
dcerpc_syntax_version_coder(char *name, struct dcerpc_context *ctx,
                            struct dcerpc_pdu *pdu,
                            struct dcerpc_iovec *iov,
                            p_syntax_id_t *syntax)
{
        uint32_t v = syntax->vers | ((uint32_t)syntax->vers_minor << 16);

        if (dcerpc_uint32_coder(name, ctx, pdu, iov, &v)) {
                return -1;
        }
        syntax->vers = v & 0xffff;
        syntax->vers_minor = v >> 16;
        return 0;
}

static int
dcerpc_bind_coder(struct dcerpc_context *ctx,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_bind_pdu *bind,
                  struct dcerpc_iovec *iov)
{
        size_t end;
        int i, j;
        uint16_t v;

        /* Max Xmit Frag */
        if (dcerpc_uint16_coder("MaxXmitFrag", ctx, pdu, iov, &bind->max_xmit_frag)) {
                return -1;
        }

        /* Max Recv Frag */
        if (dcerpc_uint16_coder("MaxRecvFrag", ctx, pdu, iov, &bind->max_recv_frag)) {
                return -1;
        }

        /* Association Group */
        if (dcerpc_uint32_coder("AssociationGroup", ctx, pdu, iov, &bind->assoc_group_id)) {
                return -1;
        }

        /* Number Of Context Items */
        if (dcerpc_uint8_coder("NumContextElement", ctx, pdu, iov, &bind->n_context_elem)) {
                return -1;
        }
        iov->offset += 3;

        //qqq TODO allocate p_cont_elem on decode
        for (i = 0; i < bind->n_context_elem; i++) {
                if (dcerpc_uint16_coder("PContId", ctx, pdu, iov, &pdu->bind.p_cont_elem[i].p_cont_id)) {
                        return -1;
                }
                if (dcerpc_uint8_coder("NumTransferSyntax", ctx, pdu, iov, &pdu->bind.p_cont_elem[i].n_transfer_syn)) {
                        return -1;
                }
                iov->offset += 1;
                /* Abstract Syntax */
                //qqq TODO allocate abstract_syntax on decode
                if (dcerpc_uuid_coder("SyntaxUUID", ctx, pdu, iov, &pdu->bind.p_cont_elem[i].abstract_syntax->uuid)) {
                        return -1;
                }
                if (dcerpc_syntax_version_coder("AbstractSyntaxVersion", ctx, pdu, iov, pdu->bind.p_cont_elem[i].abstract_syntax)) {
                        return -1;
                }
                //qqq TODO allocate transfer_syntaxes on decode
                for (j = 0; j < pdu->bind.p_cont_elem[i].n_transfer_syn; j++) {
                        if (dcerpc_uuid_coder("TransferSyntax", ctx, pdu, iov, &pdu->bind.p_cont_elem[i].transfer_syntaxes[j]->uuid)) {
                                return -1;
                        }
                        if (dcerpc_syntax_version_coder("TransferSyntaxVersion", ctx, pdu, iov, pdu->bind.p_cont_elem[i].transfer_syntaxes[j])) {
                                return -1;
                        }
                }

        }
        /* Fixup fragment length */
        end = iov->offset;
        v = (uint16_t)end;
        iov->offset = 8;
        if (dcerpc_uint16_coder("v", ctx, pdu, iov, &v)) {
                return -1;
        }
        iov->offset = end;
        
        return 0;
}

static int
dcerpc_request_coder(struct dcerpc_context *ctx,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_request_pdu *req,
                     struct dcerpc_iovec *iov)
{
        /* Alloc Hint */
        if (dcerpc_uint32_coder("AllocHint", ctx, pdu, iov, &req->alloc_hint)) {
                return -1;
        }

        /* Context ID */
        if (dcerpc_uint16_coder("ContextId", ctx, pdu, iov, &req->context_id)) {
                return -1;
        }
        
        /* Opnum */
        if (dcerpc_uint16_coder("OpNum", ctx, pdu, iov, &req->opnum)) {
                return -1;
        }

        return 0;
}

static int
dcerpc_bind_ack_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                      struct dcerpc_bind_ack_pdu *bind_ack,
                      struct dcerpc_iovec *iov)
{
        int i;
        uint16_t sec_addr_len;

        /* Max Xmit Frag */
        if (dcerpc_uint16_coder("MaxXmitFrag", ctx, pdu, iov, &bind_ack->max_xmit_frag)) {
                return -1;
        }

        /* Max Recv Frag */
        if (dcerpc_uint16_coder("MaxRecvFrag", ctx, pdu, iov, &bind_ack->max_recv_frag)) {
                return -1;
        }

        /* Association Group */
        if (dcerpc_uint32_coder("AssociationGroup", ctx, pdu, iov, &bind_ack->assoc_group_id)) {
                return -1;
        }

        /* Secondary Address Length */
        if (dcerpc_uint16_coder("SecondaryAddressLength", ctx, pdu, iov, &sec_addr_len)) {
                return -1;
        }

        /* Skip the secondary address and realign to 32bit */
        /* TODO: we need to handle the encode case.
        *        it is something like "\\PIPE\\srvsvc"
        */
        if (iov->offset < 0 ||
            (size_t)iov->offset + sec_addr_len > iov->max_offset) {
                dcerpc_set_error(ctx, "DCERPC bind_ack secondary address "
                                 "length out of bounds");
                return -1;
        }
        iov->offset += sec_addr_len;
        iov->offset = (iov->offset + 3) & ~3;
        if (iov->offset < 0 || (size_t)iov->offset > iov->max_offset) {
                dcerpc_set_error(ctx, "DCERPC bind_ack secondary address "
                                 "padding out of bounds");
                return -1;
        }

        /* Number Of Results */
        if (dcerpc_uint8_coder("NumResults", ctx, pdu, iov, &bind_ack->num_results)) {
                return -1;
        }
        if (bind_ack->num_results > MAX_ACK_RESULTS) {
                dcerpc_set_error(ctx, "DCERPC bind_ack has too many "
                                 "results (%u)", bind_ack->num_results);
                return -1;
        }
        iov->offset += 3;

        for (i = 0; i < bind_ack->num_results; i++) {
                if (dcerpc_uint16_coder("AckResult", ctx, pdu, iov, &bind_ack->results[i].ack_result)) {
                        return -1;
                }

                if (dcerpc_uint16_coder("AckReason", ctx, pdu, iov, &bind_ack->results[i].ack_reason)) {
                        return -1;
                }

                if (dcerpc_uuid_coder("UUID", ctx, pdu, iov,
                                   &bind_ack->results[i].uuid)) {
                        return -1;
                }

                if (dcerpc_uint32_coder("SyntaxVersion", ctx, pdu, iov, &bind_ack->results[i].syntax_version)) {
                        return -1;
                }
        }

        return 0;
}

static int
dcerpc_response_coder(struct dcerpc_context *ctx,
                      struct dcerpc_response_pdu *rsp,
                      struct dcerpc_iovec *iov)
{
#ifndef _MSC_VER
        struct dcerpc_pdu *pdu = container_of(rsp, struct dcerpc_pdu, rsp);
#else
        const char* __mptr = (const char*)rsp;
        struct dcerpc_pdu *pdu = (struct dcerpc_pdu*)((char *)__mptr - offsetof(struct dcerpc_pdu, rsp));
#endif /* !_MSC_VER */
    
        if (iov->offset < 0) {
                return -1;
        }

        /* Alloc Hint */
        if (dcerpc_uint32_coder("AllocationHint", ctx, pdu, iov, &rsp->alloc_hint)) {
                return -1;
        }

        if (rsp->alloc_hint > 16*1024*1024) {
                dcerpc_set_error(ctx, "DCERPC RESPONSE alloc_hint out "
                                 "of range.");
                return -1;
        }

        /* Context Id */
        if (dcerpc_uint16_coder("ContextId", ctx, pdu, iov, &rsp->context_id)) {
                return -1;
        }
        
        /* Cancel Count */
        if (dcerpc_uint8_coder("CancelCount", ctx, pdu, iov, &rsp->cancel_count)) {
                return -1;
        }
        iov->offset += 1;


        /* decode the blob */
        pdu->top_level = 1;
        if (pdu->coder("Response", ctx, pdu, iov, pdu->payload) < 0) {
                return -1;
        }

        iov->offset += rsp->alloc_hint;

        return 0;
}

/*
 * Code a whole PDU. ptype is the only PDU type accepted: on decode the
 * type comes from the peer, and the PDU types share storage in the
 * dcerpc_pdu union, so a reply of the wrong type must be refused before
 * its body is decoded into fields that hold something else.
 */
static int
dcerpc_pdu_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, uint8_t ptype)
{
        if (dcerpc_header_coder(ctx, pdu, iov, &pdu->hdr)) {
                return -1;
        }
        if (pdu->hdr.PTYPE != ptype) {
                dcerpc_set_error(ctx, "DCERPC PDU type %d, expected %d",
                                 pdu->hdr.PTYPE, ptype);
                return -1;
        }
        /*
         * As in dce_frags_status(): no auth trailer was negotiated,
         * except the one a BIND_ACK answers our authenticated BIND with
         * (smb2_bind_cb() checks it).
         */
        if (pdu->direction == DCERPC_DECODE && pdu->hdr.auth_length != 0 &&
            !(ptype == PDU_TYPE_BIND_ACK && ctx->sch != NULL)) {
                dcerpc_set_error(ctx, "DCERPC PDU has an auth trailer but "
                                 "none was negotiated");
                return -1;
        }
        /* A BIND is only ever encoded: its decode has nowhere to go. */
        if (pdu->hdr.PTYPE == PDU_TYPE_BIND &&
            pdu->direction == DCERPC_DECODE) {
                dcerpc_set_error(ctx, "DCERPC can not decode a BIND");
                return -1;
        }

        switch (pdu->hdr.PTYPE) {
        case PDU_TYPE_BIND:
                if (dcerpc_bind_coder(ctx, pdu, &pdu->bind, iov)) {
                        return -1;
                }
                break;
        case PDU_TYPE_BIND_ACK:
                if (dcerpc_bind_ack_coder(ctx, pdu, &pdu->bind_ack, iov)) {
                        return -1;
                }
                break;
        case PDU_TYPE_REQUEST:
                if (dcerpc_request_coder(ctx, pdu, &pdu->req, iov)) {
                        return -1;
                }
                break;
        case PDU_TYPE_RESPONSE:
                if (dcerpc_response_coder(ctx, &pdu->rsp, iov)) {
                        return -1;
                }
                break;
        default:
                dcerpc_set_error(ctx, "DCERPC No decoder for PDU type %d",
                                 pdu->hdr.PTYPE);
                return -1;
        }

        return 0;
}

/*
 * Multi-fragment RESPONSE reassembly over SMB named pipes.
 *
 * FSCTL_PIPE_TRANSCEIVE may return only the first fragment(s). Further
 * fragments must be read from the pipe with SMB2 READ until PFC_LAST_FRAG.
 *
 * Return values for dce_frags_status():
 *   0  complete (single fragment or full multi-fragment set in buffer)
 *   1  need more data from the pipe
 *  -1  hard error (corrupt headers / lengths)
 */
#define DCE_FRAG_DONE       0
#define DCE_FRAG_NEED_MORE  1
#define DCE_FRAG_ERROR     (-1)

#define DCE_FRAG_READ_SIZE  65536

static int
dce_frags_status(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                 const uint8_t *buf, size_t len)
{
        size_t offset = 0;
        uint32_t saved_dir = pdu->direction;

        pdu->direction = DCERPC_DECODE;

        if (len < 16) {
                pdu->direction = saved_dir;
                return DCE_FRAG_NEED_MORE;
        }

        while (1) {
                struct dcerpc_header hdr;
                struct dcerpc_iovec tmpiov;

                if (len - offset < 16) {
                        pdu->direction = saved_dir;
                        return DCE_FRAG_NEED_MORE;
                }

                /* dcerpc_header_coder only reads when decoding */
                tmpiov = (struct dcerpc_iovec){
                        .buf = (uint8_t *)(void *)(buf + offset),
                        .max_offset = len - offset,
                };
                if (dcerpc_header_coder(dce, pdu, &tmpiov, &hdr)) {
                        pdu->direction = saved_dir;
                        return DCE_FRAG_ERROR;
                }

                if (hdr.rpc_vers != 5 || hdr.rpc_vers_minor != 0) {
                        pdu->direction = saved_dir;
                        return DCE_FRAG_ERROR;
                }
                /* A reply, or a fragment of one, to some other call */
                if (hdr.call_id != pdu->call_id) {
                        dcerpc_set_error(dce, "DCERPC reply call_id %u, "
                                         "expected %u", hdr.call_id,
                                         pdu->call_id);
                        pdu->direction = saved_dir;
                        return DCE_FRAG_ERROR;
                }
                /*
                 * Without a security context a reply has no auth
                 * trailer; one that claims to would have its trailer
                 * decoded as stub data, unverified. With one,
                 * dce_unfragment_auth() checks every trailer.
                 */
                if (hdr.auth_length != 0 && dce->sch == NULL) {
                        dcerpc_set_error(dce, "DCERPC reply has an auth "
                                         "trailer but none was negotiated");
                        pdu->direction = saved_dir;
                        return DCE_FRAG_ERROR;
                }

                /* Non-RESPONSE (FAULT, BIND_ACK, ...) is a single PDU */
                if (hdr.PTYPE != PDU_TYPE_RESPONSE) {
                        /* ... and can not follow RESPONSE fragments */
                        if (offset != 0) {
                                dcerpc_set_error(dce, "DCERPC PDU type %d "
                                                 "in a RESPONSE fragment set",
                                                 hdr.PTYPE);
                                pdu->direction = saved_dir;
                                return DCE_FRAG_ERROR;
                        }
                        if (hdr.frag_length < 16) {
                                pdu->direction = saved_dir;
                                return DCE_FRAG_ERROR;
                        }
                        if (offset + hdr.frag_length > len) {
                                pdu->direction = saved_dir;
                                return DCE_FRAG_NEED_MORE;
                        }
                        pdu->direction = saved_dir;
                        return DCE_FRAG_DONE;
                }

                /* RESPONSE fragments are at least common+response header */
                if (hdr.frag_length < 24) {
                        dcerpc_set_error(dce, "DCERPC fragment length out "
                                         "of bounds");
                        pdu->direction = saved_dir;
                        return DCE_FRAG_ERROR;
                }
                if (offset + hdr.frag_length > len) {
                        pdu->direction = saved_dir;
                        return DCE_FRAG_NEED_MORE;
                }
                if (hdr.pfc_flags & PFC_LAST_FRAG) {
                        pdu->direction = saved_dir;
                        return DCE_FRAG_DONE;
                }
                offset += hdr.frag_length;
        }
}

/*
 * Collapse a complete multi-fragment RESPONSE in-place into a single
 * fragment (first header + concatenated stubs). Call only after
 * dce_frags_status() returned DCE_FRAG_DONE.
 */
static int
dce_unfragment_iov(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov)
{
        int offset = 0;
        int unfragment_len;
        struct dcerpc_header hdr, next_hdr;
        struct dcerpc_iovec tmpiov;
        uint32_t saved_dir = pdu->direction;

        pdu->direction = DCERPC_DECODE;
        iov->offset = 0;
        if (dcerpc_header_coder(dce, pdu, iov, &hdr)) {
                pdu->direction = saved_dir;
                return -1;
        }
        iov->offset = 0;
        /*
         * A single PDU (any non-RESPONSE, or a RESPONSE that is its own
         * last fragment) ends at its frag_length, and the reply holds
         * nothing after it: bytes past it are not part of the stub.
         */
        if (hdr.PTYPE != PDU_TYPE_RESPONSE ||
            (hdr.pfc_flags & PFC_LAST_FRAG)) {
                pdu->direction = saved_dir;
                if (hdr.frag_length != iov->max_offset) {
                        dcerpc_set_error(dce, "DCERPC PDU of %u bytes in "
                                         "a %zu byte reply",
                                         hdr.frag_length, iov->max_offset);
                        return -1;
                }
                return 0;
        }

        if (hdr.frag_length < 24 || (size_t)hdr.frag_length > iov->max_offset) {
                dcerpc_set_error(dce, "DCERPC fragment length out of "
                                 "bounds");
                pdu->direction = saved_dir;
                return -1;
        }

        offset += hdr.frag_length;
        unfragment_len = hdr.frag_length;
        do {
                if (offset < 0 || (size_t)offset > iov->max_offset ||
                    iov->max_offset - (size_t)offset < 24) {
                        dcerpc_set_error(dce, "DCERPC truncated multi-"
                                         "fragment response");
                        pdu->direction = saved_dir;
                        return -1;
                }

                tmpiov = (struct dcerpc_iovec){
                        .buf = iov->buf + offset,
                        .max_offset = iov->max_offset - offset,
                };
                if (dcerpc_header_coder(dce, pdu, &tmpiov, &next_hdr)) {
                        pdu->direction = saved_dir;
                        return -1;
                }

                if (next_hdr.PTYPE != PDU_TYPE_RESPONSE) {
                        dcerpc_set_error(dce, "DCERPC PDU type %d in a "
                                         "RESPONSE fragment set",
                                         next_hdr.PTYPE);
                        pdu->direction = saved_dir;
                        return -1;
                }
                if (next_hdr.frag_length < 24 ||
                    (size_t)offset + next_hdr.frag_length > iov->max_offset) {
                        dcerpc_set_error(dce, "DCERPC next fragment "
                                         "length out of bounds");
                        pdu->direction = saved_dir;
                        return -1;
                }

                memmove(iov->buf + unfragment_len, iov->buf + offset + 24,
                        next_hdr.frag_length - 24);
                unfragment_len += next_hdr.frag_length - 24;
                offset += next_hdr.frag_length;

                /*
                 * frag_length is 16-bit; combined stubs may exceed 64K.
                 * The decoder uses alloc_hint / NDR layout, not frag_length,
                 * once iov->max_offset is set to the full reassembled size.
                 */
                if (unfragment_len <= 0xffff) {
                        hdr.frag_length = (uint16_t)unfragment_len;
                }
                if (next_hdr.pfc_flags & PFC_LAST_FRAG) {
                        hdr.pfc_flags |= PFC_LAST_FRAG;
                }
                /* Write updated first-fragment header back */
                pdu->direction = DCERPC_ENCODE;
                iov->offset = 0;
                if (dcerpc_header_coder(dce, pdu, iov, &hdr)) {
                        pdu->direction = saved_dir;
                        return -1;
                }
                pdu->direction = DCERPC_DECODE;
        } while (!(next_hdr.pfc_flags & PFC_LAST_FRAG));

        /* As for a single PDU: nothing may follow the last fragment */
        if ((size_t)offset != iov->max_offset) {
                dcerpc_set_error(dce, "DCERPC %zu bytes after the last "
                                 "fragment", iov->max_offset - offset);
                pdu->direction = saved_dir;
                return -1;
        }

        iov->offset = 0;
        iov->max_offset = (size_t)unfragment_len;
        pdu->direction = saved_dir;
        return 0;
}

/*
 * dce_unfragment_iov() for a schannel context: check and unprotect each
 * fragment of the reply in place, then collapse them into one PDU (the
 * first header, then the stubs without padding or auth trailers) with
 * auth_length 0. Every RESPONSE fragment, and a FAULT that has one, must
 * carry a valid auth trailer; only an unsigned FAULT on its own, which a
 * server may send when it rejects the auth, is taken as it is. Any
 * failed check of a trailer ends the secure channel.
 */
static int
dce_unfragment_auth(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov)
{
        int seal = dce->auth_level == DCERPC_AUTH_LEVEL_PRIVACY;
        size_t min_token = seal ? DCERPC_SCHANNEL_TOKEN_LEN :
                DCERPC_SCHANNEL_SIGN_TOKEN_LEN;
        size_t offset = 0, out = 24;
        uint32_t saved_dir = pdu->direction;
        struct dcerpc_header first, hdr;
        int last;

        pdu->direction = DCERPC_DECODE;
        do {
                struct dcerpc_iovec tmpiov = {
                        .buf = iov->buf + offset,
                        .max_offset = iov->max_offset - offset,
                };
                uint8_t *f = iov->buf + offset;
                uint32_t context_id;
                size_t t, stub;
                uint8_t pad;

                if (iov->max_offset - offset < 24 ||
                    dcerpc_header_coder(dce, pdu, &tmpiov, &hdr)) {
                        goto fail;
                }
                if (offset == 0) {
                        first = hdr;
                }
                if (hdr.frag_length < 24 ||
                    hdr.frag_length > iov->max_offset - offset) {
                        dcerpc_set_error(dce, "DCERPC fragment length out "
                                         "of bounds");
                        goto fail;
                }
                if (hdr.auth_length == 0) {
                        if (offset == 0 && hdr.PTYPE == PDU_TYPE_FAULT &&
                            hdr.frag_length == iov->max_offset) {
                                iov->offset = 0;
                                pdu->direction = saved_dir;
                                return 0;
                        }
                        dcerpc_set_error(dce, "DCERPC reply without an auth "
                                         "trailer on a schannel context");
                        goto fail;
                }
                if (hdr.auth_length < min_token ||
                    (size_t)hdr.auth_length + DCE_SEC_TRAILER_LEN + 24 >
                    hdr.frag_length) {
                        dcerpc_set_error(dce, "DCERPC reply auth_length %u "
                                         "out of bounds", hdr.auth_length);
                        goto fail;
                }
                t = hdr.frag_length - hdr.auth_length - DCE_SEC_TRAILER_LEN;
                pad = f[t + 2];
                if (hdr.packed_drep[0] & DCERPC_DR_LITTLE_ENDIAN) {
                        context_id = (uint32_t)f[t + 4] |
                                ((uint32_t)f[t + 5] << 8) |
                                ((uint32_t)f[t + 6] << 16) |
                                ((uint32_t)f[t + 7] << 24);
                } else {
                        context_id = ((uint32_t)f[t + 4] << 24) |
                                ((uint32_t)f[t + 5] << 16) |
                                ((uint32_t)f[t + 6] << 8) |
                                (uint32_t)f[t + 7];
                }
                if (f[t] != DCERPC_AUTH_TYPE_SCHANNEL ||
                    f[t + 1] != dce->auth_level ||
                    pad >= DCE_AUTH_PAD_ALIGN || pad > t - 24 ||
                    context_id != DCE_AUTH_CONTEXT_ID) {
                        dcerpc_set_error(dce, "DCERPC reply auth trailer "
                                         "is not ours");
                        goto fail;
                }
                if (dcerpc_schannel_unprotect(dce->sch, seal,
                                              f + 24, t - 24,
                                              dce->header_sign ? f : f + 24,
                                              dce->header_sign ?
                                              t + DCE_SEC_TRAILER_LEN :
                                              t - 24,
                                              f + t + DCE_SEC_TRAILER_LEN,
                                              hdr.auth_length)) {
                        dcerpc_set_error(dce, "DCERPC reply failed the "
                                         "schannel check");
                        goto fail;
                }
                stub = t - 24 - pad;
                if (offset != 0) {
                        memmove(iov->buf + out, f + 24, stub);
                }
                out += stub;
                offset += hdr.frag_length;
                last = (hdr.pfc_flags & PFC_LAST_FRAG) ||
                       hdr.PTYPE != PDU_TYPE_RESPONSE;
                if (!last && iov->max_offset - offset < 24) {
                        dcerpc_set_error(dce, "DCERPC truncated multi-"
                                         "fragment response");
                        goto fail;
                }
        } while (!last);

        /* Nothing may follow the last fragment */
        if (offset != iov->max_offset) {
                dcerpc_set_error(dce, "DCERPC %zu bytes after the last "
                                 "fragment", iov->max_offset - offset);
                goto fail;
        }

        /*
         * The collapsed PDU has no trailer. frag_length is 16 bits and
         * combined stubs may be longer: the decoder goes by max_offset.
         */
        if (out <= 0xffff) {
                first.frag_length = (uint16_t)out;
        }
        first.auth_length = 0;
        first.pfc_flags |= PFC_LAST_FRAG;
        pdu->direction = DCERPC_ENCODE;
        iov->offset = 0;
        if (dcerpc_header_coder(dce, pdu, iov, &first)) {
                goto fail;
        }
        iov->offset = 0;
        iov->max_offset = out;
        pdu->direction = saved_dir;
        return 0;

 fail:
        pdu->direction = saved_dir;
        return -1;
}

static int
dcerpc_reasm_append(struct dcerpc_pdu *pdu, const uint8_t *data, size_t len)
{
        size_t need;

        if (len == 0) {
                return 0;
        }
        need = pdu->reasm_len + len;
        if (need > pdu->reasm_cap) {
                size_t new_cap = pdu->reasm_cap ? pdu->reasm_cap : 65536;
                uint8_t *nbuf;

                while (new_cap < need) {
                        if (new_cap > 8 * 1024 * 1024) {
                                return -ENOMEM;
                        }
                        new_cap *= 2;
                }
                if (new_cap > 16 * 1024 * 1024) {
                        return -ENOMEM;
                }
                nbuf = realloc(pdu->reasm_buf, new_cap);
                if (nbuf == NULL) {
                        return -ENOMEM;
                }
                pdu->reasm_buf = nbuf;
                pdu->reasm_cap = new_cap;
        }
        memcpy(pdu->reasm_buf + pdu->reasm_len, data, len);
        pdu->reasm_len += len;
        return 0;
}

struct dcerpc_frag_read {
        struct dcerpc_pdu *pdu;
        uint8_t *buf;
};

static void dcerpc_send_pdu_cb_and_free(struct dcerpc_context *dce,
                                        struct dcerpc_pdu *pdu,
                                        int status, void *command_data);
static void dcerpc_finish_call_from_reasm(struct dcerpc_context *dce,
                                          struct dcerpc_pdu *pdu);
static int dcerpc_read_more_frags(struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu);
static void
dcerpc_frag_read_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
        struct dcerpc_frag_read *fr = private_data;
        struct dcerpc_pdu *pdu = fr->pdu;
        struct dcerpc_context *dce = pdu->dce;
        struct smb2_read_reply *rep = command_data;
        uint32_t nread = 0;

        if (pdu->pending.orphaned) {
                free(fr->buf);
                free(fr);
                dcerpc_free_pdu(NULL, pdu);
                return;
        }

        /* A fragment larger than our read buffer: take what we got. */
        if (status == SMB2_STATUS_BUFFER_OVERFLOW) {
                status = SMB2_STATUS_SUCCESS;
        }
        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "DCERPC fragment READ failed "
                               "(0x%08x) %s", status, nterror_to_str(status));
                free(fr->buf);
                free(fr);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -nterror_to_errno(status),
                                           NULL);
                return;
        }

        if (rep) {
                nread = rep->data_length;
        }
        /* fr->buf holds no more than was asked for */
        if (nread > DCE_FRAG_READ_SIZE) {
                smb2_set_error(smb2, "DCERPC fragment READ returned %u "
                               "bytes, more than the %d asked for", nread,
                               DCE_FRAG_READ_SIZE);
                free(fr->buf);
                free(fr);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EIO, NULL);
                return;
        }
        if (nread == 0) {
                smb2_set_error(smb2, "DCERPC fragment READ returned 0 bytes "
                               "before LAST_FRAG");
                free(fr->buf);
                free(fr);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EIO, NULL);
                return;
        }

        if (dcerpc_reasm_append(pdu, fr->buf, nread)) {
                smb2_set_error(smb2, "DCERPC failed to grow reassembly buffer");
                free(fr->buf);
                free(fr);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -ENOMEM, NULL);
                return;
        }

        free(fr->buf);
        free(fr);

        dcerpc_finish_call_from_reasm(dce, pdu);
}

static int
dcerpc_read_more_frags(struct dcerpc_context *dce, struct dcerpc_pdu *pdu)
{
        struct dcerpc_frag_read *fr;
        struct smb2_read_request req;
        struct smb2_pdu *smb2_pdu;

        fr = calloc(1, sizeof(*fr));
        if (fr == NULL) {
                return -ENOMEM;
        }
        fr->pdu = pdu;
        fr->buf = malloc(DCE_FRAG_READ_SIZE);
        if (fr->buf == NULL) {
                free(fr);
                return -ENOMEM;
        }

        memset(&req, 0, sizeof(req));
        req.length = DCE_FRAG_READ_SIZE;
        req.offset = 0;
        req.buf = fr->buf;
        memcpy(req.file_id, dce->file_id, SMB2_FD_SIZE);
        req.minimum_count = 0;
        req.channel = SMB2_CHANNEL_NONE;

        smb2_pdu = smb2_cmd_read_async(dce->smb2, &req, dcerpc_frag_read_cb,
                                       fr);
        if (smb2_pdu == NULL) {
                free(fr->buf);
                free(fr);
                return -ENOMEM;
        }
        smb2_queue_pdu(dce->smb2, smb2_pdu);
        return 0;
}

/*
 * Process reassembly buffer: read more if incomplete, else unfragment
 * and deliver the decoded response.
 */
static void
dcerpc_finish_call_from_reasm(struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu)
{
        struct dcerpc_iovec iov;
        void *payload;
        int st;

        st = dce_frags_status(dce, pdu, pdu->reasm_buf, pdu->reasm_len);
        if (st == DCE_FRAG_NEED_MORE) {
                if (dcerpc_read_more_frags(dce, pdu)) {
                        dcerpc_send_pdu_cb_and_free(dce, pdu, -ENOMEM, NULL);
                }
                return;
        }
        if (st == DCE_FRAG_ERROR) {
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }

        iov = (struct dcerpc_iovec){
                .buf = pdu->reasm_buf,
                .max_offset = pdu->reasm_len,
        };

        if ((dce->sch != NULL ? dce_unfragment_auth(dce, pdu, &iov) :
             dce_unfragment_iov(dce, pdu, &iov))) {
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }

        /*
         * FAULT PDUs are not handled by dcerpc_pdu_coder. Extract the
         * fault status so callers get a useful error instead of
         * "No decoder for PDU type 3".
         */
        if (iov.max_offset >= 3 && iov.buf[2] == PDU_TYPE_FAULT) {
                uint32_t fault_status = 0;

                if (iov.max_offset >= 28) {
                        iov.offset = 24;
                        /* in the FAULT PDU's own byte order */
                        pdu->hdr.packed_drep[0] = iov.buf[4];
                        if (dcerpc_get_uint32(dce, pdu, &iov,
                                              &fault_status)) {
                                fault_status = 0;
                        }
                }
                dcerpc_set_error(dce, "DCERPC FAULT status=0x%08x",
                                 fault_status);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EACCES, NULL);
                return;
        }

        if (dcerpc_pdu_coder(dce, pdu, &iov, PDU_TYPE_RESPONSE)) {
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }

        payload = pdu->payload;
        pdu->payload = NULL;
        dcerpc_send_pdu_cb_and_free(dce, pdu, 0, payload);
}

static void
dcerpc_send_pdu_cb_and_free(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                            int status, void *command_data)
{
        dcerpc_cb pdu_cb = pdu->cb;
        void *pdu_cb_data = pdu->cb_data;

        dcerpc_untrack(dce, &pdu->pending);
        pdu_cb(dce, status, command_data, pdu_cb_data);
        dcerpc_free_pdu(dce, pdu);
}

/*
 * Free the output of a PIPE_TRANSCEIVE reply the callback will not use.
 * libsmb2 decodes every reply whose status is not of error severity
 * (warnings such as BUFFER_OVERFLOW, informational ones) as an ioctl
 * reply with an allocated output, whatever its status; an error reply
 * is a struct smb2_error_reply instead and has no output of ours.
 */
static void
dcerpc_free_ioctl_output(struct smb2_context *smb2, uint32_t status,
                         struct smb2_ioctl_reply *rep)
{
        if (rep == NULL || status == SMB2_STATUS_STOPPED_ON_SYMLINK) {
                return;
        }
        if ((status & SMB2_STATUS_SEVERITY_MASK) ==
            SMB2_STATUS_SEVERITY_ERROR &&
            status != SMB2_STATUS_MORE_PROCESSING_REQUIRED) {
                return;
        }
        smb2_free_data(smb2, rep->output);
        rep->output = NULL;
}

static void
dcerpc_call_cb(struct smb2_context *smb2, int status,
               void *command_data, void *private_data)
{
        struct dcerpc_pdu *pdu = private_data;
        struct dcerpc_context *dce = pdu->dce;
        struct smb2_ioctl_reply *rep = command_data;

        if (pdu->pending.orphaned) {
                dcerpc_free_ioctl_output(smb2, status, rep);
                dcerpc_free_pdu(NULL, pdu);
                return;
        }

        pdu->direction = DCERPC_DECODE;

        /*
         * The response did not fit max_output_response: the output holds
         * the start of it and the rest is read from the pipe.
         */
        if (status == SMB2_STATUS_BUFFER_OVERFLOW) {
                status = SMB2_STATUS_SUCCESS;
        }
        if (status != SMB2_STATUS_SUCCESS) {
                dcerpc_free_ioctl_output(smb2, status, rep);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -nterror_to_errno(status), NULL);
                return;
        }

        dcerpc_mem_free(pdu->payload);
        pdu->payload = NULL;

        pdu->payload = dcerpc_mem_init(pdu->decode_size);
        if (pdu->payload == NULL) {
                smb2_free_data(dce->smb2, rep->output);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -ENOMEM, NULL);
                return;
        }

        /* Seed reassembly buffer from the PIPE_TRANSCEIVE output */
        free(pdu->reasm_buf);
        pdu->reasm_buf = NULL;
        pdu->reasm_len = 0;
        pdu->reasm_cap = 0;

        if (rep->output_count && rep->output) {
                if (dcerpc_reasm_append(pdu, rep->output, rep->output_count)) {
                        smb2_free_data(dce->smb2, rep->output);
                        dcerpc_send_pdu_cb_and_free(dce, pdu, -ENOMEM, NULL);
                        return;
                }
        }
        smb2_free_data(dce->smb2, rep->output);

        dcerpc_finish_call_from_reasm(dce, pdu);
}

/*
 * Encode a REQUEST (header + stub) as a single PDU into the growable
 * iovec iov, which must be empty. Returns the pdu, with the encoded PDU in
 * iov->buf and its length in iov->offset, or NULL with iov freed.
 */
static struct dcerpc_pdu *
dcerpc_encode_request(struct dcerpc_context *dce, int opnum,
                      dcerpc_coder req_coder, void *req,
                      struct dcerpc_iovec *iov)
{
        struct dcerpc_pdu *pdu;

        /* The payload is only the root for allocations while encoding */
        pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE | ENCODING_NDR |
                                  dcerpc_get_ndr_flavor(dce), 1);
        if (pdu == NULL) {
                return NULL;
        }

        pdu->hdr.rpc_vers = 5;
        pdu->hdr.rpc_vers_minor = 0;
        pdu->hdr.PTYPE = PDU_TYPE_REQUEST;
        pdu->hdr.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG;
        pdu->hdr.call_id = dce->call_id++;
        pdu->call_id = pdu->hdr.call_id;
        pdu->hdr.frag_length = 0;
        pdu->hdr.auth_length = 0;
        pdu->req.alloc_hint = 0;
        pdu->req.context_id = dce->tctx_id;
        pdu->req.opnum = opnum;

        if (dcerpc_pdu_coder(dce, pdu, iov, PDU_TYPE_REQUEST)) {
                dcerpc_free_iovec(iov);
                dcerpc_free_pdu(dce, pdu);
                return NULL;
        }

        /* encode the blob */
        pdu->top_level = 1;
        /* Remember the request in case we need to dereference it from the reply */
        dcerpc_set_request(pdu, req);
        if (req_coder("Request", dce, pdu, iov, req)) {
                dcerpc_free_iovec(iov);
                dcerpc_free_pdu(dce, pdu);
                return NULL;
        }
        return pdu;
}

/*
 * Write frag_length, pfc_flags and alloc_hint into the 24 byte REQUEST
 * header at buf.
 */
static int
dcerpc_fixup_request_hdr(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                         uint8_t *buf, size_t frag_len, uint8_t pfc_flags,
                         uint32_t alloc_hint)
{
        struct dcerpc_iovec iov;

        iov = (struct dcerpc_iovec){ .buf = buf, .max_offset = frag_len };

        buf[3] = pfc_flags;
        iov.offset = 8;
        if (dcerpc_set_uint16(dce, pdu, &iov, (uint16_t)frag_len)) {
                return -1;
        }
        iov.offset = 16;
        if (dcerpc_uint32_coder("v", dce, pdu, &iov, &alloc_hint)) {
                return -1;
        }
        return 0;
}

/*
 * Split the single encoded REQUEST in buf into fragments of at most
 * max_frag bytes, stored back to back in pdu->frag_buf. Stub data in all
 * but the last fragment is a multiple of 8 bytes.
 */
static int
dcerpc_fragment_request(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                        const uint8_t *buf, size_t len, size_t max_frag)
{
        const uint8_t *stub = buf + 24;
        size_t stub_len = len - 24;
        size_t max_stub = (max_frag - 24) & ~(size_t)7;
        size_t nfrags, off, o = 0;

        nfrags = (stub_len + max_stub - 1) / max_stub;
        pdu->frag_buf = malloc(stub_len + nfrags * 24);
        if (pdu->frag_buf == NULL) {
                dcerpc_set_error(dce, "Failed to allocate request "
                                 "fragments");
                return -1;
        }
        for (off = 0; off < stub_len; ) {
                size_t chunk = stub_len - off;
                uint8_t pfc = 0;

                if (chunk > max_stub) {
                        chunk = max_stub;
                }
                if (off == 0) {
                        pfc |= PFC_FIRST_FRAG;
                }
                if (off + chunk == stub_len) {
                        pfc |= PFC_LAST_FRAG;
                }
                memcpy(pdu->frag_buf + o, buf, 24);
                memcpy(pdu->frag_buf + o + 24, stub + off, chunk);
                if (dcerpc_fixup_request_hdr(dce, pdu, pdu->frag_buf + o,
                                             24 + chunk, pfc,
                                             (uint32_t)(stub_len - off))) {
                        return -1;
                }
                o += 24 + chunk;
                off += chunk;
        }
        pdu->frag_len = o;
        pdu->frag_pos = 0;
        return 0;
}

/*
 * Split an encoded REQUEST (24-byte header then stub, in buf) into the
 * fragments of a schannel context, each signed or sealed: header, a
 * chunk of the stub padded to DCE_AUTH_PAD_ALIGN, the sec_trailer and
 * the token. With header signing the signature covers the fragment up
 * to the end of its sec_trailer, else the stub and its padding; sealing
 * covers the stub and padding. Every fragment takes the channel's next
 * sequence number, in the order they are sent.
 */
static int
dcerpc_fragment_request_auth(struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu, const uint8_t *buf,
                             size_t len, size_t max_frag)
{
        const uint8_t *stub = buf + 24;
        size_t stub_len = len - 24;
        size_t overhead = 24 + DCE_SEC_TRAILER_LEN + DCERPC_SCHANNEL_TOKEN_LEN;
        size_t max_stub, nfrags, off = 0, o = 0;
        int seal = dce->auth_level == DCERPC_AUTH_LEVEL_PRIVACY;

        if (max_frag < overhead + DCE_AUTH_PAD_ALIGN) {
                dcerpc_set_error(dce, "DCERPC fragment size %zu too small "
                                 "for an auth trailer", max_frag);
                return -1;
        }
        /* Fragments before the last need no padding */
        max_stub = (max_frag - overhead) & ~(size_t)(DCE_AUTH_PAD_ALIGN - 1);
        nfrags = stub_len ? (stub_len + max_stub - 1) / max_stub : 1;
        pdu->frag_buf = malloc(stub_len + nfrags * (overhead +
                                                     DCE_AUTH_PAD_ALIGN));
        if (pdu->frag_buf == NULL) {
                dcerpc_set_error(dce, "Failed to allocate request "
                                 "fragments");
                return -1;
        }
        do {
                uint8_t *frag = pdu->frag_buf + o;
                size_t chunk = stub_len - off;
                size_t pad, flen, tr;
                uint8_t pfc = 0;
                struct dcerpc_iovec iov;

                if (chunk > max_stub) {
                        chunk = max_stub;
                }
                if (off == 0) {
                        pfc |= PFC_FIRST_FRAG;
                }
                if (off + chunk == stub_len) {
                        pfc |= PFC_LAST_FRAG;
                }
                pad = (DCE_AUTH_PAD_ALIGN - (chunk % DCE_AUTH_PAD_ALIGN)) %
                      DCE_AUTH_PAD_ALIGN;
                tr = 24 + chunk + pad;
                flen = tr + DCE_SEC_TRAILER_LEN + DCERPC_SCHANNEL_TOKEN_LEN;

                memcpy(frag, buf, 24);
                memcpy(frag + 24, stub + off, chunk);
                memset(frag + 24 + chunk, 0, pad);
                if (dcerpc_fixup_request_hdr(dce, pdu, frag, flen, pfc,
                                             (uint32_t)(stub_len - off))) {
                        return -1;
                }
                iov = (struct dcerpc_iovec){
                        .buf = frag,
                        .offset = 10,
                        .max_offset = flen,
                };
                if (dcerpc_set_uint16(dce, pdu, &iov,
                                      DCERPC_SCHANNEL_TOKEN_LEN)) {
                        return -1;
                }
                frag[tr] = DCERPC_AUTH_TYPE_SCHANNEL;
                frag[tr + 1] = dce->auth_level;
                frag[tr + 2] = (uint8_t)pad;
                frag[tr + 3] = 0;
                iov.offset = tr + 4;
                if (dcerpc_set_uint32(dce, pdu, &iov, DCE_AUTH_CONTEXT_ID)) {
                        return -1;
                }
                if (dcerpc_schannel_protect(dce->sch, seal,
                                            frag + 24, chunk + pad,
                                            dce->header_sign ? frag :
                                            frag + 24,
                                            dce->header_sign ?
                                            tr + DCE_SEC_TRAILER_LEN :
                                            chunk + pad,
                                            NULL,
                                            frag + tr +
                                            DCE_SEC_TRAILER_LEN)) {
                        dcerpc_set_error(dce, "DCERPC schannel could not "
                                         "protect the request");
                        return -1;
                }
                o += flen;
                off += chunk;
        } while (off < stub_len);
        pdu->frag_len = o;
        pdu->frag_pos = 0;
        return 0;
}

static int dcerpc_send_request_frag(struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu);

static void
dcerpc_frag_write_cb(struct smb2_context *smb2 _U_, int status,
                     void *command_data _U_, void *private_data)
{
        struct dcerpc_pdu *pdu = private_data;
        struct dcerpc_context *dce = pdu->dce;
        int rc;

        if (pdu->pending.orphaned) {
                dcerpc_free_pdu(NULL, pdu);
                return;
        }
        if (status != SMB2_STATUS_SUCCESS) {
                dcerpc_set_error(dce, "DCERPC fragment WRITE failed "
                                 "(0x%08x) %s", status, nterror_to_str(status));
                dcerpc_send_pdu_cb_and_free(dce, pdu,
                                            -nterror_to_errno(status), NULL);
                return;
        }
        rc = dcerpc_send_request_frag(dce, pdu);
        if (rc) {
                dcerpc_send_pdu_cb_and_free(dce, pdu, rc, NULL);
        }
}

/*
 * Send the fragment at frag_pos: WRITE if more follow (continuing from
 * dcerpc_frag_write_cb), TRANSCEIVE for the last one.
 */
static int
dcerpc_send_request_frag(struct dcerpc_context *dce, struct dcerpc_pdu *pdu)
{
        uint8_t *frag = pdu->frag_buf + pdu->frag_pos;
        uint16_t flen = frag[8] | (frag[9] << 8);
        struct smb2_pdu *smb2_pdu;

        if (!(pdu->hdr.packed_drep[0] & DCERPC_DR_LITTLE_ENDIAN)) {
                flen = (frag[8] << 8) | frag[9];
        }
        pdu->frag_pos += flen;

        if (frag[3] & PFC_LAST_FRAG) {
                struct smb2_ioctl_request req;

                memset(&req, 0, sizeof(req));
                req.ctl_code = SMB2_FSCTL_PIPE_TRANSCEIVE;
                memcpy(req.file_id, dce->file_id, SMB2_FD_SIZE);
                req.input_count = flen;
                req.input = frag;
                req.flags = SMB2_0_IOCTL_IS_FSCTL;
                smb2_pdu = smb2_cmd_ioctl_async(dce->smb2, &req,
                                                dcerpc_call_cb, pdu);
        } else {
                struct smb2_write_request req;

                memset(&req, 0, sizeof(req));
                memcpy(req.file_id, dce->file_id, SMB2_FD_SIZE);
                req.length = flen;
                req.buf = frag;
                smb2_pdu = smb2_cmd_write_async(dce->smb2, &req, 0,
                                                dcerpc_frag_write_cb, pdu);
        }
        if (smb2_pdu == NULL) {
                return -ENOMEM;
        }
        smb2_queue_pdu(dce->smb2, smb2_pdu);
        return 0;
}

/*
 * Issue an async DCE/RPC request (FSCTL_PIPE_TRANSCEIVE).
 *
 * Reply memory ownership (success path)
 * -------------------------------------
 * On success the callback's command_data is the decoded reply root: a buffer
 * of decode_size bytes allocated as a dcerpc mem-tree root.  Nested decode
 * allocations (dcerpc_alloc_data: arrays, strings, pointed-to structs, …)
 * are linked to that same root.  Freeing the root with dcerpc_free_data()
 * (or smb2_free_data(); the header layouts match) frees the entire tree.
 *
 * The internal PDU is destroyed after the callback is invoked and does not
 * own that tree.  Before free, the root is stolen out of pdu->payload so
 * dcerpc_free_pdu() does not free it.  Lifetime of all reply allocations is
 * therefore tied to the returned rep pointer, not to the PDU or dce context.
 *
 * On error, command_data is NULL; there is nothing to free for the reply.
 * Request-side buffers supplied by the caller are never part of this tree.
 */
int
dcerpc_call_async(struct dcerpc_context *dce,
                  int opnum,
                  dcerpc_coder req_coder, void *req,
                  dcerpc_coder rep_coder, int decode_size,
                  dcerpc_cb cb, void *cb_data)
{
        struct dcerpc_pdu *pdu = NULL;
        struct dcerpc_iovec iov = {0};
        size_t max_frag, len;

        if (dce->destroying) {
                return -ECANCELED;
        }
        if (dcerpc_need_smb2(dce)) {
                return -EINVAL;
        }

        pdu = dcerpc_encode_request(dce, opnum, req_coder, req, &iov);
        if (pdu == NULL) {
                return -1;
        }
        len = iov.offset;

        pdu->coder = rep_coder;
        pdu->decode_size = decode_size;
        pdu->cb = cb;
        pdu->cb_data = cb_data;

        max_frag = dce->max_xmit_frag ? dce->max_xmit_frag
                                      : DCE_DEFAULT_XMIT_FRAG;
        if (max_frag < 24 + 8) {
                max_frag = DCE_DEFAULT_XMIT_FRAG;
        }
        if (dce->sch != NULL) {
                if (dcerpc_fragment_request_auth(dce, pdu, iov.buf, len,
                                                 max_frag)) {
                        dcerpc_free_iovec(&iov);
                        dcerpc_free_pdu(dce, pdu);
                        return -1;
                }
        } else if (len <= max_frag) {
                /* fits in one fragment: send the encoded buffer itself */
                pdu->frag_buf = iov.buf;
                iov.buf = NULL;
                if (dcerpc_fixup_request_hdr(dce, pdu, pdu->frag_buf, len,
                                             PFC_FIRST_FRAG | PFC_LAST_FRAG,
                                             (uint32_t)(len - 24))) {
                        dcerpc_free_pdu(dce, pdu);
                        return -1;
                }
                pdu->frag_len = len;
                pdu->frag_pos = 0;
        } else if (dcerpc_fragment_request(dce, pdu, iov.buf, len,
                                           max_frag)) {
                dcerpc_free_iovec(&iov);
                dcerpc_free_pdu(dce, pdu);
                return -1;
        }
        dcerpc_free_iovec(&iov);

        if (dcerpc_send_request_frag(dce, pdu)) {
                dcerpc_free_pdu(dce, pdu);
                return -ENOMEM;
        }
        dcerpc_track(dce, &pdu->pending, cb, cb_data);
        return 0;
}

/*
 * Sync wait helper (same pattern as lib/sync.c wait_for_reply).
 */
struct dcerpc_sync_cb_data {
        int is_finished;
        /*
         * The sync caller gave up waiting (dcerpc_wait_for_reply()
         * failed) while the call was still pending: the callback frees
         * this and the reply, if it ever comes.
         */
        int abandoned;
        int status;
        void *ptr;
};

static int
dcerpc_wait_for_reply(struct smb2_context *smb2, struct dcerpc_sync_cb_data *cb_data)
{
        while (!cb_data->is_finished) {
                struct pollfd pfd;

                memset(&pfd, 0, sizeof(pfd));
                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);

                if (poll(&pfd, 1, 1000) < 0) {
                        smb2_set_error(smb2, "Poll failed");
                        return -1;
                }
                /*
                 * Service even when idle: libsmb2 only times out PDUs
                 * from smb2_service(), so a server that never answers
                 * would otherwise keep us here for ever.
                 */
                if (smb2_service(smb2, pfd.revents) < 0) {
                        /*
                         * Our reply was processed before the error, as
                         * lib/sync.c: the call completed, so return it.
                         */
                        if (cb_data->is_finished) {
                                break;
                        }
                        smb2_set_error(smb2, "smb2_service failed with : "
                                       "%s\n", smb2_get_error(smb2));
                        return -1;
                }
        }
        return 0;
}

static void
dcerpc_call_sync_cb(struct dcerpc_context *dce, int status,
                    void *command_data, void *cb_data)
{
        struct dcerpc_sync_cb_data *scb = cb_data;

        if (scb->abandoned) {
                if (command_data != NULL) {
                        dcerpc_free_data(dce, command_data);
                }
                free(scb);
                return;
        }
        scb->status = status;
        scb->ptr = command_data;
        scb->is_finished = 1;
}

/*
 * dcerpc_wait_for_reply() failed. If the call already completed, free
 * what it left; else it is still pending and its callback will run later
 * (when the reply, a timeout or dcerpc_destroy_context() comes), so leave
 * scb for dcerpc_call_sync_cb() to free then.
 */
static void
dcerpc_abandon_sync(struct dcerpc_context *dce,
                    struct dcerpc_sync_cb_data *scb)
{
        if (scb->is_finished) {
                if (scb->ptr != NULL) {
                        dcerpc_free_data(dce, scb->ptr);
                }
                free(scb);
                return;
        }
        scb->abandoned = 1;
}

void *
dcerpc_call(struct dcerpc_context *dce,
            int opnum,
            dcerpc_coder req_coder, void *req,
            dcerpc_coder rep_coder, int decode_size)
{
        struct smb2_context *smb2;
        struct dcerpc_sync_cb_data *scb;
        void *rep = NULL;
        int rc;

        if (dce == NULL) {
                return NULL;
        }
        smb2 = dcerpc_get_smb2_context(dce);
        if (smb2 == NULL) {
                dcerpc_need_smb2(dce);
                return NULL;
        }

        scb = calloc(1, sizeof(*scb));
        if (scb == NULL) {
                smb2_set_error(smb2, "Failed to allocate sync_cb_data");
                return NULL;
        }

        rc = dcerpc_call_async(dce, opnum, req_coder, req, rep_coder,
                               decode_size, dcerpc_call_sync_cb, scb);
        if (rc != 0) {
                free(scb);
                return NULL;
        }

        if (dcerpc_wait_for_reply(smb2, scb) < 0) {
                dcerpc_abandon_sync(dce, scb);
                return NULL;
        }

        if (scb->status != (int)SMB2_STATUS_SUCCESS) {
                /* Reply root may still be present on some error paths. */
                if (scb->ptr != NULL) {
                        dcerpc_free_data(dce, scb->ptr);
                }
                free(scb);
                return NULL;
        }

        rep = scb->ptr;
        free(scb);
        return rep;
}

/*
 * Synchronous open+bind of a DCE/RPC named pipe (wraps
 * dcerpc_connect_context_async + event wait).
 *
 * Returns 0 on success. On failure returns non-zero; check
 * dcerpc_get_error() / smb2_get_error().
 */
int
dcerpc_connect_context(struct dcerpc_context *dce, const char *path,
                       p_syntax_id_t *syntax)
{
        struct smb2_context *smb2;
        struct dcerpc_sync_cb_data *scb;
        int rc;

        if (dce == NULL) {
                return -1;
        }
        smb2 = dcerpc_get_smb2_context(dce);
        if (smb2 == NULL) {
                return dcerpc_need_smb2(dce);
        }

        scb = calloc(1, sizeof(*scb));
        if (scb == NULL) {
                smb2_set_error(smb2, "Failed to allocate sync_cb_data");
                return -ENOMEM;
        }

        rc = dcerpc_connect_context_async(dce, path, syntax,
                                          dcerpc_call_sync_cb, scb);
        if (rc != 0) {
                free(scb);
                return rc;
        }

        if (dcerpc_wait_for_reply(smb2, scb) < 0) {
                dcerpc_abandon_sync(dce, scb);
                return -1;
        }

        rc = scb->status;
        free(scb);

        if (rc != (int)SMB2_STATUS_SUCCESS) {
                return rc ? rc : -1;
        }

        return 0;
}

static void
dcerpc_bind_cb(struct dcerpc_context *dce, int status,
               void *command_data, void *cb_data)
{
        struct dcerpc_cb_data *data = cb_data;

        if (status != SMB2_STATUS_SUCCESS) {
                data->cb(dce, status, NULL, data->cb_data);
                free(data);
                return;
        }

        data->cb(dce, 0, NULL, data->cb_data);
        free(data);
}

static int dcerpc_bind_ack_auth(struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu, const uint8_t *buf,
                                size_t len, size_t body_end);

static void
smb2_bind_cb(struct smb2_context *smb2, int status,
             void *command_data, void *private_data)
{
        struct dcerpc_pdu *pdu = private_data;
        struct dcerpc_context *dce = pdu->dce;
        struct dcerpc_iovec iov _U_;
        struct smb2_ioctl_reply *rep = command_data;
        p_syntax_id_t *offered[2];
        int offered_id[2];
        int n_offered;
        int i;

        if (pdu->pending.orphaned) {
                dcerpc_free_ioctl_output(smb2, status, rep);
                dcerpc_free_pdu(NULL, pdu);
                return;
        }

        pdu->direction = DCERPC_DECODE;

        if (status != SMB2_STATUS_SUCCESS) {
                dcerpc_free_ioctl_output(smb2, status, rep);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -nterror_to_errno(status), NULL);
                return;
        }

        iov = (struct dcerpc_iovec){
                .buf = rep->output,
                .max_offset = rep->output_count,
        };
        if (dcerpc_pdu_coder(dce, pdu, &iov, PDU_TYPE_BIND_ACK)) {
                smb2_free_data(dce->smb2, rep->output);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }
        if (dce->sch != NULL &&
            (pdu->hdr.frag_length != rep->output_count ||
             dcerpc_bind_ack_auth(dce, pdu, rep->output, rep->output_count,
                                  iov.offset))) {
                smb2_free_data(dce->smb2, rep->output);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }
        smb2_free_data(dce->smb2, rep->output);

        if (pdu->hdr.call_id != pdu->call_id) {
                dcerpc_set_error(dce, "DCERPC BIND_ACK call_id %u, "
                                 "expected %u", pdu->hdr.call_id,
                                 pdu->call_id);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }
        /* The BIND_ACK is all of the reply, as dce_unfragment_iov() */
        if (pdu->hdr.frag_length != rep->output_count) {
                dcerpc_set_error(dce, "DCERPC BIND_ACK of %u bytes in a "
                                 "%u byte reply", pdu->hdr.frag_length,
                                 rep->output_count);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }

        if (pdu->bind_ack.num_results < 1) {
                smb2_set_error(smb2, "No results in BIND ACK");
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }
        /*
         * One result per context offered, in the order offered (see
         * dcerpc_bind_async(): context 0 is NDR32 and context 1 NDR64,
         * either or both). An accepted one must name the transfer syntax
         * its context offered; take its context id from what we offered,
         * never from the position alone.
         */
        n_offered = 0;
        if (smb2_get_ndr(smb2) == 0 || smb2_get_ndr(smb2) == 1) {
                offered_id[n_offered] = 0;
                offered[n_offered++] = &ndr32_syntax;
        }
        if (smb2_get_ndr(smb2) == 0 || smb2_get_ndr(smb2) == 2) {
                offered_id[n_offered] = 1;
                offered[n_offered++] = &ndr64_syntax;
        }
        if (pdu->bind_ack.num_results != n_offered) {
                dcerpc_set_error(dce, "DCERPC BIND_ACK has %u results for "
                                 "%d contexts", pdu->bind_ack.num_results,
                                 n_offered);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }
        for (i = 0; i < n_offered; i++) {
                struct dcerpc_bind_context_results *res =
                        &pdu->bind_ack.results[i];

                if (res->ack_result != ACK_RESULT_ACCEPTANCE) {
                        continue;
                }
                if (memcmp(&res->uuid, &offered[i]->uuid,
                           sizeof(res->uuid)) ||
                    res->syntax_version != ((uint32_t)offered[i]->vers |
                                            ((uint32_t)offered[i]->vers_minor
                                             << 16))) {
                        dcerpc_set_error(dce, "DCERPC BIND_ACK accepted "
                                         "a transfer syntax context %d "
                                         "did not offer", offered_id[i]);
                        dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL,
                                                    NULL);
                        return;
                }
                dce->tctx_id = offered_id[i];
                break;
        }
        if (i == n_offered) {
                smb2_set_error(smb2, "Bind rejected all contexts");
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }
        /*
         * C706 12.6.4.4: every implementation accepts fragments of at
         * least 1432 bytes. Less would split a request into a write per
         * few bytes of stub (8 bytes each at max_recv_frag 32).
         */
        if (pdu->bind_ack.max_recv_frag < DCE_MIN_FRAG) {
                dcerpc_set_error(dce, "DCERPC BIND_ACK max_recv_frag %u is "
                                 "below %d", pdu->bind_ack.max_recv_frag,
                                 DCE_MIN_FRAG);
                dcerpc_send_pdu_cb_and_free(dce, pdu, -EINVAL, NULL);
                return;
        }
        dce->max_xmit_frag = pdu->bind_ack.max_recv_frag;

        dcerpc_send_pdu_cb_and_free(dce, pdu, 0, NULL);
}
/*
 * The auth trailer of an authenticated BIND, after its body: padding to
 * 4, the sec_trailer, and an NL_AUTH_MESSAGE NEGOTIATE_REQUEST naming
 * the domain and machine account the secure channel belongs to. Then
 * frag_length and auth_length are set to match.
 */
static int
dcerpc_bind_auth(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov)
{
        static const uint32_t nl_flags = NL_FLAG_OEM_NETBIOS_DOMAIN_NAME |
                NL_FLAG_OEM_NETBIOS_COMPUTER_NAME;
        const char *names[2] = { dce->auth_domain, dce->auth_computer };
        size_t auth_len = 8;
        size_t end;
        uint8_t pad;
        int i, n;

        for (n = 0; n < 2; n++) {
                auth_len += strlen(names[n]) + 1;
        }
        pad = (uint8_t)((4 - (iov->offset & 3)) & 3);
        for (i = 0; i < pad; i++) {
                if (dcerpc_set_uint8(dce, iov, 0)) {
                        return -1;
                }
        }
        if (dcerpc_set_uint8(dce, iov, DCERPC_AUTH_TYPE_SCHANNEL) ||
            dcerpc_set_uint8(dce, iov, dce->auth_level) ||
            dcerpc_set_uint8(dce, iov, pad) ||
            dcerpc_set_uint8(dce, iov, 0) ||
            dcerpc_set_uint32(dce, pdu, iov, DCE_AUTH_CONTEXT_ID)) {
                return -1;
        }
        /* NL_AUTH_MESSAGE is little-endian whatever the PDU's order */
        for (i = 0; i < 4; i++) {
                if (dcerpc_set_uint8(dce, iov,
                                     (uint8_t)(NL_NEGOTIATE_REQUEST >>
                                               (8 * i)))) {
                        return -1;
                }
        }
        for (i = 0; i < 4; i++) {
                if (dcerpc_set_uint8(dce, iov,
                                     (uint8_t)(nl_flags >> (8 * i)))) {
                        return -1;
                }
        }
        for (n = 0; n < 2; n++) {
                const char *c = names[n];

                do {
                        if (dcerpc_set_uint8(dce, iov, (uint8_t)*c)) {
                                return -1;
                        }
                } while (*c++ != '\0');
        }
        end = iov->offset;
        if (end > UINT16_MAX) {
                dcerpc_set_error(dce, "DCERPC BIND with auth too long");
                return -1;
        }
        iov->offset = 8;
        if (dcerpc_set_uint16(dce, pdu, iov, (uint16_t)end) ||
            dcerpc_set_uint16(dce, pdu, iov, (uint16_t)auth_len)) {
                return -1;
        }
        iov->offset = end;
        return 0;
}

/*
 * The auth trailer of the BIND_ACK to an authenticated BIND, at the end
 * of buf (len bytes, the whole PDU); body_end is where the BIND_ACK body
 * decoded to. It must be ours (auth type, level, context id) and carry
 * an NL_AUTH_MESSAGE NEGOTIATE_RESPONSE.
 */
static int
dcerpc_bind_ack_auth(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                     const uint8_t *buf, size_t len, size_t body_end)
{
        struct dcerpc_iovec iov;
        uint16_t auth_len = pdu->hdr.auth_length;
        uint32_t context_id, type;
        size_t t;

        if (auth_len == 0) {
                dcerpc_set_error(dce, "DCERPC BIND_ACK did not accept the "
                                 "schannel auth");
                return -1;
        }
        if (auth_len < 8 || (size_t)auth_len + DCE_SEC_TRAILER_LEN > len ||
            len - auth_len - DCE_SEC_TRAILER_LEN < body_end) {
                dcerpc_set_error(dce, "DCERPC BIND_ACK auth_length %u out "
                                 "of bounds", auth_len);
                return -1;
        }
        t = len - auth_len - DCE_SEC_TRAILER_LEN;
        if (buf[t] != DCERPC_AUTH_TYPE_SCHANNEL ||
            buf[t + 1] != dce->auth_level ||
            buf[t + 2] != t - body_end) {
                dcerpc_set_error(dce, "DCERPC BIND_ACK auth type %u level "
                                 "%u pad %u is not ours", buf[t],
                                 buf[t + 1], buf[t + 2]);
                return -1;
        }
        iov = (struct dcerpc_iovec){
                .buf = (uint8_t *)(void *)buf,
                .offset = t + 4,
                .max_offset = len,
        };
        if (dcerpc_get_uint32(dce, pdu, &iov, &context_id) ||
            context_id != DCE_AUTH_CONTEXT_ID) {
                dcerpc_set_error(dce, "DCERPC BIND_ACK auth context id is "
                                 "not ours");
                return -1;
        }
        t += DCE_SEC_TRAILER_LEN;
        type = (uint32_t)buf[t] | ((uint32_t)buf[t + 1] << 8) |
               ((uint32_t)buf[t + 2] << 16) | ((uint32_t)buf[t + 3] << 24);
        if (type != NL_NEGOTIATE_RESPONSE) {
                dcerpc_set_error(dce, "DCERPC BIND_ACK NL_AUTH_MESSAGE type "
                                 "%u is not a negotiate response", type);
                return -1;
        }
        dce->header_sign = (pdu->hdr.pfc_flags &
                            PFC_SUPPORT_HEADER_SIGN) != 0;
        return 0;
}


static int
dcerpc_bind_async(struct dcerpc_context *dce, dcerpc_cb cb,
                  void *cb_data)
{
        struct dcerpc_pdu *pdu;
        struct smb2_pdu *smb2_pdu;
        struct smb2_ioctl_request req;
        struct dcerpc_iovec iov _U_;
        struct p_cont_elem_t *pce;

        /* Before the transfer syntax is negotiated: only the byte order */
        pdu = dcerpc_allocate_pdu(dce, DCERPC_ENCODE | ENCODING_NDR |
                                  (dcerpc_get_ndr_flavor(dce) &
                                   DCERPC_BIG_ENDIAN), NSE_BUF_SIZE);
        if (pdu == NULL) {
                return -ENOMEM;
        }

        pdu->hdr.rpc_vers = 5;
        pdu->hdr.rpc_vers_minor = 0;
        pdu->hdr.PTYPE = PDU_TYPE_BIND;
        pdu->hdr.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG;
        if (dce->sch != NULL) {
                pdu->hdr.pfc_flags |= PFC_SUPPORT_HEADER_SIGN;
        }
        pdu->hdr.call_id = dce->call_id++;
        pdu->call_id = pdu->hdr.call_id;
        pdu->hdr.frag_length = 0;
        pdu->hdr.auth_length = 0;
        pdu->bind.max_xmit_frag = 32768;
        pdu->bind.max_recv_frag = 32768;
        pdu->bind.assoc_group_id = 0;
        pdu->bind.n_context_elem = smb2_get_ndr(dce->smb2) ? 1 : 2;
        pdu->bind.p_cont_elem = dcerpc_alloc_data(pdu,
                     pdu->bind.n_context_elem * sizeof(struct p_cont_elem_t));
        if (pdu->bind.p_cont_elem == NULL) {
                dcerpc_set_error(dce, "Failed to allocate p_cont_elem");
                dcerpc_free_pdu(dce, pdu);
                return -ENOMEM;
        }
        pce = pdu->bind.p_cont_elem;
        if (smb2_get_ndr(dce->smb2) == 0 || smb2_get_ndr(dce->smb2) == 1) {
                pce->p_cont_id = 0;
                pce->n_transfer_syn = 1;
                pce->abstract_syntax = dce->syntax;
                pce->transfer_syntaxes = dcerpc_alloc_data(pdu,
                     pce->n_transfer_syn * sizeof(struct p_cont_elem_t *));
                if (pce->transfer_syntaxes == NULL) {
                        dcerpc_set_error(dce, "Failed to allocate transfer_syntaxes");
                        dcerpc_free_pdu(dce, pdu);
                        return -ENOMEM;
                }
                pce->transfer_syntaxes[0] = &ndr32_syntax;
                pce++;
        }
        if (smb2_get_ndr(dce->smb2) == 0 || smb2_get_ndr(dce->smb2) == 2) {
                pce->p_cont_id = 1;
                pce->n_transfer_syn = 1;
                pce->abstract_syntax = dce->syntax;
                pce->transfer_syntaxes = dcerpc_alloc_data(pdu,
                     pce->n_transfer_syn * sizeof(struct p_cont_elem_t *));
                if (pce->transfer_syntaxes == NULL) {
                        dcerpc_set_error(dce, "Failed to allocate transfer_syntaxes");
                        dcerpc_free_pdu(dce, pdu);
                        return -ENOMEM;
                }
                pce->transfer_syntaxes[0] = &ndr64_syntax;
        }

        pdu->cb = cb;
        pdu->cb_data = cb_data;

        iov = (struct dcerpc_iovec){
                .buf = pdu->payload,
                .max_offset = NSE_BUF_SIZE,
        };
        if (dcerpc_pdu_coder(dce, pdu, &iov, PDU_TYPE_BIND)) {
                dcerpc_free_pdu(dce, pdu);
                return -ENOMEM;
        }
        if (dce->sch != NULL && dcerpc_bind_auth(dce, pdu, &iov)) {
                dcerpc_free_pdu(dce, pdu);
                return -EINVAL;
        }

        memset(&req, 0, sizeof(struct smb2_ioctl_request));
        req.ctl_code = SMB2_FSCTL_PIPE_TRANSCEIVE;
        memcpy(req.file_id, dce->file_id, SMB2_FD_SIZE);
        req.input_count = (uint32_t)iov.offset;
        req.input = iov.buf;
        req.flags = SMB2_0_IOCTL_IS_FSCTL;

        if (dce->destroying) {
                dcerpc_free_pdu(dce, pdu);
                return -ECANCELED;
        }
        smb2_pdu = smb2_cmd_ioctl_async(dce->smb2, &req, smb2_bind_cb, pdu);
        if (smb2_pdu == NULL) {
                dcerpc_free_pdu(dce, pdu);
                return -ENOMEM;
        }
        dcerpc_track(dce, &pdu->pending, cb, cb_data);
        smb2_queue_pdu(dce->smb2, smb2_pdu);
 
        return 0;
}

static void
smb2_open_cb(struct smb2_context *smb2, int status,
             void *command_data, void *private_data)
{
        struct dcerpc_cb_data *data = private_data;
        struct smb2_create_reply *rep = command_data;
        struct dcerpc_context *dce = data->dce;

        if (data->pending.orphaned) {
                /* context destroyed while opening: close the pipe again */
                if (status == SMB2_STATUS_SUCCESS) {
                        struct smb2_close_request cl_req;
                        struct smb2_pdu *pdu;

                        memset(&cl_req, 0, sizeof(cl_req));
                        memcpy(cl_req.file_id, rep->file_id, SMB2_FD_SIZE);
                        pdu = smb2_cmd_close_async(smb2, &cl_req,
                                                   dcerpc_close_cb, NULL);
                        if (pdu) {
                                smb2_queue_pdu(smb2, pdu);
                        }
                }
                free(data);
                return;
        }
        dcerpc_untrack(dce, &data->pending);

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Failed to open pipe %s: %s",
                               dce->path, nterror_to_str(status));
                data->cb(dce, -nterror_to_errno(status),
                         NULL, data->cb_data);
                free(data);
                return;
        }
        
        memcpy(dce->file_id, rep->file_id, SMB2_FD_SIZE);

        status = dcerpc_bind_async(dce, dcerpc_bind_cb, data);
        if (status) {
                data->cb(dce, status, NULL, data->cb_data);
                free(data);
                return;
        }

        return;
}

int
dcerpc_open_async(struct dcerpc_context *dce, dcerpc_cb cb,
                  void *cb_data)
{
        struct smb2_create_request req;
        struct smb2_pdu *pdu;
        struct dcerpc_cb_data *data;

        data = calloc(1, sizeof(struct dcerpc_cb_data));
        if (data == NULL) {
                dcerpc_set_error(dce, "Failed to allocate dcerpc callback "
                                 "data");
                return -ENOMEM;
        }
        data->dce = dce;
        data->cb = cb;
        data->cb_data = cb_data;

        memset(&req, 0, sizeof(struct smb2_create_request));
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        req.desired_access = SMB2_FILE_READ_DATA |
                SMB2_FILE_WRITE_DATA |
                SMB2_FILE_APPEND_DATA |
                SMB2_FILE_READ_EA |
                SMB2_FILE_READ_ATTRIBUTES |
                SMB2_FILE_WRITE_EA |
                SMB2_FILE_WRITE_ATTRIBUTES |
                SMB2_READ_CONTROL |
                SMB2_SYNCHRONIZE;
        req.file_attributes = 0;
        req.share_access = SMB2_FILE_SHARE_READ |
                SMB2_FILE_SHARE_WRITE |
                SMB2_FILE_SHARE_DELETE;
        req.create_disposition = SMB2_FILE_OPEN;
        req.create_options = 0;
        req.name = dce->path;

        if (dce->destroying) {
                free(data);
                return -ECANCELED;
        }
        pdu = smb2_cmd_create_async(dce->smb2, &req, smb2_open_cb, data);
        if (pdu == NULL) {
                free(data);
                return -ENOMEM;
        }
        dcerpc_track(dce, &data->pending, cb, cb_data);
        smb2_queue_pdu(dce->smb2, pdu);

        return 0;
}

#else /* !HAVE_LIBSMB2 */
/* Built without libsmb2: there is no transport, see dcerpc_need_smb2() */
int
dcerpc_call_async(struct dcerpc_context *dce, int opnum _U_,
                  dcerpc_coder req_coder _U_, void *req _U_,
                  dcerpc_coder rep_coder _U_, int decode_size _U_,
                  dcerpc_cb cb _U_, void *cb_data _U_)
{
        return dcerpc_need_smb2(dce);
}

void *
dcerpc_call(struct dcerpc_context *dce, int opnum _U_,
            dcerpc_coder req_coder _U_, void *req _U_,
            dcerpc_coder rep_coder _U_, int decode_size _U_)
{
        dcerpc_need_smb2(dce);
        return NULL;
}

int
dcerpc_connect_context(struct dcerpc_context *dce, const char *path _U_,
                       p_syntax_id_t *syntax _U_)
{
        return dcerpc_need_smb2(dce);
}

int
dcerpc_open_async(struct dcerpc_context *dce, dcerpc_cb cb _U_,
                  void *cb_data _U_)
{
        return dcerpc_need_smb2(dce);
}
#endif /* HAVE_LIBSMB2 */

const char *
dcerpc_get_error(struct dcerpc_context *dce)
{
#ifdef HAVE_LIBSMB2
        if (dce->smb2) {
                return smb2_get_error(dce->smb2);
        }
#endif
        return dce->error_string;
}

void
dcerpc_free_data(struct dcerpc_context *dce _U_, void *data)
{
        /* Frees a mem tree transferred out of a PDU (e.g. call reply root). */
        dcerpc_mem_free(data);
}

/*
 * Read filename and decode it as YAML into a structure of decode_size bytes
 * using coder.  A temporary dcerpc context is created for the decode and
 * destroyed before return.  The structure is a mem-tree root that owns
 * everything decoded into it.  Free the result with
 * dcerpc_free_data(NULL, ptr).
 */
void *
dcerpc_read_yaml_file(const char *filename,
                      dcerpc_coder coder,
                      int decode_size)
{
        struct dcerpc_context *dce = NULL;
        struct dcerpc_pdu *pdu = NULL;
        struct dcerpc_iovec iov;
        struct stat st;
        void *payload = NULL;
        char *filebuf = NULL;
        char root_key[256];
        const char *p;
        const char *start;
        size_t key_len;
        int fd = -1;
        ssize_t n;
        size_t total = 0;
        size_t file_size;

        if (filename == NULL || coder == NULL || decode_size <= 0) {
                return NULL;
        }

        dce = dcerpc_create_context(NULL);
        if (dce == NULL) {
                goto out;
        }

        fd = open(filename, O_RDONLY);
        if (fd < 0) {
                dcerpc_set_error(dce, "Failed to open %s: %s",
                                 filename, strerror(errno));
                goto out;
        }
        if (fstat(fd, &st) < 0) {
                dcerpc_set_error(dce, "Failed to stat %s: %s",
                                 filename, strerror(errno));
                goto out;
        }
        if (st.st_size < 0) {
                dcerpc_set_error(dce, "Invalid size for %s", filename);
                goto out;
        }
        file_size = (size_t)st.st_size;

        pdu = dcerpc_allocate_pdu(dce, DCERPC_DECODE | ENCODING_YAML,
                                  decode_size);
        if (pdu == NULL) {
                goto out;
        }

        /* Decoding copies what it keeps, so the file buffer is temporary */
        filebuf = malloc(file_size + 1);
        if (filebuf == NULL) {
                dcerpc_set_error(dce, "Failed to allocate buffer for %s",
                                 filename);
                goto out;
        }

        while (total < file_size) {
                n = read(fd, filebuf + total, file_size - total);
                if (n < 0) {
                        dcerpc_set_error(dce, "Failed to read %s: %s",
                                         filename, strerror(errno));
                        goto out;
                }
                if (n == 0) {
                        break;
                }
                total += (size_t)n;
        }
        close(fd);
        fd = -1;
        filebuf[total] = '\0';

        /*
         * Peek first YAML mapping key (text before first ':'), skipping
         * blank lines and full-line # comments.
         */
        p = filebuf;
        for (;;) {
                while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
                        p++;
                }
                if (*p == '#') {
                        while (*p && *p != '\n' && *p != '\r') {
                                p++;
                        }
                        continue;
                }
                break;
        }
        start = p;
        while (*p && *p != ':' && *p != '\n' && *p != '\r' && *p != '#') {
                p++;
        }
        key_len = (size_t)(p - start);
        /* Trim trailing spaces on the key token. */
        while (key_len > 0 &&
               (start[key_len - 1] == ' ' || start[key_len - 1] == '\t')) {
                key_len--;
        }
        if (*p != ':' || key_len == 0 || key_len >= sizeof(root_key)) {
                dcerpc_set_error(dce, "No YAML root key in %s", filename);
                goto out;
        }
        memcpy(root_key, start, key_len);
        root_key[key_len] = '\0';

        iov = (struct dcerpc_iovec){
                .buf = (uint8_t *)filebuf,
                .max_offset = total + 1,
        };

        if (dcerpc_do_coder(root_key, dce, pdu, &iov,
                            pdu->payload, coder)) {
                if (dce->error_string[0] == '\0') {
                        dcerpc_set_error(dce,
                                         "Failed to decode YAML from %s",
                                         filename);
                }
                goto out;
        }

        /* Steal root (struct + nested allocs); free PDU only. */
        payload = pdu->payload;
        pdu->payload = NULL;

out:
        free(filebuf);
        if (fd >= 0) {
                close(fd);
        }
        if (pdu) {
                dcerpc_free_pdu(dce, pdu);
        }
        if (dce) {
                dcerpc_destroy_context(dce);
        }
        return payload;
}

uint32_t
dcerpc_pdu_direction(struct dcerpc_pdu *pdu)
{
        return pdu->direction;
}

enum dcerpc_encoding
dcerpc_pdu_encoding(struct dcerpc_pdu *pdu)
{
        return pdu->encoding;
}

char *
dcerpc_pdu_yaml_key(struct dcerpc_pdu *pdu)
{
        return pdu->yaml_key;
}

char *
dcerpc_pdu_yaml_val(struct dcerpc_pdu *pdu)
{
        return pdu->yaml_val;
}

void
dcerpc_pdu_clear_yaml_key(struct dcerpc_pdu *pdu)
{
        pdu->yaml_key = NULL;
}

char *
dcerpc_pdu_json_key(struct dcerpc_pdu *pdu)
{
        return pdu->json_key;
}

int
dcerpc_pdu_is_conformance_run(struct dcerpc_pdu *pdu)
{
        return pdu->is_conformance_run;
}

void
dcerpc_pdu_raise_max_alignment(struct dcerpc_pdu *pdu, int alignment)
{
        if (alignment > pdu->max_alignment) {
                pdu->max_alignment = alignment;
        }
}

/*
 * Packet-form structures such as self-relative SECURITY_DESCRIPTORs, ACLs
 * and ACEs are defined as little-endian byte layouts, not as NDR, so they
 * must not follow a big-endian data representation. Coders for them bracket
 * their work with begin/end; the calls nest.
 */
void
dcerpc_pdu_packet_form_begin(struct dcerpc_pdu *pdu)
{
        pdu->packet_form++;
}

void
dcerpc_pdu_packet_form_end(struct dcerpc_pdu *pdu)
{
        pdu->packet_form--;
}

/* Align the buffer position for a 32/64-bit NDR value */
int
dcerpc_align_3264(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov)
{
        return dcerpc_iov_align(pdu, iov, pdu->ndr64 ? 8 : 4);
}

uint32_t
dcerpc_get_ndr_flavor(struct dcerpc_context *dce)
{
        uint32_t flavor = 0;

        /* The presentation context IDs are 0 for NDR32 and 1 for NDR64 */
        if (dce->tctx_id) {
                flavor |= DCERPC_NDR64;
        }
        if (!(dce->packed_drep[0] & DCERPC_DR_LITTLE_ENDIAN)) {
                flavor |= DCERPC_BIG_ENDIAN;
        }
        return flavor;
}
int dcerpc_get_cr(struct dcerpc_pdu *pdu)
{
        return pdu->is_conformance_run;
}

void dcerpc_set_size_is(struct dcerpc_pdu *pdu, uint32_t size_is)
{
        pdu->size_is = size_is;
}

uint32_t dcerpc_get_size_is(struct dcerpc_pdu *pdu)
{
        return pdu->size_is;
}

void dcerpc_set_length_is(struct dcerpc_pdu *pdu, uint32_t length_is)
{
        pdu->length_is = length_is;
}

uint32_t dcerpc_get_length_is(struct dcerpc_pdu *pdu)
{
        return pdu->length_is;
}

void dcerpc_set_switch_is(struct dcerpc_pdu *pdu, int switch_is)
{
        pdu->switch_is = switch_is;
}

int dcerpc_get_switch_is(struct dcerpc_pdu *pdu)
{
        return pdu->switch_is;
}

void dcerpc_set_unicode_max_length(struct dcerpc_pdu *pdu, uint16_t max_length)
{
        /*
         * MaximumLength only exists on the NDR wire form of
         * RPC_UNICODE_STRING. Ignore for YAML/JSON and for decode so
         * procedure coders need not branch on encoding/direction.
         */
        if (dcerpc_pdu_direction(pdu) != DCERPC_ENCODE ||
            dcerpc_pdu_encoding(pdu) != ENCODING_NDR) {
                return;
        }
        pdu->unicode_max_length = max_length;
}

uint16_t dcerpc_get_unicode_max_length(struct dcerpc_pdu *pdu)
{
        return pdu->unicode_max_length;
}

void dcerpc_set_request(struct dcerpc_pdu *pdu, void *request)
{
        pdu->request = request;
}

void dcerpc_pdu_set_server_call(struct dcerpc_pdu *pdu,
                                struct dcerpc_server_call *call)
{
        pdu->server_call = call;
}

struct dcerpc_server_call *dcerpc_pdu_server_call(struct dcerpc_pdu *pdu)
{
        return pdu->server_call;
}

void *dcerpc_get_request(struct dcerpc_pdu *pdu)
{
        return pdu->request;
}

/**********************
 * typedef struct dcerpc_context_handle {
 *    unsigned32 context_handle_attributes;
 *    dcerpc_uuid_t context_handle_uuid;
 * } dcerpc_context_handle;
 **********************/
int
dcerpc_context_handle_coder(char *name, struct dcerpc_context *dce,
                            struct dcerpc_pdu *pdu,
                            struct dcerpc_iovec *iov,
                            void *ptr)
{
        struct dcerpc_context_handle *handle = ptr;

        if (dcerpc_uint32_coder("ContextHandleAttributes", dce, pdu, iov, &handle->context_handle_attributes)) {
                return -1;
        }
        if (dcerpc_uuid_coder("UUID", dce, pdu, iov,
                              &handle->context_handle_uuid)) {
                return -1;
        }
        return 0;
}


/*
 * typedef struct _RPC_UNICODE_STRING {
 *       uint16_t Length;
 *       uint16_t MaximumLength;
 *       [size_is(MaximumLength/2), length_is(Length/2)] WCHAR* Buffer;
 * } RPC_UNICODE_STRING, *PRPC_UNICODE_STRING;
 *
 * nult: 0 = plain RPC_UNICODE_STRING (MS-DTYP); 1 = NUL-terminated Buffer
 * (RPC_UNICODE_STRINGz / RRP_UNICODE_STRING in MS-RRP). Same pattern as
 * _ndr_utf16z_coder.
 *
 * Represented in C as char * (UTF-8). ptr is char **.
 * NDR form; YAML/JSON show only the string (yaml/json_utf16_coder).
 */
static int
_ndr_RPC_UNICODE_STRING_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov,
                              void *ptr, int nult)
{
        uint16_t len, maxlen;
        dcerpc_coder buffer_coder;

/* TODO conformance split
 * during the conformance run we need to do the alignment in all the
  coders, even for the coders that do  not have any conformance data.

  that will eliminate the need to manually set the alignment like
  we do here
*/
        if (dcerpc_align_3264(pdu, iov)) {
                return -1;
        }

        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE) {
                char *s = *(char **)ptr;
                uint16_t override = dcerpc_get_unicode_max_length(pdu);

                if (s && s[0] != '\0') {
                        /*
                         * Length is in bytes of UTF-16, which is not twice
                         * the UTF-8 length for anything but ASCII.
                         */
                        struct dcerpc_utf16_buf *u = dcerpc_utf8_to_utf16(s);
                        size_t units;

                        if (u == NULL) {
                                dcerpc_set_error(dce, "%s is not valid UTF-8",
                                                 name);
                                return -1;
                        }
                        units = (size_t)u->len;
                        free(u);
                        if (units + (nult ? 1 : 0) > UINT16_MAX / 2) {
                                dcerpc_set_error(dce, "%s is too long for an "
                                                 "RPC_UNICODE_STRING", name);
                                return -1;
                        }
                        len = (uint16_t)(units * 2);
                        if (nult) {
                                len = (uint16_t)(len + 2);
                        }
                } else if (nult) {
                        /*
                         * Empty/NULL still encode a single NUL wchar via
                         * utf16z (actual_count=1); Length must match.
                         * MS-RRP EnumKey-style buffer ads still use this
                         * when content is empty; only MaximumLength is
                         * significant for the server-side allocation.
                         */
                        len = 2;
                } else {
                        len = 0;
                }
                /*
                 * MaxLength must agree with the UTF-16 array max_count that
                 * the Buffer coder emits (size_is(MaximumLength/2)).
                 * Non-nult utf16 rounds odd wchar counts up by one; nult
                 * utf16z uses content+NUL with no odd-count padding.
                 *
                 * dcerpc_set_unicode_max_length() can raise MaximumLength
                 * above the content size (client receive buffer size).
                 */
                if (nult) {
                        maxlen = len;
                } else {
                        maxlen = (len & 0x02) ? len + 2 : len;
                }
                if (override > maxlen) {
                        maxlen = override;
                }
        }
        if (dcerpc_uint16_coder("Length", dce, pdu, iov, &len)) {
                return -1;
        }
        if (dcerpc_uint16_coder("MaxLength", dce, pdu, iov, &maxlen)) {
                return -1;
        }
        /*
         * Unique Buffer: always pass the caller's stable char ** (ptr).
         * Never a stack temporary — Buffer is often deferred (e.g.
         * LookupNames2 name arrays) and must still be valid when flushed.
         * Empty/NULL *ptr still uses ptr so the unique header is present
         * and the utf16 coder encodes an empty (or single-NUL) array.
         */
        buffer_coder = nult ? dcerpc_utf16z_coder : dcerpc_utf16_coder;
        /*
         * An empty plain RPC_UNICODE_STRING that announces no receive
         * buffer has a NULL Buffer, as Windows sends it (Length and
         * MaximumLength 0).
         */
        if (dcerpc_pdu_direction(pdu) == DCERPC_ENCODE && !nult &&
            maxlen == 0) {
                if (dcerpc_ptr_coder("Buffer", dce, pdu, iov, NULL,
                                     PTR_UNIQUE, buffer_coder)) {
                        return -1;
                }
                return 0;
        }
        if (dcerpc_ptr_coder("Buffer", dce, pdu, iov, ptr,
                             PTR_UNIQUE, buffer_coder)) {
                return -1;
        }

        return 0;
}

static int
ndr_RPC_UNICODE_STRING_coder(char *name, struct dcerpc_context *dce,
                             struct dcerpc_pdu *pdu,
                             struct dcerpc_iovec *iov,
                             void *ptr)
{
        return _ndr_RPC_UNICODE_STRING_coder(name, dce, pdu, iov,
                                             ptr, 0);
}

static int
ndr_RPC_UNICODE_STRINGz_coder(char *name, struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              struct dcerpc_iovec *iov,
                              void *ptr)
{
        return _ndr_RPC_UNICODE_STRING_coder(name, dce, pdu, iov,
                                             ptr, 1);
}

/* RPC_UNICODE_STRING: Buffer not required to be NUL-terminated. */
int
dcerpc_RPC_UNICODE_STRING_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct dcerpc_iovec *iov,
                                void *ptr)
{
        if (pdu->coders->unicode_string_coder) {
                return pdu->coders->unicode_string_coder(name, dce, pdu,
                                                         iov, ptr);
        }
        return -1;
}

/*
 * RPC_UNICODE_STRINGz: Buffer is NUL-terminated (MS-RRP RRP_UNICODE_STRING).
 * Same relationship as ndr_utf16z_coder vs ndr_utf16_coder.
 */
int
dcerpc_RPC_UNICODE_STRINGz_coder(char *name, struct dcerpc_context *dce,
                                 struct dcerpc_pdu *pdu,
                                 struct dcerpc_iovec *iov,
                                 void *ptr)
{
        if (pdu->coders->unicode_stringz_coder) {
                return pdu->coders->unicode_stringz_coder(name, dce, pdu,
                                                          iov, ptr);
        }
        return -1;
}


/*
 * Append formatted text to a YAML/JSON output buffer. Fails, instead of
 * silently truncating, when the output does not fit.
 */
static int
dcerpc_text_printf(struct dcerpc_context *ctx, struct dcerpc_iovec *iov, const char *fmt, ...)
{
        va_list ap;
        size_t room;
        int n;

        /* Room for the terminating NUL; grow and retry if it is too small */
        if (dcerpc_iov_reserve(ctx, iov, 1)) {
                goto full;
        }
        room = iov->max_offset - iov->offset;
        va_start(ap, fmt);
        n = vsnprintf((char *)&iov->buf[iov->offset], room, fmt, ap);
        va_end(ap);
        if (n >= 0 && (size_t)n >= room) {
                if (dcerpc_iov_reserve(ctx, iov, (size_t)n + 1)) {
                        goto full;
                }
                room = iov->max_offset - iov->offset;
                va_start(ap, fmt);
                n = vsnprintf((char *)&iov->buf[iov->offset], room, fmt, ap);
                va_end(ap);
        }
        if (n < 0 || (size_t)n >= room) {
                goto full;
        }
        iov->offset += (size_t)n;
        return 0;
full:
        dcerpc_set_error(ctx, "DCERPC text encoding: output buffer "
                         "too small");
        return -1;
}

/* Append len bytes as lowercase hex, two digits per byte. */
static int
dcerpc_text_print_hex(struct dcerpc_context *ctx, struct dcerpc_iovec *iov, const uint8_t *data, uint32_t len)
{
        uint32_t i;

        for (i = 0; i < len; i++) {
                if (dcerpc_text_printf(ctx, iov, "%02x", data[i])) {
                        return -1;
                }
        }
        return 0;
}

static int
hex_nibble(char c)
{
        if (c >= '0' && c <= '9') {
                return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
        }
        return -1;
}

/* Parse a hex string into pdu-owned storage. "" gives len 0, data NULL. */
static int
dcerpc_text_parse_hex(struct dcerpc_pdu *pdu, const char *name,
                      const char *hex, struct dcerpc_bytes *b)
{
        size_t n = hex ? strlen(hex) : 0;
        size_t i;

        if (n % 2 || n / 2 > DCERPC_BYTES_MAX) {
                printf("Bad hex byte string for %s\n", name);
                return -1;
        }
        b->len = (uint32_t)(n / 2);
        if (b->len == 0) {
                b->data = NULL;
                return 0;
        }
        b->data = dcerpc_alloc_data(pdu, b->len);
        if (b->data == NULL) {
                return -1;
        }
        for (i = 0; i < b->len; i++) {
                int hi = hex_nibble(hex[2 * i]);
                int lo = hex_nibble(hex[2 * i + 1]);

                if (hi < 0 || lo < 0) {
                        printf("Bad hex byte string for %s\n", name);
                        return -1;
                }
                b->data[i] = (uint8_t)(hi << 4 | lo);
        }
        return 0;
}

static int
yaml_print_preamble(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov)
{
        int i, n = pdu->yaml_indentation;

        /*
         * The body of a list item is one indentation level deeper than
         * the list. On the item's first line "- " takes the place of
         * that level, so all fields of the item, including nested ones,
         * line up under the first key:
         *   - Name: BUILTIN
         *     SID: S-1-5-32
         */
        if (pdu->yaml_array_prefix) {
                n--;
        }
        for(i = 0; i < n; i++) {
                if (dcerpc_text_printf(ctx, iov, "  ")) {
                        return -1;
                }
        }
        if (pdu->yaml_array_prefix) {
                if (dcerpc_text_printf(ctx, iov, "- ")) {
                        return -1;
                }
                pdu->yaml_array_prefix = 0;
        }
        return 0;
}

/*
 * Start a YAML "name: " line. An anonymous array element (name NULL, see
 * scalar_carray_coder) is just the value after the list item's "- ".
 */
static int
yaml_print_key(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
               struct dcerpc_iovec *iov, const char *name)
{
        if (yaml_print_preamble(ctx, pdu, iov)) {
                return -1;
        }
        if (name == NULL) {
                return 0;
        }
        return dcerpc_text_printf(ctx, iov, "%s: ", name);
}

/*
 * Does the current key match name? An anonymous array element (name
 * NULL) is a key-less list item, which yaml_next_kv() returns as key "".
 */
/*
 * yaml_next_kv() failed: leave a key no name matches and no value, so
 * every coder after it fails its key check instead of dereferencing a
 * NULL key or value; callers do not check yaml_next_kv()'s return.
 */
static char yaml_failed_key[] = "\001";

static void
yaml_set_failed(struct dcerpc_pdu *pdu)
{
        pdu->yaml_key = yaml_failed_key;
        pdu->yaml_val = NULL;
}

static int
yaml_key_mismatch(struct dcerpc_pdu *pdu, const char *name)
{
        if (pdu->yaml_key == NULL) {
                return 1;
        }
        if (name == NULL) {
                /*
                 * An anonymous element ("- value"). The end of the input
                 * also has key "" but no value: a list shorter than its
                 * count must not read that as an element.
                 */
                return pdu->yaml_key[0] != '\0' || pdu->yaml_val == NULL;
        }
        return strcmp(pdu->yaml_key, name);
}

/* name for error messages */
static const char *
yaml_name(const char *name)
{
        return name ? name : "array element";
}

/*
 * A double-quoted YAML scalar, unquoted in place. Values that a plain
 * scalar can not carry (control characters, a leading '"' or '#', " #",
 * leading or trailing blanks, ": " in a list element) are written quoted
 * by yaml_print_string().
 * Escapes: \\ \" \n \r \t \xHH. After the closing quote only blanks and
 * a # comment may follow.
 */
static int
yaml_unquote(char *str)
{
        char *in = str + 1;
        char *out = str;

        while (*in != '"') {
                unsigned int v;
                int i;

                if (*in == '\0') {
                        return -1;
                }
                if (*in != '\\') {
                        *out++ = *in++;
                        continue;
                }
                in++;
                switch (*in) {
                case '\\':
                case '"':
                        *out++ = *in++;
                        break;
                case 'n':
                        *out++ = '\n';
                        in++;
                        break;
                case 'r':
                        *out++ = '\r';
                        in++;
                        break;
                case 't':
                        *out++ = '\t';
                        in++;
                        break;
                case 'x':
                        in++;
                        v = 0;
                        for (i = 0; i < 2; i++) {
                                int n = hex_nibble(*in);

                                if (n < 0) {
                                        return -1;
                                }
                                v = (v << 4) | (unsigned int)n;
                                in++;
                        }
                        if (v == 0) {
                                return -1;
                        }
                        *out++ = (char)v;
                        break;
                default:
                        return -1;
                }
        }
        in++;
        while (*in == ' ' || *in == '\t') {
                in++;
        }
        if (*in != '\0' && *in != '#') {
                return -1;
        }
        *out = '\0';
        return 0;
}

/*
 * Does a string need yaml_print_string() to quote it? An anonymous list
 * element ("- value") also must not look like "key: value".
 */
static int
yaml_needs_quoting(const char *s, int anonymous)
{
        size_t len = strlen(s);
        size_t i;

        if (len == 0) {
                return 0;
        }
        if (s[0] == '"' || s[0] == '#' || s[0] == ' ' || s[0] == '\t' ||
            s[len - 1] == ' ' || s[len - 1] == '\t') {
                return 1;
        }
        for (i = 0; i < len; i++) {
                unsigned char c = (unsigned char)s[i];

                if (c < 0x20 || c == 0x7f) {
                        return 1;
                }
                if (c == '#' && (s[i - 1] == ' ' || s[i - 1] == '\t')) {
                        return 1;
                }
                if (anonymous && c == ':' &&
                    (s[i + 1] == '\0' || s[i + 1] == ' ' ||
                     s[i + 1] == '\t')) {
                        return 1;
                }
        }
        return 0;
}

/*
 * A string value: plain when it reads back unchanged, else double-quoted
 * and escaped. The strings often come from the peer, and one with a
 * newline must not be able to add a key of its own to the output.
 */
static int
yaml_print_string(struct dcerpc_context *ctx, struct dcerpc_iovec *iov,
                  const char *s, int anonymous)
{
        if (!yaml_needs_quoting(s, anonymous)) {
                return dcerpc_text_printf(ctx, iov, "%s\n", s);
        }
        if (dcerpc_text_printf(ctx, iov, "\"")) {
                return -1;
        }
        for (; *s; s++) {
                unsigned char c = (unsigned char)*s;
                int rc;

                switch (c) {
                case '\\':
                        rc = dcerpc_text_printf(ctx, iov, "\\\\");
                        break;
                case '"':
                        rc = dcerpc_text_printf(ctx, iov, "\\\"");
                        break;
                case '\n':
                        rc = dcerpc_text_printf(ctx, iov, "\\n");
                        break;
                case '\r':
                        rc = dcerpc_text_printf(ctx, iov, "\\r");
                        break;
                case '\t':
                        rc = dcerpc_text_printf(ctx, iov, "\\t");
                        break;
                default:
                        if (c < 0x20 || c == 0x7f) {
                                rc = dcerpc_text_printf(ctx, iov, "\\x%02x",
                                                        c);
                        } else {
                                rc = dcerpc_text_printf(ctx, iov, "%c", c);
                        }
                        break;
                }
                if (rc) {
                        return -1;
                }
        }
        return dcerpc_text_printf(ctx, iov, "\"\n");
}

/*
 * Advance to the next YAML key: value (or list item "- key: value").
 *
 * Skips blank lines and # comments:
 *   - full-line comments: optional indent, then '#' to end of line
 *   - trailing comments: "key: value # comment" (space/tab before '#')
 *
 * '#' inside an unquoted value with no preceding whitespace is kept as
 * part of the value (e.g. password: abc#def). A value in double quotes
 * is taken as it is quoted (yaml_unquote()), # and all.
 */
static int
yaml_next_kv(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov)
{
        char *str;
        char *hash;
        char *end;
        char *sep;
        int item;

        if (pdu->yaml_key) {
                return 0;
        }

again:
        if (iov->offset >= iov->max_offset || iov->buf[iov->offset] == '\0') {
                /*
                 * End of buffer: leave an empty key so callers that
                 * strcmp(yaml_key, name) for optional UNIQUE fields do not
                 * crash (same as a blank line with no ':').
                 */
                pdu->yaml_key = (char *)"";
                pdu->yaml_val = NULL;
                return 0;
        }

        /*
         * Parse a copy of the line: decoding never writes the input, and
         * the key and value strings live as long as the decoded data.
         */
        {
                size_t start = iov->offset;
                size_t len;

                while (iov->offset < iov->max_offset &&
                       iov->buf[iov->offset] != '\0' &&
                       iov->buf[iov->offset] != '\n') {
                        (iov->offset)++;
                }
                len = iov->offset - start;
                if (iov->offset < iov->max_offset &&
                    iov->buf[iov->offset] == '\n') {
                        (iov->offset)++;
                }
                str = dcerpc_alloc_data(pdu, len + 1);
                if (str == NULL) {
                        yaml_set_failed(pdu);
                        return -1;
                }
                memcpy(str, &iov->buf[start], len);
                str[len] = '\0';
        }

        pdu->yaml_indentation = 0;
        while (*str == ' ' || *str == '\t') {
                str++;
                pdu->yaml_indentation++;
        }
        /* Blank line or full-line comment → try the next line. */
        if (*str == '\0' || *str == '#') {
                goto again;
        }
        /* YAML list items: "  - key: value" (optional spaces after '-'). */
        item = 0;
        if (str[0] == '-' && (str[1] == ' ' || str[1] == '\t' ||
                              str[1] == '\0')) {
                item = 1;
                str += str[1] ? 2 : 1;
                while (*str == ' ' || *str == '\t') {
                        str++;
                }
                if (*str == '#') {
                        goto again;
                }
                /* "- "quoted"": an anonymous element, whatever it holds */
                if (*str == '"') {
                        pdu->yaml_key = (char *)"";
                        goto value;
                }
        }

        /* The key ends at ": " or at a ':' that ends the line. */
        for (sep = str; (sep = strchr(sep, ':')) != NULL; sep++) {
                if (sep[1] == '\0' || sep[1] == ' ' || sep[1] == '\t') {
                        break;
                }
        }
        if (sep == NULL) {
                if (item) {
                        /*
                         * "- value": an anonymous array element; the
                         * key is "" (see yaml_key_mismatch()).
                         */
                        pdu->yaml_key = (char *)"";
                        goto value;
                }
                /* Not a key: line (e.g. ---); skip and continue. */
                pdu->yaml_key = NULL;
                goto again;
        }
        pdu->yaml_key = str;
        str = sep;
        *str++ = 0;
        /* Trim trailing whitespace from key. */
        end = pdu->yaml_key + strlen(pdu->yaml_key);
        while (end > pdu->yaml_key &&
               (end[-1] == ' ' || end[-1] == '\t')) {
                *--end = '\0';
        }
        while (*str == ' ' || *str == '\t') {
                str++;
        }
value:
        if (*str == '"') {
                char *q = dcerpc_alloc_data(pdu, strlen(str) + 1);

                if (q == NULL) {
                        yaml_set_failed(pdu);
                        return -1;
                }
                strcpy(q, str);
                if (yaml_unquote(q) == 0) {
                        pdu->yaml_val = q;
                        return 0;
                }
                /* Not a well-formed quoted string: take it as it is. */
                dcerpc_set_error(pdu->dce, "YAML bad quoted value for %s",
                                 pdu->yaml_key);
        }
        /*
         * Strip a trailing # comment from the value. A '#' starts a comment
         * only when it is at the start of the value or preceded by whitespace
         * (so password: abc#def keeps the hash; "value # note" drops the note).
         */
        for (hash = str; *hash; hash++) {
                if (*hash != '#') {
                        continue;
                }
                if (hash == str || hash[-1] == ' ' || hash[-1] == '\t') {
                        end = hash;
                        while (end > str &&
                               (end[-1] == ' ' || end[-1] == '\t')) {
                                end--;
                        }
                        *end = '\0';
                        break;
                }
        }
        pdu->yaml_val = str;

        return 0;
}


/*
 * NDR coders
 */
/* Encode words that vary in size depending on the transport syntax */
int
ndr_uint3264_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr)
{
        uint32_t u32 = 0;
        uint64_t val = *(uint64_t *)ptr;

        if (pdu->is_conformance_run) {
                if (pdu->ndr64) {
                        if (pdu->max_alignment < 8) {
                                pdu->max_alignment = 8;
                        }
                } else {
                        if (pdu->max_alignment < 4) {
                                pdu->max_alignment = 4;
                        }
                }
                return 0;
        }
        if (pdu->direction == DCERPC_DECODE) {
                if (pdu->ndr64) {
                        if (dcerpc_get_uint64(ctx, pdu, iov, ptr)) {
                                return -1;
                        }
                } else {
                        if (dcerpc_get_uint32(ctx, pdu, iov, &u32)) {
                                return -1;
                        }
                        *(uint64_t *)ptr = u32;
                }
        } else {
                if (pdu->ndr64) {
                        if (dcerpc_set_uint64(ctx, pdu, iov, val)) {
                                return -1;
                        }
                } else {
                        if (dcerpc_set_uint32(ctx, pdu, iov, (uint32_t)val)) {
                                return -1;
                        }
                }
        }
        return 0;
}

static int
ndr_conformance_coder(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov, void *ptr)
{
        uint32_t u32 = 0;
        uint64_t val = *(uint64_t *)ptr;

        if (!pdu->is_conformance_run) {
                return 0;
        }

        if (pdu->direction == DCERPC_DECODE) {
                if (pdu->ndr64) {
                        if (dcerpc_get_uint64(ctx, pdu, iov, ptr)) {
                                return -1;
                        }
                } else {
                        if (dcerpc_get_uint32(ctx, pdu, iov, &u32)) {
                                return -1;
                        }
                        *(uint64_t *)ptr = u32;
                }
        } else {
                if (pdu->ndr64) {
                        if (dcerpc_set_uint64(ctx, pdu, iov, val)) {
                                return -1;
                        }
                } else {
                        if (dcerpc_set_uint32(ctx, pdu, iov, val)) {
                                return -1;
                        }
                }
        }
        return 0;
}

int
ndr_uint8_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->is_conformance_run) {
                if (pdu->max_alignment < 1) {
                        pdu->max_alignment = 1;
                }
                return 0;
        }
        if (pdu->direction == DCERPC_DECODE) {
                return dcerpc_get_uint8(ctx, iov, ptr);
        } else {
                return dcerpc_set_uint8(ctx, iov, *(uint8_t *)ptr);
        }

        return 0;
}

/*
 * A conformance or variance value of a byte array: 32 bits in NDR32, 64
 * bits in NDR64. Values above 32 bits are rejected on decode.
 */
static int
ndr_count_coder(char *name, struct dcerpc_context *ctx,
                struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov, uint32_t *count)
{
        uint64_t v = *count;

        if (ndr_uint3264_coder(name, ctx, pdu, iov, &v)) {
                return -1;
        }
        if (v > UINT32_MAX) {
                return -1;
        }
        *count = (uint32_t)v;
        return 0;
}

/*
 * [size_is(len)] byte data[] — conformant byte array.
 * Wire: max_count, then max_count bytes. ptr is struct dcerpc_bytes *.
 */
static int
ndr_bytes_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, void *ptr)
{
        struct dcerpc_bytes *b = ptr;
        uint32_t max_count;
        uint32_t i;

        if (pdu->is_conformance_run) {
                return 0;
        }

        if (pdu->direction == DCERPC_ENCODE) {
                max_count = b->len;
        } else {
                max_count = 0;
        }
        if (ndr_count_coder("MaxCount", ctx, pdu, iov, &max_count)) {
                return -1;
        }
        if (pdu->direction == DCERPC_DECODE) {
                if (max_count > DCERPC_BYTES_MAX) {
                        return -1;
                }
                b->len = max_count;
                if (max_count == 0) {
                        b->data = NULL;
                        return 0;
                }
                b->data = dcerpc_alloc_array(pdu, iov, max_count, 1);
                if (b->data == NULL) {
                        return -1;
                }
                for (i = 0; i < max_count; i++) {
                        if (dcerpc_get_uint8(ctx, iov, &b->data[i])) {
                                return -1;
                        }
                }
                return 0;
        }
        for (i = 0; i < max_count; i++) {
                if (dcerpc_set_uint8(ctx, iov,
                                     b->data ? b->data[i] : 0)) {
                        return -1;
                }
        }
        return 0;
}

/*
 * [size_is(max_count), length_is(len)] byte data[] — conformant-varying
 * byte array. Wire: max_count, offset, actual_count, then actual_count
 * bytes. ptr is struct dcerpc_varying_bytes *.
 */
static int
ndr_varying_bytes_coder(char *name, struct dcerpc_context *ctx,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, void *ptr)
{
        struct dcerpc_varying_bytes *b = ptr;
        uint32_t max_count;
        uint32_t arr_offset = 0;
        uint32_t actual;
        uint32_t i;

        if (pdu->is_conformance_run) {
                return 0;
        }

        if (pdu->direction == DCERPC_ENCODE) {
                max_count = b->max_count;
                actual = b->len;
                if (actual > max_count) {
                        return -1;
                }
        } else {
                max_count = 0;
                actual = 0;
        }
        if (ndr_count_coder("MaxCount", ctx, pdu, iov, &max_count) ||
            ndr_count_coder("Offset", ctx, pdu, iov, &arr_offset) ||
            ndr_count_coder("ActualCount", ctx, pdu, iov, &actual)) {
                return -1;
        }
        if (pdu->direction == DCERPC_DECODE) {
                if (actual > max_count || actual > DCERPC_BYTES_MAX ||
                    arr_offset != 0) {
                        return -1;
                }
                b->max_count = max_count;
                b->len = actual;
                if (actual == 0) {
                        b->data = NULL;
                        return 0;
                }
                b->data = dcerpc_alloc_array(pdu, iov, actual, 1);
                if (b->data == NULL) {
                        return -1;
                }
                for (i = 0; i < actual; i++) {
                        if (dcerpc_get_uint8(ctx, iov, &b->data[i])) {
                                return -1;
                        }
                }
                return 0;
        }
        for (i = 0; i < actual; i++) {
                if (dcerpc_set_uint8(ctx, iov,
                                     b->data ? b->data[i] : 0)) {
                        return -1;
                }
        }
        return 0;
}

int
ndr_uint16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->is_conformance_run) {
                if (pdu->max_alignment < 2) {
                        pdu->max_alignment = 2;
                }
                return 0;
        }
        
        if (pdu->direction == DCERPC_DECODE) {
                return dcerpc_get_uint16(ctx, pdu, iov, ptr);
        } else {
                return dcerpc_set_uint16(ctx, pdu, iov, *(uint16_t *)ptr);
        }
}

static int
ndr_uint16_coder_pp(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, void *ptr,
                    struct dcerpc_uint32_pretty_printer *pp)
{
        return ndr_uint16_coder(name, ctx, pdu, iov, ptr);
}
        
int
ndr_uint32_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->is_conformance_run) {
                if (pdu->max_alignment < 4) {
                        pdu->max_alignment = 4;
                }
                return 0;
        }
        if (pdu->direction == DCERPC_DECODE) {
                return dcerpc_get_uint32(ctx, pdu, iov, ptr);
        } else {
                return dcerpc_set_uint32(ctx, pdu, iov, *(uint32_t *)ptr);
        }
}
static int
ndr_uint32_coder_pp(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, void *ptr,
                    struct dcerpc_uint32_pretty_printer *pp)
{
        return ndr_uint32_coder(name, ctx, pdu, iov, ptr);
}

static int
ndr_uint64_coder(char *name _U_, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->is_conformance_run) {
                if (pdu->max_alignment < 8) {
                        pdu->max_alignment = 8;
                }
                return 0;
        }

        if (pdu->direction == DCERPC_DECODE) {
                return dcerpc_get_uint64(ctx, pdu, iov, ptr);
        } else {
                return dcerpc_set_uint64(ctx, pdu, iov, *(uint64_t *)ptr);
        }
}

int
ndr_uuid_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
               struct dcerpc_iovec *iov, void *ptr)
{
        int i;
        struct dcerpc_uuid *uuid = ptr;
        
        if (ndr_uint32_coder("V1", ctx, pdu, iov, &uuid->v1)) {
                return -1;
        }
        if (ndr_uint16_coder("V2", ctx, pdu, iov, &uuid->v2)) {
                return -1;
        }
        if (ndr_uint16_coder("V3", ctx, pdu, iov, &uuid->v3)) {
                return -1;
        }
        for (i = 0; i < 8; i++) {
                if (ndr_uint8_coder("V4", ctx, pdu, iov, &uuid->v4[i])) {
                        return -1;
                }
        }

        return 0;
}        

static int
ndr_do_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
             struct dcerpc_iovec *iov, void *ptr,
             dcerpc_coder coder)
{
        uint32_t size_is = pdu->size_is;
        uint32_t length_is = pdu->length_is;
        int switch_is = pdu->switch_is;

        pdu->max_alignment = 1;
        pdu->is_conformance_run = 1;
        if (coder(name, ctx, pdu, iov, ptr)) {
                return -1;
        }
        if (dcerpc_iov_align(pdu, iov, (size_t)pdu->max_alignment)) {
                return -1;
        }
        /*
         * Both runs must see the same inputs: nested coders in the
         * conformance run (e.g. array elements with their own size_is)
         * may have changed size_is/switch_is.
         */
        pdu->size_is = size_is;
        pdu->length_is = length_is;
        pdu->switch_is = switch_is;
        pdu->is_conformance_run = 0;
        if (coder(name, ctx, pdu, iov, ptr)) {
                return -1;
        }
        return 0;
}

int ndr_struct_coder(char *name, struct dcerpc_context *ctx,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov,
                        void *ptr, dcerpc_coder coder)
{
        return coder(name, ctx, pdu, iov, ptr);
}

int ndr_union_coder(char *name, struct dcerpc_context *ctx,
                    struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov,
                    uint32_t *switch_is, void *ptr, dcerpc_coder coder)
{
        uint64_t p;

        /* Conformance */
        p = *switch_is;
        if (ndr_uint3264_coder("", ctx, pdu, iov, &p)) {
                return -1;
        }
        if (dcerpc_union_check_discriminant(ctx, pdu, *switch_is, p)) {
                return -1;
        }
        *switch_is = p;

        /* Data */
        dcerpc_set_switch_is(pdu, p);
        if (coder(name, ctx, pdu, iov, ptr)) {
                return -1;
        }

        return 0;
}

static int
ndr_encode_utf16(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov,
                 void *ptr, int nult)
{
        struct dcerpc_utf16 *s = ptr;
        int i;
        uint64_t val;
        uint16_t zero = 0;

        /* Conformance part */
        if (pdu->is_conformance_run) {
                if (s->utf8) {
                        s->utf16 = dcerpc_utf8_to_utf16(s->utf8);
                } else {
                        s->utf16 = dcerpc_utf8_to_utf16("");
                }
                if (s->utf16 == NULL) {
                        return -1;
                }

                if (nult) {
                        val = s->utf16->len + 1;
                } else {
                        val = s->utf16->len;
                }
                s->actual_count = (uint32_t)val;
                if (!nult) {
                        if (val & 0x01) val++;
                }
                s->max_count = (uint32_t)val;
                s->offset    = 0;

                /*
                 * Honor dcerpc_set_unicode_max_length() so Buffer
                 * max_count matches RPC_UNICODE_STRING.MaximumLength/2.
                 * Override is in bytes; max_count is in wchar units.
                 * Cleared here so the next string starts clean.
                 */
                if (pdu->unicode_max_length) {
                        uint32_t ovr = (uint32_t)(pdu->unicode_max_length / 2);

                        if (ovr > s->max_count) {
                                s->max_count = ovr;
                        }
                        pdu->unicode_max_length = 0;
                }
                val = s->max_count;
                if (ndr_conformance_coder(ctx, pdu, iov, &val)) {
                        free(s->utf16);
                        s->utf16 = NULL;
                        return -1;
                }
                val = s->offset;
                if (ndr_conformance_coder(ctx, pdu, iov, &val)) {
                        free(s->utf16);
                        s->utf16 = NULL;
                        return -1;
                }
                val = s->actual_count;
                if (ndr_conformance_coder(ctx, pdu, iov, &val)) {
                        free(s->utf16);
                        s->utf16 = NULL;
                        return -1;
                }
                if (pdu->max_alignment < 2) {
                        pdu->max_alignment = 2;
                }
                return 0;
        }

        /* Data part */
        for (i = 0; i < s->utf16->len; i++) {
                if (dcerpc_uint16_coder("Utf16", ctx, pdu, iov, &s->utf16->val[i])) {
                        free(s->utf16);
                        s->utf16 = NULL;
                        return -1;
                }
        }
        if (nult) {
                if (dcerpc_uint16_coder("Nult", ctx, pdu, iov, &zero)) {
                        free(s->utf16);
                        s->utf16 = NULL;
                        return -1;
                }
        }
        free(s->utf16);
        s->utf16 = NULL;
        return 0;
}

static int
ndr_decode_utf16(struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov,
                 void *ptr, int nult)
{
        struct dcerpc_utf16 *s = ptr;
        uint64_t val = 0;
        char *str;
        const char *tmp;
        const uint8_t *units8;
        uint32_t i;

        /* Conformance part */
        if (pdu->is_conformance_run) {
                /* NDR64 counts are 64-bit; none of ours exceeds 32 */
                if (ndr_conformance_coder(ctx, pdu, iov, &val) ||
                    val > UINT32_MAX) {
                        return -1;
                }
                s->max_count = (uint32_t)val;
                if (ndr_conformance_coder(ctx, pdu, iov, &val) ||
                    val > UINT32_MAX) {
                        return -1;
                }
                s->offset = (uint32_t)val;
                if (ndr_conformance_coder(ctx, pdu, iov, &val) ||
                    val > UINT32_MAX) {
                        return -1;
                }
                s->actual_count = (uint32_t)val;
                if (pdu->max_alignment < 2) {
                        pdu->max_alignment = 2;
                }
                return 0;
        }
        
        /* Data part */
        if (s->actual_count > s->max_count || s->offset != 0) {
                return -1;
        }
        if ((uint64_t)iov->offset + (uint64_t)s->actual_count * 2u > iov->max_offset) {
                return -1;
        }
        /*
         * The string ends at its first NUL. Trailing NULs (a terminator,
         * or one counted in a Length) are fine, but characters after a
         * NUL would be silently dropped: "admin\0x" would read as
         * "admin". A unit is NUL when both its bytes are, in either
         * byte order.
         */
        units8 = &iov->buf[iov->offset];
        for (i = 0; i < s->actual_count; i++) {
                if (units8[2 * i] == 0 && units8[2 * i + 1] == 0) {
                        break;
                }
        }
        for (; i < s->actual_count; i++) {
                if (units8[2 * i] != 0 || units8[2 * i + 1] != 0) {
                        dcerpc_set_error(ctx, "DCERPC string with a NUL "
                                         "inside it");
                        return -1;
                }
        }
        if (!(pdu->hdr.packed_drep[0] & DCERPC_DR_LITTLE_ENDIAN)) {
                /* Byte-swap into a copy: decoding never writes the input */
                size_t start = iov->offset;
                uint16_t *units;

                units = malloc((s->actual_count ? s->actual_count : 1) *
                               sizeof(uint16_t));
                if (units == NULL) {
                        return -1;
                }
                for (i = 0; i < s->actual_count; i++) {
                        if (dcerpc_get_uint16(ctx, pdu, iov, &units[i])) {
                                free(units);
                                return -1;
                        }
                }
                tmp = dcerpc_utf16_to_utf8(units, (size_t)s->actual_count);
                free(units);
                iov->offset = start;
        } else {
                tmp = dcerpc_utf16_to_utf8((uint16_t *)(void *)(&iov->buf[iov->offset]), (size_t)s->actual_count);
        }
        if (tmp == NULL) {
                return -1;
        }
        iov->offset += (size_t)s->actual_count * 2;

        str = dcerpc_alloc_data(pdu, strlen(tmp) + 1);
        if (str == NULL) {
                free(discard_const(tmp));
                return -1;
        }
        strcat(str, tmp);
        free(discard_const(tmp));

        s->utf8 = str;

        return 0;
}

/* ptr is char ** */
int
_ndr_utf16z_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov,
                  void *ptr, int nult)
{
        struct dcerpc_utf16 **u = ptr;
        struct dcerpc_utf16 *utf16;
        const char **s = ptr;
        const char *str;
        int ret = -1;

        if (pdu->is_conformance_run) {
                /* Swap the char * pointer to dcerpc_utf16 * */
                utf16 = calloc(1, sizeof(struct dcerpc_utf16));
                if (utf16 == NULL) {
                        return -1;
                }
                utf16->utf8 = *s;
                *u = utf16;
                ptr = utf16;
        } else {
                ptr = *u;
        }
        
        if (pdu->direction == DCERPC_DECODE) {
                ret = ndr_decode_utf16(ctx, pdu, iov, ptr, nult);
        } else {
                ret = ndr_encode_utf16(ctx, pdu, iov, ptr, nult);
        }

        if (pdu->is_conformance_run) {
                if (ret) {
                        /* Restore original char * and free temps on error */
                        utf16 = *u;
                        str = utf16->utf8;
                        free(utf16->utf16);
                        free(utf16);
                        *s = str;
                }
                return ret;
        }

        /* Data run: swap the pointer back */
        utf16 = *u;
        str = utf16->utf8;
        *s = str;
        free(utf16);

        return ret;
}

/* Handle \0 terminated utf16 strings */
/* ptr is char ** */
int
ndr_utf16z_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov,
                 void *ptr)
{
        return _ndr_utf16z_coder(name, ctx, pdu, iov, ptr, 1);
}

/* Handle utf16 strings that are NOT \0 terminated */
/* ptr is char ** */
int
ndr_utf16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov,
                void *ptr)
{
        return _ndr_utf16z_coder(name, ctx, pdu, iov, ptr, 0);
}

static int
dcerpc_add_deferred_pointer(struct dcerpc_context *ctx,
                            struct dcerpc_pdu *pdu,
                            dcerpc_coder coder, void *ptr)
{
        if (pdu->max_ptr >= pdu->ptrs_cap) {
                int cap = pdu->ptrs_cap ? pdu->ptrs_cap * 2 : 64;
                struct dcerpc_deferred_pointer *np;

                np = realloc(pdu->ptrs, cap * sizeof(*np));
                if (np == NULL) {
                        dcerpc_set_error(ctx, "Failed to grow deferred "
                                         "NDR pointer array");
                        return -1;
                }
                pdu->ptrs = np;
                pdu->ptrs_cap = cap;
        }
        pdu->ptrs[pdu->max_ptr].coder = coder;
        pdu->ptrs[pdu->max_ptr].ptr = ptr;
        pdu->ptrs[pdu->max_ptr].size_is = pdu->size_is;
        pdu->ptrs[pdu->max_ptr].length_is = pdu->length_is;
        pdu->ptrs[pdu->max_ptr].switch_is = pdu->switch_is;
        pdu->max_ptr++;
        return 0;
}

static int
dcerpc_process_deferred_pointers(struct dcerpc_context *ctx,
                                 struct dcerpc_pdu *pdu,
                                 struct dcerpc_iovec *iov)
{
        struct dcerpc_deferred_pointer *dp;
        int idx;

        while (pdu->cur_ptr != pdu->max_ptr) {
                idx = pdu->cur_ptr++;
                dp = &pdu->ptrs[idx];
                pdu->size_is = dp->size_is;
                pdu->length_is = dp->length_is;
                pdu->switch_is = dp->switch_is;
                if (ndr_do_coder("DEFERRED", ctx, pdu, iov, dp->ptr, dp->coder)) {
                        return -1;
                }
        }
        return 0;
}

static int
ndr_encode_ptr(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
               struct dcerpc_iovec *iov, void *ptr,
               enum ptr_type type, dcerpc_coder coder)
{
        int top_level = pdu->top_level;
        uint64_t val;

        if (pdu->is_conformance_run) {
                if (pdu->ndr64) {
                        if (pdu->max_alignment < 8) {
                                pdu->max_alignment = 8;
                        }
                } else {
                        if (pdu->max_alignment < 4) {
                                pdu->max_alignment = 4;
                        }
                }
                return 0;
        }

        switch (type) {
        case PTR_REF:
                if (pdu->top_level) {
                        pdu->top_level = 0;
                        if (ndr_do_coder(name, dce, pdu, iov, ptr, coder)) {
                                return -1;
                        }
                        pdu->top_level = top_level;
                        goto out;
                }

                val = RPTR;
                if (ndr_uint3264_coder("ReferentId", dce, pdu, iov, &val)) {
                        return -1;
                }
                if (dcerpc_add_deferred_pointer(dce, pdu, (dcerpc_coder)coder, ptr)) {
                        return -1;
                }
                break;
        case PTR_FULL:
                if (ptr == NULL) {
                        val = 0;
                        if (ndr_uint3264_coder("ReferentId", dce, pdu, iov, &val)) {
                                return -1;
                        }
                        goto out;
                }
                
                /*
                 * Like Windows, a full pointer never refers back to an
                 * earlier referent: each one gets a new id and its data.
                 * A reply continues after its request's highest id, which
                 * the peer chose: past the largest id the next one would
                 * wrap to 0, a NULL pointer followed by data.
                 */
                if (pdu->full_ptr_id >= (pdu->ndr64 ? UINT64_MAX :
                                         UINT32_MAX)) {
                        dcerpc_set_error(dce, "DCERPC out of full pointer "
                                         "ids");
                        return -1;
                }
                val = ++pdu->full_ptr_id;
                if (ndr_uint3264_coder("ReferentId", dce, pdu, iov, &val)) {
                        return -1;
                }
                if (pdu->top_level) {
                        pdu->top_level = 0;
                        if (ndr_do_coder(name, dce, pdu, iov, ptr, coder)) {
                                return -1;
                        }
                        pdu->top_level = top_level;
                } else {
                        if (dcerpc_add_deferred_pointer(dce, pdu, (dcerpc_coder)coder, ptr)) {
                                return -1;
                        }
                }
                break;
        case PTR_UNIQUE:
                if (ptr == NULL) {
                        val = 0;
                        if (ndr_uint3264_coder("ReferentId", dce, pdu, iov, &val)) {
                                return -1;
                        }
                        goto out;
                }

                val = UPTR;
                if (ndr_uint3264_coder("ReferentId", dce, pdu, iov, &val)) {
                        return -1;
                }
                if (pdu->top_level) {
                        pdu->top_level = 0;
                        if (ndr_do_coder(name, dce, pdu, iov, ptr, coder)) {
                                return -1;
                        }
                        pdu->top_level = top_level;
                } else {
                        if (dcerpc_add_deferred_pointer(dce, pdu, (dcerpc_coder)coder, ptr)) {
                                return -1;
                        }
                }
                break;
        }

 out:
        if (pdu->top_level) {
                pdu->top_level = 0;
                if (dcerpc_process_deferred_pointers(dce, pdu, iov)) {
                        return -1;
                }
                pdu->top_level = top_level;
        }
        return 0;
}

/* TODO conformance split
 * during the conformance run we need to do the alignment in all the
  coders, even for the coders that do  not have any conformance data.
*/
static int
ndr_decode_ptr(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
               struct dcerpc_iovec *iov, void *ptr,
               enum ptr_type type, dcerpc_coder coder)
{
        int top_level = pdu->top_level;
        uint64_t p;

        if (pdu->is_conformance_run) {
                if (!(type==PTR_REF && pdu->top_level)) {
                        if (pdu->ndr64) {
                                if (pdu->max_alignment < 8) {
                                        pdu->max_alignment = 8;
                                }
                        } else {
                                if (pdu->max_alignment < 4) {
                                        pdu->max_alignment = 4;
                                }
                        }
                }
                return 0;
        }
        
        switch (type) {
        case PTR_REF:
                if (pdu->top_level) {
                        pdu->top_level = 0;
                        if (ndr_do_coder(name, dce, pdu, iov, ptr, coder)) {
                                return -1;
                        }
                        pdu->top_level = top_level;
                        goto out;
                }

                if (ndr_uint3264_coder("ReferentId", dce, pdu, iov, &p)) {
                        return -1;
                }
                if (dcerpc_add_deferred_pointer(dce, pdu, (dcerpc_coder)coder, ptr)) {
                        return -1;
                }
                break;
        case PTR_FULL:
        case PTR_UNIQUE:
                if (ndr_uint3264_coder("ReferentId", dce, pdu, iov, &p)) {
                        return -1;
                }
                if (p == 0) {
                        return 0;
                }
                /*
                 * Windows sends the data after every full pointer, even
                 * one whose id it already used, so decode it like a
                 * unique pointer and only track the highest id.
                 */
                if (type == PTR_FULL && p > pdu->full_ptr_id) {
                        pdu->full_ptr_id = p;
                }
                if (ptr == NULL) {
                        /* Non-null wire referent but no local buffer: fail
                         * rather than leaving the referent body unconsumed
                         * and desynchronizing the rest of the stub.
                         */
                        dcerpc_set_error(dce, "DCERPC unique pointer "
                                         "referent present but destination is "
                                         "NULL");
                        return -1;
                }

                if (pdu->top_level) {
                        pdu->top_level = 0;
                        if (ndr_do_coder(name, dce, pdu, iov, ptr, coder)) {
                                return -1;
                        }
                        pdu->top_level = top_level;
                } else {
                        if (dcerpc_add_deferred_pointer(dce, pdu, (dcerpc_coder)coder, ptr)) {
                                return -1;
                        }
                }
                break;
        }

 out:
        if (pdu->top_level) {
                pdu->top_level = 0;
                if (dcerpc_process_deferred_pointers(dce, pdu, iov)) {
                        return -1;
                }
                pdu->top_level = top_level;
        }
        return 0;
}

int
ndr_carray_coder(char *name, struct dcerpc_context *ctx,
                 struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov,
                 uint32_t num, void *ptr, int elem_size, dcerpc_coder coder)
{
        uint32_t i;
        uint64_t p;
        uint8_t *data = ptr;

        /* Conformance */
        p = num;
        if (ndr_conformance_coder(ctx, pdu, iov, &p)) {
                return -1;
        }
        if (p != num) {
                return -1;
        }

        /* Data */
        for (i = 0; i < p; i++) {
                if (coder(name, ctx, pdu, iov, &data[(size_t)i * elem_size])) {
                        return -1;
                }
        }

        return 0;
}

/*
 * Conformant-varying array: max_count is conformance (coded in the
 * conformance run, so hoisted like a conformant array's), offset and
 * actual_count are variance and precede the elements, which are the
 * first num of max_count. On decode max_count must equal the expected
 * size_is and actual_count the expected length_is.
 */
static int
ndr_cvarray_coder(char *name, struct dcerpc_context *ctx,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov,
                  uint32_t max_count, uint32_t num, void *ptr,
                  int elem_size, dcerpc_coder coder)
{
        uint8_t *data = ptr;
        uint64_t p = max_count;
        uint64_t off = 0;
        uint64_t actual = num;
        uint32_t i;

        if (num > max_count) {
                return -1;
        }
        if (ndr_conformance_coder(ctx, pdu, iov, &p)) {
                return -1;
        }
        if (p != max_count) {
                return -1;
        }
        if (ndr_uint3264_coder("Offset", ctx, pdu, iov, &off) ||
            ndr_uint3264_coder("ActualCount", ctx, pdu, iov,
                               &actual)) {
                return -1;
        }
        if (!pdu->is_conformance_run && (off != 0 || actual != num)) {
                return -1;
        }
        for (i = 0; i < num; i++) {
                if (coder(name, ctx, pdu, iov, &data[(size_t)i * elem_size])) {
                        return -1;
                }
        }
        return 0;
}

int
dcerpc_cvarray_coder(char *name, struct dcerpc_context *ctx,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov,
                     uint32_t max_count, uint32_t num, void *ptr,
                     int elem_size, dcerpc_coder coder)
{
        if (pdu->encoding != ENCODING_NDR) {
                /* the array holds max_count elements; NDR checks this too */
                if (num > max_count) {
                        dcerpc_set_error(ctx, "DCERPC %s has %u elements, "
                                         "room for %u", name, num, max_count);
                        return -1;
                }
                return dcerpc_carray_coder(name, ctx, pdu, iov, num,
                                           ptr, elem_size, coder);
        }
        return ndr_cvarray_coder(name, ctx, pdu, iov, max_count, num,
                                 ptr, elem_size, coder);
}

int
dcerpc_scalar_cvarray_coder(char *name, struct dcerpc_context *ctx,
                            struct dcerpc_pdu *pdu,
                            struct dcerpc_iovec *iov,
                            uint32_t max_count, uint32_t num, void *ptr,
                            int elem_size, dcerpc_coder coder)
{
        if (pdu->encoding != ENCODING_NDR) {
                /* the array holds max_count elements; NDR checks this too */
                if (num > max_count) {
                        dcerpc_set_error(ctx, "DCERPC %s has %u elements, "
                                         "room for %u", name, num, max_count);
                        return -1;
                }
                return dcerpc_scalar_carray_coder(name, ctx, pdu, iov, num,
                                                  ptr, elem_size, coder);
        }
        return ndr_cvarray_coder(name, ctx, pdu, iov, max_count, num,
                                 ptr, elem_size, coder);
}

int
ndr_ptr_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
              struct dcerpc_iovec *iov, void *ptr,
              enum ptr_type type, dcerpc_coder coder)
{
        if (pdu->direction == DCERPC_DECODE) {
                return ndr_decode_ptr(name, dce, pdu, iov, ptr,
                                      type, coder);
        } else {
                return ndr_encode_ptr(name, dce, pdu, iov, ptr,
                                      type, coder);
        }
}

struct dcerpc_coders ndr_coders = {
        .uint8_coder     = ndr_uint8_coder,
        .uint16_coder    = ndr_uint16_coder,
        .uint16_coder_pp = ndr_uint16_coder_pp,
        .uint32_coder    = ndr_uint32_coder,
        .uint32_coder_pp = ndr_uint32_coder_pp,
        .uint64_coder    = ndr_uint64_coder,
        .uuid_coder      = ndr_uuid_coder,
        .sid_coder       = ndr_sid_coder,
        .utf16_coder     = ndr_utf16_coder,
        .utf16z_coder    = ndr_utf16z_coder,
        .unicode_string_coder  = ndr_RPC_UNICODE_STRING_coder,
        .unicode_stringz_coder = ndr_RPC_UNICODE_STRINGz_coder,
        .struct_coder    = ndr_struct_coder,
        .do_coder        = ndr_do_coder,
        .union_coder     = ndr_union_coder,
        .carray_coder    = ndr_carray_coder,
        .scalar_carray_coder = ndr_carray_coder,
        .ptr_coder       = ndr_ptr_coder,
        .bytes_coder     = ndr_bytes_coder,
        .varying_bytes_coder = ndr_varying_bytes_coder,
};


/*
 * Blob fields: a [size_is(len)] unique byte array whose bytes are a
 * packet-form object such as a self-relative SECURITY_DESCRIPTOR. The C
 * struct holds the decoded object instead of the bytes.
 */
struct dcerpc_blob {
        struct dcerpc_bytes bytes;
        void **objp;
        size_t obj_size;
        dcerpc_coder coder;
        int present;
};

/* Serialize obj with coder into a buffer on pdu. */
static int
blob_serialize(struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
               void *obj, dcerpc_coder coder, uint8_t **bytes, uint32_t *len)
{
        struct dcerpc_iovec iov = {0};

        if (coder("", dce, pdu, &iov, obj)) {
                dcerpc_free_iovec(&iov);
                return -1;
        }
        *bytes = dcerpc_alloc_data(pdu, iov.offset ? iov.offset : 1);
        if (*bytes == NULL) {
                dcerpc_free_iovec(&iov);
                return -1;
        }
        memcpy(*bytes, iov.buf, iov.offset);
        *len = (uint32_t)iov.offset;
        dcerpc_free_iovec(&iov);
        return 0;
}

/* NDR deferred body: max_count + bytes; on decode parse them into *objp. */
static int
blob_body_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, void *ptr)
{
        struct dcerpc_blob *b = ptr;
        struct dcerpc_iovec biov;
        void *obj;

        if (ndr_bytes_coder(name, dce, pdu, iov, &b->bytes)) {
                return -1;
        }
        if (pdu->is_conformance_run || pdu->direction == DCERPC_ENCODE ||
            b->bytes.len == 0) {
                return 0;
        }
        obj = dcerpc_alloc_data(pdu, b->obj_size);
        if (obj == NULL) {
                return -1;
        }
        biov = (struct dcerpc_iovec){
                .buf = b->bytes.data,
                .max_offset = b->bytes.len,
        };
        if (b->coder(name, dce, pdu, &biov, obj)) {
                return -1;
        }
        *b->objp = obj;
        return 0;
}

/* YAML/JSON: the pointer coders only call this when the key is present. */
static int
blob_text_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, void *ptr)
{
        struct dcerpc_blob *b = ptr;

        b->present = 1;
        return b->coder(name, dce, pdu, iov, *b->objp);
}

/*
 * The length field of a blob. NDR: on encode it is computed from obj (NULL
 * obj = 0). YAML/JSON: wire-only, so it is omitted (and 0 on decode).
 */
int
dcerpc_blob_len_coder(char *name, struct dcerpc_context *dce,
                      struct dcerpc_pdu *pdu,
                      struct dcerpc_iovec *iov,
                      uint32_t *len, void *obj, dcerpc_coder coder)
{
        uint8_t *bytes;

        if (pdu->encoding != ENCODING_NDR) {
                if (pdu->direction == DCERPC_DECODE) {
                        *len = 0;
                }
                return 0;
        }
        if (pdu->direction == DCERPC_ENCODE && !pdu->is_conformance_run) {
                *len = 0;
                if (obj && blob_serialize(dce, pdu, obj, coder, &bytes, len)) {
                        return -1;
                }
        }
        return ndr_uint32_coder(name, dce, pdu, iov, len);
}

/*
 * The byte-array field of a blob. objp is the address of the object
 * pointer field (e.g. SECURITY_DESCRIPTOR **), obj_size the object size.
 * NDR: unique pointer to [size_is(len)] bytes holding the object.
 * YAML/JSON: the object itself; a NULL object is an absent key.
 */
int
dcerpc_blob_coder(char *name, struct dcerpc_context *dce,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov,
                  uint32_t len, void *objp, size_t obj_size,
                  dcerpc_coder coder)
{
        void **op = objp;
        struct dcerpc_blob *b = NULL;

        if (pdu->encoding == ENCODING_NDR) {
                if (!pdu->is_conformance_run) {
                        if (pdu->direction == DCERPC_ENCODE && *op) {
                                b = dcerpc_alloc_data(pdu, sizeof(*b));
                                if (b == NULL ||
                                    blob_serialize(dce, pdu, *op, coder,
                                                   &b->bytes.data,
                                                   &b->bytes.len)) {
                                        return -1;
                                }
                                if (b->bytes.len != len) {
                                        dcerpc_set_error(dce, "Blob %s "
                                                         "length mismatch", name);
                                        return -1;
                                }
                        } else if (pdu->direction == DCERPC_DECODE) {
                                *op = NULL;
                                if (len) {
                                        b = dcerpc_alloc_data(pdu, sizeof(*b));
                                        if (b == NULL) {
                                                return -1;
                                        }
                                        b->objp = op;
                                        b->obj_size = obj_size;
                                        b->coder = coder;
                                }
                        }
                }
                return ndr_ptr_coder(name, dce, pdu, iov, b,
                                     PTR_UNIQUE, blob_body_coder);
        }

        if (pdu->direction == DCERPC_ENCODE && *op == NULL) {
                return 0;
        }
        b = dcerpc_alloc_data(pdu, sizeof(*b));
        if (b == NULL) {
                return -1;
        }
        b->objp = op;
        b->coder = coder;
        if (pdu->direction == DCERPC_DECODE) {
                *op = dcerpc_alloc_data(pdu, obj_size);
                if (*op == NULL) {
                        return -1;
                }
        }
        if (dcerpc_ptr_coder(name, dce, pdu, iov, b, PTR_UNIQUE,
                             blob_text_coder)) {
                return -1;
        }
        if (pdu->direction == DCERPC_DECODE && !b->present) {
                *op = NULL;
        }
        return 0;
}

/*
 * JSON Coders
 */
/*
 * JSON
 *
 * Text encoding parallel to YAML. Objects map to JSON objects, conformant
 * arrays to JSON arrays of objects, and scalars/strings/uuids/sids to
 * JSON numbers and strings. Example:
 *
 *   {
 *     "NetrShareEnum": {
 *       "Level": 2,
 *       "ShareInfo": {
 *         "EntriesRead": 1,
 *         "ShareInfo0": [
 *           {
 *             "NetName": "IPC$"
 *           }
 *         ]
 *       }
 *     }
 *   }
 */

/* Shared with YAML: pretty-printed uint32 values as "NAME | NAME | 0x10" */
static int text_print_pp_value(struct dcerpc_context *ctx,
                               struct dcerpc_iovec *iov,
                               struct dcerpc_uint32_pretty_printer *pp,
                               uint32_t value);
static int text_parse_pp_value(char *str,
                               struct dcerpc_uint32_pretty_printer *pp,
                               uint32_t *out);

static int json_append(struct dcerpc_iovec *iov, const char *s);

/*
 * The void writers below leave a failure to the next json_append(), which
 * reports it.
 */
static void
json_write_indent(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov)
{
        int i;

        for (i = 0; i < pdu->json_indentation; i++) {
                if (json_append(iov, "  ") < 0) {
                        return;
                }
        }
}

/*
 * Emit a separator before the next value in the current object/array:
 * optional comma, newline, then indentation. Marks that a subsequent
 * sibling will need a leading comma.
 */
static void
json_sep(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov)
{
        if (pdu->json_need_comma) {
                json_append(iov, ",");
        }
        json_append(iov, "\n");
        json_write_indent(pdu, iov);
        pdu->json_need_comma = 1;
}

/* Append a NUL-terminated string (the NUL is not counted in offset). */
static int
json_append(struct dcerpc_iovec *iov, const char *s)
{
        size_t n = strlen(s);

        if (dcerpc_iov_reserve(NULL, iov, n + 1)) {
                return -1;
        }
        memcpy(&iov->buf[iov->offset], s, n + 1);
        iov->offset += n;
        return 0;
}

/*
 * Write a JSON string value (including surrounding quotes), escaping
 * characters as required by RFC 8259.
 */
static int
json_append_quoted(struct dcerpc_iovec *iov, const char *s)
{
        const unsigned char *p;

        if (s == NULL) {
                s = "";
        }
        if (json_append(iov, "\"") < 0) {
                return -1;
        }
        for (p = (const unsigned char *)s; *p; p++) {
                char esc[8];
                const char *out;
                size_t n;

                switch (*p) {
                case '"':  out = "\\\""; n = 2; break;
                case '\\': out = "\\\\"; n = 2; break;
                case '\b': out = "\\b";  n = 2; break;
                case '\f': out = "\\f";  n = 2; break;
                case '\n': out = "\\n";  n = 2; break;
                case '\r': out = "\\r";  n = 2; break;
                case '\t': out = "\\t";  n = 2; break;
                default:
                        if (*p < 0x20) {
                                snprintf(esc, sizeof(esc), "\\u%04x", *p);
                                out = esc;
                                n = 6;
                        } else {
                                esc[0] = (char)*p;
                                out = esc;
                                n = 1;
                        }
                        break;
                }
                if (dcerpc_iov_reserve(NULL, iov, n + 1)) {
                        return -1;
                }
                memcpy(&iov->buf[iov->offset], out, n);
                iov->offset += n;
                iov->buf[iov->offset] = '\0';
        }
        if (json_append(iov, "\"") < 0) {
                return -1;
        }
        return 0;
}

/*
 * Start a JSON member: separator, then "name": . An anonymous array
 * element (name NULL, see scalar_carray_coder) is a bare value.
 */
static int
json_print_key(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
               const char *name)
{
        json_sep(pdu, iov);
        if (name == NULL) {
                return 0;
        }
        if (json_append_quoted(iov, name) < 0) {
                return -1;
        }
        return json_append(iov, ": ");
}

static int
json_skip_ws(struct dcerpc_iovec *iov)
{
        while (iov->offset < (int)iov->max_offset && iov->buf[iov->offset] != '\0') {
                char c = (char)iov->buf[iov->offset];

                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                        (iov->offset)++;
                        continue;
                }
                break;
        }
        return 0;
}

static int
json_expect_char(struct dcerpc_iovec *iov, char expect)
{
        json_skip_ws(iov);
        if (iov->offset >= (int)iov->max_offset || iov->buf[iov->offset] != (uint8_t)expect) {
                printf("JSON parse error: expected '%c'\n", expect);
                return -1;
        }
        (iov->offset)++;
        return 0;
}

/*
 * Parse a JSON string at iov->offset into the buffer in-place (unescaped).
 * Sets *start to the unescaped string (NUL-terminated in iov buffer).
 */
static int
json_parse_string(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                  char **start)
{
        char *dst;
        size_t end;

        json_skip_ws(iov);
        if (iov->offset >= iov->max_offset || iov->buf[iov->offset] != '"') {
                printf("JSON parse error: expected string\n");
                return -1;
        }
        (iov->offset)++;
        /*
         * Unescape into a copy: decoding never writes the input. The
         * unescaped string is no longer than the raw one, up to the
         * closing quote.
         */
        for (end = iov->offset; end < iov->max_offset &&
                     iov->buf[end] != '\0' && iov->buf[end] != '"'; end++) {
                if (iov->buf[end] == '\\' && end + 1 < iov->max_offset) {
                        end++;
                }
        }
        dst = dcerpc_alloc_data(pdu, end - iov->offset + 1);
        if (dst == NULL) {
                return -1;
        }
        *start = dst;

        while (iov->offset < (int)iov->max_offset && iov->buf[iov->offset] != '\0') {
                unsigned char c = iov->buf[iov->offset];

                if (c == '"') {
                        *dst = '\0';
                        (iov->offset)++;
                        return 0;
                }
                if (c == '\\') {
                        (iov->offset)++;
                        if (iov->offset >= (int)iov->max_offset) {
                                printf("JSON parse error: truncated escape\n");
                                return -1;
                        }
                        c = iov->buf[iov->offset];
                        switch (c) {
                        case '"':
                        case '\\':
                        case '/':
                                *dst++ = (char)c;
                                break;
                        case 'b': *dst++ = '\b'; break;
                        case 'f': *dst++ = '\f'; break;
                        case 'n': *dst++ = '\n'; break;
                        case 'r': *dst++ = '\r'; break;
                        case 't': *dst++ = '\t'; break;
                        case 'u': {
                                unsigned int cp = 0;
                                int i;

                                for (i = 0; i < 4; i++) {
                                        (iov->offset)++;
                                        if (iov->offset >= (int)iov->max_offset) {
                                                printf("JSON parse error: bad \\u escape\n");
                                                return -1;
                                        }
                                        c = iov->buf[iov->offset];
                                        cp <<= 4;
                                        if (c >= '0' && c <= '9') {
                                                cp |= c - '0';
                                        } else if (c >= 'a' && c <= 'f') {
                                                cp |= c - 'a' + 10;
                                        } else if (c >= 'A' && c <= 'F') {
                                                cp |= c - 'A' + 10;
                                        } else {
                                                printf("JSON parse error: bad \\u escape\n");
                                                return -1;
                                        }
                                }
                                /* BMP only; emit as ISO-8859-1 if < 256 else '?' */
                                *dst++ = (cp < 256) ? (char)cp : '?';
                                break;
                        }
                        default:
                                printf("JSON parse error: unknown escape \\%c\n", c);
                                return -1;
                        }
                        (iov->offset)++;
                        continue;
                }
                *dst++ = (char)c;
                (iov->offset)++;
        }
        printf("JSON parse error: unterminated string\n");
        return -1;
}

/*
 * Read the next object member key into pdu->json_key. If the next non-ws
 * character is '}', leaves it and returns 1 (end of object). Returns 0 on
 * key read, -1 on error.
 */
static int
json_next_key(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov)
{
        char *key;

        if (pdu->json_key) {
                return 0;
        }

        json_skip_ws(iov);
        if (iov->offset < (int)iov->max_offset && iov->buf[iov->offset] == '}') {
                return 1;
        }
        /* optional comma between members */
        if (iov->offset < (int)iov->max_offset && iov->buf[iov->offset] == ',') {
                (iov->offset)++;
                json_skip_ws(iov);
        }
        if (json_parse_string(pdu, iov, &key) < 0) {
                return -1;
        }
        if (json_expect_char(iov, ':') < 0) {
                return -1;
        }
        pdu->json_key = key;
        return 0;
}

/*
 * Ensure pdu->json_key holds the next object member key.
 * Returns 0 if a key is available, 1 at end of object, -1 on error.
 */
int
dcerpc_json_next_key(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov)
{
        return json_next_key(pdu, iov);
}

static int
json_expect_key(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                const char *name)
{
        int rc;

        if (name == NULL) {
                /* anonymous array element: a bare value, no key */
                return 0;
        }
        rc = json_next_key(pdu, iov);
        if (rc != 0) {
                if (rc > 0) {
                        printf("Wrong JSON key: expected %s but got end of object\n",
                               name);
                }
                return -1;
        }
        if (strcmp(pdu->json_key, name)) {
                printf("Wrong JSON key: expected %s but got %s\n",
                       name, pdu->json_key);
                return -1;
        }
        pdu->json_key = NULL;
        return 0;
}

/* Parse a JSON number (integer) into an unsigned long. */
static int
json_parse_ulong(struct dcerpc_iovec *iov, unsigned long *out)
{
        /*
         * strtoul() needs a NUL-terminated string and the buffer need not
         * be: parse a copy of at most what is left of it. No number we
         * take is longer than this.
         */
        char num[32];
        size_t n = 0;
        char *end;

        json_skip_ws(iov);
        while (n < sizeof(num) - 1 && iov->offset + n < iov->max_offset &&
               iov->buf[iov->offset + n] != '\0') {
                num[n] = (char)iov->buf[iov->offset + n];
                n++;
        }
        num[n] = '\0';
        errno = 0;
        *out = strtoul(num, &end, 0);
        if (end == num || errno == ERANGE) {
                printf("JSON parse error: expected number\n");
                return -1;
        }
        iov->offset += (size_t)(end - num);
        return 0;
}

/*
 * A value with a pretty printer is a JSON string of names, e.g.
 * "STYPE_IPC | STYPE_SPECIAL"; a plain number is accepted too.
 */
static int
json_parse_pp_value(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                    struct dcerpc_uint32_pretty_printer *pp,
                    unsigned long *out)
{
        char *str;
        uint32_t v;

        json_skip_ws(iov);
        if (pp == NULL || iov->offset >= (int)iov->max_offset ||
            iov->buf[iov->offset] != '"') {
                return json_parse_ulong(iov, out);
        }
        if (json_parse_string(pdu, iov, &str) < 0) {
                return -1;
        }
        if (text_parse_pp_value(str, pp, &v)) {
                return -1;
        }
        *out = v;
        return 0;
}

static int
json_print_pp_value(struct dcerpc_context *ctx, struct dcerpc_iovec *iov, struct dcerpc_uint32_pretty_printer *pp,
                    uint32_t value)
{
        if (pp == NULL) {
                return dcerpc_text_printf(ctx, iov, "%u", value);
        }
        if (dcerpc_text_printf(ctx, iov, "\"")) {
                return -1;
        }
        if (text_print_pp_value(ctx, iov, pp, value)) {
                return -1;
        }
        return dcerpc_text_printf(ctx, iov, "\"");
}

static int
json_uint8_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->direction == DCERPC_DECODE) {
                unsigned long v;

                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_parse_ulong(iov, &v) < 0) {
                        return -1;
                }
                *(uint8_t *)ptr = (uint8_t)v;
                return 0;
        } else {
                if (json_print_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "%u", *(uint8_t *)ptr)) {
                        return -1;
                }
                return 0;
        }
}

static int
_json_uint16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr,
                   struct dcerpc_uint32_pretty_printer *pp)
{
        if (pdu->direction == DCERPC_DECODE) {
                unsigned long v;

                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_parse_pp_value(pdu, iov, pp, &v) < 0) {
                        return -1;
                }
                *(uint16_t *)ptr = (uint16_t)v;
                return 0;
        } else {
                if (json_print_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_print_pp_value(ctx, iov, pp,
                                        *(uint16_t *)ptr)) {
                        return -1;
                }
                return 0;
        }
}

static int
json_uint16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, void *ptr)
{
        return _json_uint16_coder(name, ctx, pdu, iov, ptr, NULL);
}

static int
json_uint16_coder_pp(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, void *ptr,
                     struct dcerpc_uint32_pretty_printer *pp)
{
        return _json_uint16_coder(name, ctx, pdu, iov, ptr, pp);
}

static int
_json_uint32_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr,
                   struct dcerpc_uint32_pretty_printer *pp)
{
        if (pdu->direction == DCERPC_DECODE) {
                unsigned long v;

                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_parse_pp_value(pdu, iov, pp, &v) < 0) {
                        return -1;
                }
                *(uint32_t *)ptr = v;
                return 0;
        } else {
                if (json_print_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_print_pp_value(ctx, iov, pp,
                                        *(uint32_t *)ptr)) {
                        return -1;
                }
                return 0;
        }
}

static int
json_uint32_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, void *ptr)
{
        return _json_uint32_coder(name, ctx, pdu, iov, ptr, NULL);
}

static int
json_uint32_coder_pp(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, void *ptr,
                     struct dcerpc_uint32_pretty_printer *pp)
{
        return _json_uint32_coder(name, ctx, pdu, iov, ptr, pp);
}

static int
json_uint64_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->direction == DCERPC_DECODE) {
                unsigned long v;

                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_parse_ulong(iov, &v) < 0) {
                        return -1;
                }
                *(uint64_t *)ptr = (uint64_t)v;
                return 0;
        } else {
                if (json_print_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "%" PRIu64, *(uint64_t *)ptr)) {
                        return -1;
                }
                return 0;
        }
}

static int
json_uuid_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, void *ptr)
{
        int i;
        dcerpc_uuid_t *uuid = ptr;

        if (pdu->direction == DCERPC_DECODE) {
                char *val;
                unsigned int v1, v2, v3;
                unsigned int b[8];

                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_parse_string(pdu, iov, &val) < 0) {
                        return -1;
                }
                if (sscanf(val,
                           "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                           &v1, &v2, &v3,
                           &b[0], &b[1], &b[2], &b[3],
                           &b[4], &b[5], &b[6], &b[7]) != 11) {
                        printf("Failed to parse UUID value for %s: %s\n",
                               name ? name : "array element", val);
                        return -1;
                }
                uuid->v1 = v1;
                uuid->v2 = v2;
                uuid->v3 = v3;
                for (i = 0; i < 8; i++) {
                        uuid->v4[i] = b[i];
                }
                return 0;
        } else {
                char uuidstr[64];

                snprintf(uuidstr, sizeof(uuidstr),
                         "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         uuid->v1, uuid->v2, uuid->v3,
                         uuid->v4[0], uuid->v4[1],
                         uuid->v4[2], uuid->v4[3],
                         uuid->v4[4], uuid->v4[5],
                         uuid->v4[6], uuid->v4[7]);
                if (json_print_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_append_quoted(iov, uuidstr) < 0) {
                        return -1;
                }
                return 0;
        }
}

static int
json_struct_coder(char *name, struct dcerpc_context *ctx,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov,
                  void *ptr, dcerpc_coder coder)
{
        int ret;

        if (pdu->direction == DCERPC_DECODE) {
                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_expect_char(iov, '{') < 0) {
                        return -1;
                }
                pdu->json_key = NULL;
                ret = coder(name, ctx, pdu, iov, ptr);
                if (ret) {
                        return ret;
                }
                if (json_expect_char(iov, '}') < 0) {
                        return -1;
                }
                return 0;
        } else {
                json_sep(pdu, iov);
                if (json_append_quoted(iov, name) < 0) {
                        return -1;
                }
                if (json_append(iov, ": {") < 0) {
                        return -1;
                }
                pdu->json_need_comma = 0;
                pdu->json_indentation++;

                ret = coder(name, ctx, pdu, iov, ptr);
                pdu->json_indentation--;
                if (json_append(iov, "\n") < 0) {
                        return -1;
                }
                json_write_indent(pdu, iov);
                if (json_append(iov, "}") < 0) {
                        return -1;
                }
                pdu->json_need_comma = 1;
                return ret;
        }
}

static int
json_do_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
              struct dcerpc_iovec *iov, void *ptr,
              dcerpc_coder coder)
{
        int ret;

        if (pdu->direction == DCERPC_DECODE) {
                if (json_expect_char(iov, '{') < 0) {
                        return -1;
                }
                pdu->json_key = NULL;
                ret = json_struct_coder(name, ctx, pdu, iov, ptr, coder);
                if (ret) {
                        return ret;
                }
                if (json_expect_char(iov, '}') < 0) {
                        return -1;
                }
                return 0;
        } else {
                if (json_append(iov, "{") < 0) {
                        return -1;
                }
                pdu->json_need_comma = 0;
                pdu->json_indentation = 1;
                ret = json_struct_coder(name, ctx, pdu, iov, ptr, coder);
                pdu->json_indentation = 0;
                if (json_append(iov, "\n}\n") < 0) {
                        return -1;
                }
                return ret;
        }
}

static int
json_union_coder(char *name, struct dcerpc_context *ctx,
                 struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov,
                 uint32_t *switch_is, void *ptr, dcerpc_coder coder)
{
        int ret;

        if (pdu->direction == DCERPC_DECODE) {
                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_expect_char(iov, '{') < 0) {
                        return -1;
                }
                dcerpc_set_switch_is(pdu, *switch_is);
                pdu->json_key = NULL;
                /*
                 * Peek at the next key so the case coder receives the arm
                 * field name (mirrors yaml_union_coder).
                 */
                if (json_next_key(pdu, iov) < 0) {
                        return -1;
                }
                name = pdu->json_key;
                ret = coder(name, ctx, pdu, iov, ptr);
                if (ret) {
                        return ret;
                }
                if (json_expect_char(iov, '}') < 0) {
                        return -1;
                }
                return 0;
        } else {
                json_sep(pdu, iov);
                if (json_append_quoted(iov, name) < 0) {
                        return -1;
                }
                if (json_append(iov, ": {") < 0) {
                        return -1;
                }
                pdu->json_need_comma = 0;
                pdu->json_indentation++;
                dcerpc_set_switch_is(pdu, *switch_is);
                ret = coder(name, ctx, pdu, iov, ptr);
                pdu->json_indentation--;
                if (json_append(iov, "\n") < 0) {
                        return -1;
                }
                json_write_indent(pdu, iov);
                if (json_append(iov, "}") < 0) {
                        return -1;
                }
                pdu->json_need_comma = 1;
                return ret;
        }
}

static int
json_utf16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov,
                 void *ptr)
{
        if (pdu->direction == DCERPC_DECODE) {
                char *val;

                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_parse_string(pdu, iov, &val) < 0) {
                        return -1;
                }
                *(char **)ptr = val;
                return 0;
        } else {
                const char *s = *(char **)ptr;

                if (json_print_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_append_quoted(iov, s ? s : "") < 0) {
                        return -1;
                }
                return 0;
        }
}

/* Byte array as a hex string: "Name": "0a0b..." */
static int
json_bytes_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr)
{
        struct dcerpc_bytes *b = ptr;

        if (pdu->direction == DCERPC_DECODE) {
                char *val;

                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_parse_string(pdu, iov, &val) < 0) {
                        return -1;
                }
                return dcerpc_text_parse_hex(pdu, name, val, b);
        } else {
                if (json_print_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "\"")) {
                        return -1;
                }
                if (b->data &&
                    dcerpc_text_print_hex(ctx, iov, b->data, b->len)) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "\"")) {
                        return -1;
                }
                return 0;
        }
}

/*
 * Text encodings carry only the transmitted bytes, so a conformant-varying
 * array is coded like a plain byte array and max_count is len on decode.
 */
static int
text_varying_bytes_coder(char *name, struct dcerpc_context *ctx,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov, void *ptr,
                         dcerpc_coder bytes_coder)
{
        struct dcerpc_varying_bytes *vb = ptr;
        struct dcerpc_bytes b;

        b.len = vb->len;
        b.data = vb->data;
        if (bytes_coder(name, ctx, pdu, iov, &b)) {
                return -1;
        }
        if (pdu->direction == DCERPC_DECODE) {
                vb->max_count = b.len;
                vb->len = b.len;
                vb->data = b.data;
        }
        return 0;
}

static int
json_varying_bytes_coder(char *name, struct dcerpc_context *ctx,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov, void *ptr)
{
        return text_varying_bytes_coder(name, ctx, pdu, iov, ptr,
                                        json_bytes_coder);
}

static int
json_carray_coder(char *name, struct dcerpc_context *ctx,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov,
                  uint32_t num, void *ptr, int elem_size, dcerpc_coder coder)
{
        uint32_t i;
        uint8_t *data = ptr;

        if (pdu->direction == DCERPC_DECODE) {
                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_expect_char(iov, '[') < 0) {
                        return -1;
                }
                for (i = 0; i < num; i++) {
                        json_skip_ws(iov);
                        if (i > 0) {
                                if (json_expect_char(iov, ',') < 0) {
                                        return -1;
                                }
                        }
                        /* Each element is a JSON object of its fields */
                        if (json_expect_char(iov, '{') < 0) {
                                return -1;
                        }
                        pdu->json_key = NULL;
                        if (coder(name, ctx, pdu, iov,
                                  &data[(size_t)i * elem_size])) {
                                return -1;
                        }
                        if (json_expect_char(iov, '}') < 0) {
                                return -1;
                        }
                }
                if (json_expect_char(iov, ']') < 0) {
                        return -1;
                }
                return 0;
        } else {
                json_sep(pdu, iov);
                if (json_append_quoted(iov, name) < 0) {
                        return -1;
                }
                if (json_append(iov, ": [") < 0) {
                        return -1;
                }
                if (num == 0) {
                        if (json_append(iov, "]") < 0) {
                                return -1;
                        }
                        return 0;
                }

                pdu->json_indentation++;
                for (i = 0; i < num; i++) {
                        /* Array element separator */
                        pdu->json_need_comma = (i > 0);
                        json_sep(pdu, iov);
                        if (json_append(iov, "{") < 0) {
                                return -1;
                        }
                        pdu->json_need_comma = 0;
                        pdu->json_indentation++;
                        if (coder(name, ctx, pdu, iov,
                                  &data[(size_t)i * elem_size])) {
                                return -1;
                        }
                        pdu->json_indentation--;
                        if (json_append(iov, "\n") < 0) {
                                return -1;
                        }
                        json_write_indent(pdu, iov);
                        if (json_append(iov, "}") < 0) {
                                return -1;
                        }
                }
                pdu->json_indentation--;
                if (json_append(iov, "\n") < 0) {
                        return -1;
                }
                json_write_indent(pdu, iov);
                if (json_append(iov, "]") < 0) {
                        return -1;
                }
                pdu->json_need_comma = 1;
                return 0;
        }
}

/* Array of plain values as a JSON array: "Names": ["a", "b"] */
static int
json_scalar_carray_coder(char *name, struct dcerpc_context *ctx,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov,
                         uint32_t num, void *ptr, int elem_size,
                         dcerpc_coder coder)
{
        uint32_t i;
        uint8_t *data = ptr;

        if (pdu->direction == DCERPC_DECODE) {
                if (json_expect_key(pdu, iov, name) < 0) {
                        return -1;
                }
                if (json_expect_char(iov, '[') < 0) {
                        return -1;
                }
                for (i = 0; i < num; i++) {
                        json_skip_ws(iov);
                        if (i > 0) {
                                if (json_expect_char(iov, ',') < 0) {
                                        return -1;
                                }
                        }
                        if (coder(NULL, ctx, pdu, iov,
                                  &data[(size_t)i * elem_size])) {
                                return -1;
                        }
                }
                return json_expect_char(iov, ']');
        }
        if (json_print_key(pdu, iov, name) < 0) {
                return -1;
        }
        if (json_append(iov, "[") < 0) {
                return -1;
        }
        if (num == 0) {
                if (json_append(iov, "]") < 0) {
                        return -1;
                }
                pdu->json_need_comma = 1;
                return 0;
        }
        pdu->json_indentation++;
        for (i = 0; i < num; i++) {
                /* the element's json_print_key() writes the separator */
                pdu->json_need_comma = (i > 0);
                if (coder(NULL, ctx, pdu, iov, &data[(size_t)i * elem_size])) {
                        return -1;
                }
        }
        pdu->json_indentation--;
        if (json_append(iov, "\n") < 0) {
                return -1;
        }
        json_write_indent(pdu, iov);
        if (json_append(iov, "]") < 0) {
                return -1;
        }
        pdu->json_need_comma = 1;
        return 0;
}

static int
json_ptr_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
               struct dcerpc_iovec *iov, void *ptr,
               enum ptr_type type, dcerpc_coder coder)
{
        if (name == NULL) {
                /*
                 * Element of a list of bare values (scalar_carray_coder):
                 * the value itself; a NULL element cannot be shown.
                 */
                if (ptr == NULL) {
                        printf("NULL element in a list of values\n");
                        return -1;
                }
                return coder(name, dce, pdu, iov, ptr);
        }
        if (ptr == NULL) {
                return 0;
        }
        if (pdu->direction == DCERPC_DECODE) {
                int rc;

                rc = json_next_key(pdu, iov);
                if (rc < 0) {
                        return -1;
                }
                if (rc > 0 || strcmp(pdu->json_key, name)) {
                        /*
                         * UNIQUE and FULL pointers are optional: missing key
                         * means a NULL referent. Leave json_key set if
                         * present so the next field can consume it.
                         */
                        if (type != PTR_REF) {
                                return 0;
                        }
                        if (rc > 0) {
                                printf("Wrong JSON key: expected %s but got end of object\n",
                                       name);
                                return -1;
                        }
                }
                return coder(name, dce, pdu, iov, ptr);
        } else {
                return coder(name, dce, pdu, iov, ptr);
        }
}

/*
 * RPC_UNICODE_STRING (plain and NUL-terminated): text encodings show only
 * the string; Length/MaximumLength are NDR-only.
 */
struct dcerpc_coders json_coders = {
        .uint8_coder     = json_uint8_coder,
        .uint16_coder    = json_uint16_coder,
        .uint16_coder_pp = json_uint16_coder_pp,
        .uint32_coder    = json_uint32_coder,
        .uint32_coder_pp = json_uint32_coder_pp,
        .uint64_coder    = json_uint64_coder,
        .uuid_coder      = json_uuid_coder,
        .sid_coder       = text_sid_coder,
        .utf16_coder     = json_utf16_coder,
        .utf16z_coder    = json_utf16_coder,
        .unicode_string_coder  = json_utf16_coder,
        .unicode_stringz_coder = json_utf16_coder,
        .struct_coder    = json_struct_coder,
        .do_coder        = json_do_coder,
        .union_coder     = json_union_coder,
        .carray_coder    = json_carray_coder,
        .scalar_carray_coder = json_scalar_carray_coder,
        .ptr_coder       = json_ptr_coder,
        .bytes_coder     = json_bytes_coder,
        .varying_bytes_coder = json_varying_bytes_coder,
};



/*
 * YAML Coders
 */
static int
yaml_uint8_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->direction == DCERPC_DECODE) {
                yaml_next_kv(pdu, iov);
                if (yaml_key_mismatch(pdu, name)) {
                        printf("Wrong YAML key encountered for uint8. Expected %s but got %s\n",
                               yaml_name(name), pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                *(uint8_t *)ptr = (uint8_t)strtoul(pdu->yaml_val, NULL, 0);
                yaml_next_kv(pdu, iov);
                return 0;
        } else {
                if (yaml_print_key(ctx, pdu, iov, name)) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "%u\n", *(uint8_t *)ptr)) {
                        return -1;
                }
                return 0;
        }
}

/*
 * Print a pretty-printed value as "NAME1 | NAME2 | 0x10": every matching
 * bitfield name, followed by any bits no matching entry covers, formatted
 * with pp->fmt. If nothing matches the plain number is printed.
 */
static int
text_print_pp_value(struct dcerpc_context *ctx, struct dcerpc_iovec *iov, struct dcerpc_uint32_pretty_printer *pp,
                    uint32_t value)
{
        char *fmt = pp ? pp->fmt : "%u";
        uint32_t covered = 0;
        int count = 0;
        int i;

        for (i = 0; pp && pp->bitfields[i].name; i++) {
                if ((value & pp->bitfields[i].mask) != pp->bitfields[i].value) {
                        continue;
                }
                if (dcerpc_text_printf(ctx, iov, "%s%s",
                                       count ? " | " : "",
                                       pp->bitfields[i].name)) {
                        return -1;
                }
                covered |= pp->bitfields[i].mask;
                count++;
        }
        if (count && (value & ~covered) == 0) {
                return 0;
        }
        if (count && dcerpc_text_printf(ctx, iov, " | ")) {
                return -1;
        }
        return dcerpc_text_printf(ctx, iov, fmt,
                                  count ? value & ~covered : value);
}

/*
 * Parse a value written by text_print_pp_value(): a '|' separated list
 * of bitfield names and/or numbers that are OR'ed together. A plain
 * number is the degenerate case.
 */
static int
text_parse_pp_value(char *str, struct dcerpc_uint32_pretty_printer *pp,
                    uint32_t *out)
{
        char *tok, *next, *end;
        uint32_t value = 0;
        int i;

        if (str == NULL) {
                printf("YAML parse error: missing value\n");
                return -1;
        }
        for (tok = str; tok; tok = next) {
                next = strchr(tok, '|');
                if (next) {
                        *next++ = '\0';
                }
                while (*tok == ' ' || *tok == '\t') {
                        tok++;
                }
                end = tok + strlen(tok);
                while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) {
                        *--end = '\0';
                }
                if (*tok == '\0') {
                        continue;
                }
                if ((*tok >= '0' && *tok <= '9') || *tok == '-') {
                        value |= (uint32_t)strtoul(tok, NULL, 0);
                        continue;
                }
                for (i = 0; pp && pp->bitfields[i].name; i++) {
                        if (!strcmp(pp->bitfields[i].name, tok)) {
                                value |= pp->bitfields[i].value;
                                break;
                        }
                }
                if (pp == NULL || pp->bitfields[i].name == NULL) {
                        printf("YAML parse error: unknown value '%s'\n", tok);
                        return -1;
                }
        }
        *out = value;
        return 0;
}

static int
_yaml_uint16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr,
                   struct dcerpc_uint32_pretty_printer *pp)
{
        if (pdu->direction == DCERPC_DECODE) {
                uint32_t v;

                yaml_next_kv(pdu, iov);
                if (yaml_key_mismatch(pdu, name)) {
                        printf("Wrong YAML key encountered for uint16. Expected %s but got %s\n",
                               yaml_name(name), pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                if (text_parse_pp_value(pdu->yaml_val, pp, &v)) {
                        return -1;
                }
                *(uint16_t *)ptr = (uint16_t)v;
                yaml_next_kv(pdu, iov);
                return 0;
        } else {
                if (yaml_print_key(ctx, pdu, iov, name)) {
                        return -1;
                }
                if (text_print_pp_value(ctx, iov, pp,
                                        *(uint16_t *)ptr)) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "\n")) {
                        return -1;
                }
                return 0;
        }
}

static int
yaml_uint16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, void *ptr)
{
        return _yaml_uint16_coder(name, ctx, pdu, iov, ptr, NULL);
}

static int
yaml_uint16_coder_pp(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, void *ptr,
                     struct dcerpc_uint32_pretty_printer *pp)
{
        return _yaml_uint16_coder(name, ctx, pdu, iov, ptr, pp);
}

static int
_yaml_uint32_coder(char *name, struct dcerpc_context *ctx,
                   struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr,
                   struct dcerpc_uint32_pretty_printer *pp)
{
        if (dcerpc_pdu_direction(pdu) == DCERPC_DECODE) {
                uint32_t v;

                yaml_next_kv(pdu, iov);
                if (yaml_key_mismatch(pdu, name)) {
                        printf("Wrong YAML key encountered for uint32. Expected %s but got %s\n",
                               yaml_name(name), pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                if (text_parse_pp_value(pdu->yaml_val, pp, &v)) {
                        return -1;
                }
                *(uint32_t *)ptr = v;
                yaml_next_kv(pdu, iov);
                return 0;
        } else {
                if (yaml_print_key(ctx, pdu, iov, name)) {
                        return -1;
                }
                if (text_print_pp_value(ctx, iov, pp,
                                        *(uint32_t *)ptr)) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "\n")) {
                        return -1;
                }
                return 0;
        }
}

static int
yaml_uint32_coder(char *name, struct dcerpc_context *ctx,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, void *ptr)
{
        return _yaml_uint32_coder(name, ctx, pdu, iov, ptr, NULL);
}
        
static int
yaml_uint32_coder_pp(char *name, struct dcerpc_context *ctx,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, void *ptr,
                     struct dcerpc_uint32_pretty_printer *pp)
{
        return _yaml_uint32_coder(name, ctx, pdu, iov, ptr, pp);
}

static int
yaml_uint64_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, void *ptr)
{
        if (pdu->direction == DCERPC_DECODE) {
                yaml_next_kv(pdu, iov);
                if (yaml_key_mismatch(pdu, name)) {
                        printf("Wrong YAML key encountered for uint64. Expected %s but got %s\n",
                               yaml_name(name), pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                *(uint64_t *)ptr = strtoull(pdu->yaml_val, NULL, 0);
                yaml_next_kv(pdu, iov);
                return 0;
        } else {
                if (yaml_print_key(ctx, pdu, iov, name)) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "%" PRIu64 "\n", *(uint64_t *)ptr)) {
                        return -1;
                }
                return 0;
        }
}

static int
yaml_uuid_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                struct dcerpc_iovec *iov, void *ptr)
{
        int i;
        dcerpc_uuid_t *uuid = ptr;

        if (pdu->direction == DCERPC_DECODE) {
                unsigned int v1, v2, v3;
                unsigned int b[8];

                yaml_next_kv(pdu, iov);
                if (yaml_key_mismatch(pdu, name)) {
                        printf("Wrong YAML key encountered for uuid. Expected %s but got %s\n",
                               yaml_name(name), pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                if (sscanf(pdu->yaml_val,
                           "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                           &v1, &v2, &v3,
                           &b[0], &b[1], &b[2], &b[3],
                           &b[4], &b[5], &b[6], &b[7]) != 11) {
                        printf("Failed to parse UUID value for %s: %s\n",
                               yaml_name(name), pdu->yaml_val);
                        return -1;
                }
                uuid->v1 = v1;
                uuid->v2 = v2;
                uuid->v3 = v3;
                for (i = 0; i < 8; i++) {
                        uuid->v4[i] = b[i];
                }
                yaml_next_kv(pdu, iov);
                return 0;
        } else {
                if (yaml_print_key(ctx, pdu, iov, name)) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", uuid->v1, uuid->v2, uuid->v3, uuid->v4[0], uuid->v4[1], uuid->v4[2], uuid->v4[3], uuid->v4[4], uuid->v4[5], uuid->v4[6], uuid->v4[7])) {
                        return -1;
                }
                return 0;
        }
}

static int
yaml_struct_coder(char *name, struct dcerpc_context *ctx,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov,
                  void *ptr, dcerpc_coder coder)
{
        int ret;

        if (pdu->direction == DCERPC_DECODE) {
                yaml_next_kv(pdu, iov);
                if (strcmp(pdu->yaml_key,  name)) {
                        printf("Wrong YAML key encountered for struct. Expected %s but got %s\n",
                               name, pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                yaml_next_kv(pdu, iov);
                ret = coder(name, ctx, pdu, iov, ptr);
        } else {
                if (yaml_print_preamble(ctx, pdu, iov)) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "%s: %s\n", name, pdu->yaml_val)) {
                        return -1;
                }
                pdu->yaml_val = "";

                pdu->yaml_indentation++;
                ret = coder(name, ctx, pdu, iov, ptr);
                pdu->yaml_indentation--;
        }
        return ret;
}

static int
yaml_do_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
             struct dcerpc_iovec *iov, void *ptr,
             dcerpc_coder coder)
{
        if (pdu->direction == DCERPC_DECODE) {
                yaml_next_kv(pdu, iov);
                if (strcmp(pdu->yaml_key,  name)) {
                        printf("Wrong YAML key encountered for do. Expected %s but got %s\n",
                               name, pdu->yaml_key);
                        return -1;
                }
                return yaml_struct_coder(name,ctx, pdu, iov, ptr, coder);
        } else {
                pdu->yaml_val = dcerpc_get_request(pdu) ? "Response" : "Request";
                return yaml_struct_coder(name,ctx, pdu, iov, ptr, coder);
        }
}

static int
yaml_union_coder(char *name, struct dcerpc_context *ctx,
                 struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov,
                 uint32_t *switch_is, void *ptr, dcerpc_coder coder)
{
        int ret;

        if (pdu->direction == DCERPC_DECODE) {
                if (strcmp(pdu->yaml_key,  name)) {
                        printf("Wrong YAML key encountered for union. Expected %s but got %s\n",
                               name, pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                yaml_next_kv(pdu, iov);
                /*
                 * Level was already decoded into *switch_is; publish it so
                 * the case coder's dcerpc_get_switch_is() sees the right arm
                 * (NDR does this when it reads the discriminant from the wire).
                 */
                dcerpc_set_switch_is(pdu, *switch_is);
                name = pdu->yaml_key;
                ret = coder(name, ctx, pdu, iov, ptr);
        } else {
                if (yaml_print_preamble(ctx, pdu, iov)) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "%s:\n", name)) {
                        return -1;
                }
        
                pdu->yaml_indentation++;
                dcerpc_set_switch_is(pdu, *switch_is);
                ret = coder(name, ctx, pdu, iov, ptr);
                pdu->yaml_indentation--;
        }
        return ret;
}

static int
yaml_utf16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov,
                 void *ptr)
{
        if (pdu->direction == DCERPC_DECODE) {
                yaml_next_kv(pdu, iov);
                if (yaml_key_mismatch(pdu, name)) {
                        printf("Wrong YAML key encountered for ptr. Expected %s but got %s\n",
                               yaml_name(name), pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                *(char **)ptr = pdu->yaml_val;
                yaml_next_kv(pdu, iov);
                return 0;
        } else {
                const char *s = *(char **)ptr;

                if (yaml_print_key(ctx, pdu, iov, name)) {
                        return -1;
                }
                if (yaml_print_string(ctx, iov, s ? s : "", name == NULL)) {
                        return -1;
                }
                return 0;
        }
        return -1;
}

static int yaml_bytes_coder(char *name, struct dcerpc_context *ctx,
                            struct dcerpc_pdu *pdu,
                            struct dcerpc_iovec *iov, void *ptr);

static int
yaml_varying_bytes_coder(char *name, struct dcerpc_context *ctx,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov, void *ptr)
{
        return text_varying_bytes_coder(name, ctx, pdu, iov, ptr,
                                        yaml_bytes_coder);
}

/* Byte array as a hex string: "Name: 0a0b..." */
static int
yaml_bytes_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                 struct dcerpc_iovec *iov, void *ptr)
{
        struct dcerpc_bytes *b = ptr;

        if (pdu->direction == DCERPC_DECODE) {
                yaml_next_kv(pdu, iov);
                if (yaml_key_mismatch(pdu, name)) {
                        printf("Wrong YAML key encountered for bytes. Expected %s but got %s\n",
                               yaml_name(name), pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                if (dcerpc_text_parse_hex(pdu, name, pdu->yaml_val, b)) {
                        return -1;
                }
                yaml_next_kv(pdu, iov);
                return 0;
        } else {
                if (yaml_print_preamble(ctx, pdu, iov)) {
                        return -1;
                }
                if (name && dcerpc_text_printf(ctx, iov, "%s:%s", name,
                                               b->len && b->data ? " " : "")) {
                        return -1;
                }
                if (b->data &&
                    dcerpc_text_print_hex(ctx, iov, b->data, b->len)) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "\n")) {
                        return -1;
                }
                return 0;
        }
}

static int
yaml_carray_coder(char *name, struct dcerpc_context *ctx,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov,
                  uint32_t num, void *ptr, int elem_size, dcerpc_coder coder)
{
        uint32_t i;
        uint8_t *data = ptr;

        if (pdu->direction == DCERPC_DECODE) {
                yaml_next_kv(pdu, iov);
                if (strcmp(pdu->yaml_key, name)) {
                        printf("Wrong YAML key encountered for carray. Expected %s but got %s\n",
                               name, pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                yaml_next_kv(pdu, iov);
                for (i = 0; i < num; i++) {
                        if (coder(name, ctx, pdu, iov, &data[(size_t)i * elem_size])) {
                                return -1;
                        }
                }
                return 0;
        } else {
                if (yaml_print_preamble(ctx, pdu, iov)) {
                        return -1;
                }
                if (dcerpc_text_printf(ctx, iov, "%s:\n", name)) {
                        return -1;
                }

                pdu->yaml_indentation++;
                for (i = 0; i < num; i++) {
                        pdu->yaml_array_prefix = 1;
                        pdu->yaml_indentation++;
                        if (coder(name, ctx, pdu, iov, &data[(size_t)i * elem_size])) {
                                return -1;
                        }
                        pdu->yaml_indentation--;
                        pdu->yaml_array_prefix = 0;
                }
                pdu->yaml_indentation--;
        }
        return 0;
}

/*
 * Array of plain values as a YAML sequence:
 *   Names:
 *     - sahlberg
 *     - Administrator
 */
static int
yaml_scalar_carray_coder(char *name, struct dcerpc_context *ctx,
                         struct dcerpc_pdu *pdu,
                         struct dcerpc_iovec *iov,
                         uint32_t num, void *ptr, int elem_size,
                         dcerpc_coder coder)
{
        uint32_t i;
        uint8_t *data = ptr;

        if (pdu->direction == DCERPC_DECODE) {
                yaml_next_kv(pdu, iov);
                if (strcmp(pdu->yaml_key, name)) {
                        printf("Wrong YAML key encountered for carray. Expected %s but got %s\n",
                               name, pdu->yaml_key);
                        return -1;
                }
                pdu->yaml_key = NULL;
                yaml_next_kv(pdu, iov);
                for (i = 0; i < num; i++) {
                        if (coder(NULL, ctx, pdu, iov,
                                  &data[(size_t)i * elem_size])) {
                                return -1;
                        }
                }
                return 0;
        }
        if (yaml_print_preamble(ctx, pdu, iov)) {
                return -1;
        }
        if (dcerpc_text_printf(ctx, iov, "%s:\n", name)) {
                return -1;
        }
        pdu->yaml_indentation++;
        for (i = 0; i < num; i++) {
                pdu->yaml_array_prefix = 1;
                pdu->yaml_indentation++;
                if (coder(NULL, ctx, pdu, iov, &data[(size_t)i * elem_size])) {
                        return -1;
                }
                pdu->yaml_indentation--;
                pdu->yaml_array_prefix = 0;
        }
        pdu->yaml_indentation--;
        return 0;
}

static int
yaml_ptr_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
               struct dcerpc_iovec *iov, void *ptr,
               enum ptr_type type, dcerpc_coder coder)
{
        if (name == NULL) {
                /*
                 * Element of a list of bare values (scalar_carray_coder):
                 * the value itself; a NULL element cannot be shown.
                 */
                if (ptr == NULL) {
                        printf("NULL element in a list of values\n");
                        return -1;
                }
                return coder(name, dce, pdu, iov, ptr);
        }
        if (ptr == NULL) {
                return 0;
        }
        if (pdu->direction == DCERPC_DECODE) {
                yaml_next_kv(pdu, iov);
                if (strcmp(pdu->yaml_key, name)) {
                        /*
                         * UNIQUE and FULL pointers are optional in YAML:
                         * missing key means a NULL referent. REF pointers
                         * always present the referent; the nested coder
                         * validates keys (either a struct wrapper name or
                         * the first field).
                         */
                        if (type != PTR_REF) {
                                return 0;
                        }
                }
                return coder(name, dce, pdu, iov, ptr);
        } else {
                return coder(name, dce, pdu, iov, ptr);
        }
}

/*
 * RPC_UNICODE_STRING (plain and NUL-terminated): text encodings show only
 * the string; Length/MaximumLength are NDR-only.
 */
struct dcerpc_coders yaml_coders = {
        .uint8_coder     = yaml_uint8_coder,
        .uint16_coder    = yaml_uint16_coder,
        .uint16_coder_pp = yaml_uint16_coder_pp,
        .uint32_coder    = yaml_uint32_coder,
        .uint32_coder_pp = yaml_uint32_coder_pp,
        .uint64_coder    = yaml_uint64_coder,
        .uuid_coder      = yaml_uuid_coder,
        .sid_coder       = text_sid_coder,
        .utf16_coder     = yaml_utf16_coder,
        .utf16z_coder    = yaml_utf16_coder,
        .unicode_string_coder  = yaml_utf16_coder,
        .unicode_stringz_coder = yaml_utf16_coder,
        .struct_coder    = yaml_struct_coder,
        .do_coder        = yaml_do_coder,
        .union_coder     = yaml_union_coder,
        .carray_coder    = yaml_carray_coder,
        .scalar_carray_coder = yaml_scalar_carray_coder,
        .ptr_coder       = yaml_ptr_coder,
        .bytes_coder     = yaml_bytes_coder,
        .varying_bytes_coder = yaml_varying_bytes_coder,
};

