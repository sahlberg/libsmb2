/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2018 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _DCERPC_H_
#define _DCERPC_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Data representation */
/* Integer */
#define DCERPC_DR_BIG_ENDIAN                    0x00
#define DCERPC_DR_LITTLE_ENDIAN                 0x10
/* Character */
#define DCERPC_DR_ASCII                         0x00
#define DCERPC_DR_EBCDIC                        0x01

struct dcerpc_context;
struct dcerpc_pdu;

/* Opaque; full definition in smb2/libsmb2.h. */
struct smb2_context;

/*
 * Buffer descriptor for NDR/YAML/JSON encode/decode.
 * Layout is identical to libsmb2's struct smb2_iovec (stable public ABI)
 * so the same buffer can be cast either way; dcerpc owns this type so
 * consumers do not need to include or redefine smb2_iovec.
 */
struct dcerpc_iovec {
        uint8_t *buf;
        size_t len;
        void (*free)(void *);
};

/* Encoder/Decoder for a DCERPC object */
typedef int (*dcerpc_coder)(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                            struct dcerpc_iovec *iov, int *offset,
                            void *ptr);

struct dcerpc_uint32_pretty_printer_bitfield {
        char *name;
        uint32_t mask;
        uint32_t value;
};

struct dcerpc_uint32_pretty_printer {
        char *fmt;
        struct dcerpc_uint32_pretty_printer_bitfield bitfields[];
};

/* Encoder/Decoder for a DCERPC object with a pretty-printer*/
typedef int (*dcerpc_coder_pp)(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr,
                               struct dcerpc_uint32_pretty_printer *pp);

/* Encoder/Decoder for a DCERPC object with a pass-through coder*/
typedef int (*dcerpc_coder_cdr)(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct dcerpc_iovec *iov, int *offset,
                                void *ptr,
                                dcerpc_coder coder);

/* Encoder/Decoder for a DCERPC union with a discriminator */
typedef int (*dcerpc_coder_union)(char *name, struct dcerpc_context *dce,
                                  struct dcerpc_pdu *pdu,
                                  struct dcerpc_iovec *iov, int *offset,
                                  uint32_t *switch_is, void *ptr,
                                  dcerpc_coder coder);

enum dcerpc_encoding {
        ENCODING_NDR    = 0,
        ENCODING_YAML   = 1,
        ENCODING_JSON   = 2
};

enum ptr_type {
        PTR_REF    = 0,
        PTR_UNIQUE = 1,
        PTR_FULL   = 2
};

typedef struct dcerpc_uuid {
        uint32_t v1;
        uint16_t v2;
        uint16_t v3;
        uint8_t v4[8];
} dcerpc_uuid_t;

typedef struct p_syntax_id {
        dcerpc_uuid_t uuid;
        uint16_t vers;
        uint16_t vers_minor;
} p_syntax_id_t;

struct ndr_transfer_syntax {
        dcerpc_uuid_t uuid;
        uint16_t vers;
};

struct dcerpc_context_handle {
        uint32_t context_handle_attributes;
        dcerpc_uuid_t context_handle_uuid;
};

struct dcerpc_utf16 {
        uint32_t max_count;       /* internal use only */
        uint32_t offset;          /* internal use only */
        uint32_t actual_count;    /* internal use only */

        struct smb2_utf16 *utf16; /* internal use only */
        
        const char *utf8;
};

extern p_syntax_id_t lsa_interface;
extern p_syntax_id_t srvsvc_interface;
extern p_syntax_id_t wkssvc_interface;
extern p_syntax_id_t winreg_interface;
extern p_syntax_id_t epm_interface;
        
typedef void (*dcerpc_cb)(struct dcerpc_context *dce, int status,
                          void *command_data, void *cb_data);

struct dcerpc_procedure {
        int opnum;
        char *name;
        dcerpc_coder req_coder;
        int req_size;
        dcerpc_coder rep_coder;
        int rep_size;
};

/*
 * Server-side implementation callback for a decoded request.
 * req/rep are the allocated request and response structures.
 * pdu may be used with dcerpc_alloc_data() for nested allocations.
 * Return 0 if rep is populated; non-zero on failure.
 */
typedef int (*dcerpc_stub_fn)(struct dcerpc_context *dce,
                              struct dcerpc_pdu *pdu,
                              void *req,
                              void *rep);

struct dcerpc_stub {
        int opnum;
        char *name;
        dcerpc_stub_fn fn;
};

struct dcerpc_service {
        struct dcerpc_service *next;
        const char *name;
        p_syntax_id_t *interface;
        struct dcerpc_procedure *procs;
};
        
extern struct dcerpc_service *dcerpc_services;

/*
 * Register a service so it can be looked up by name in dcerpc_services.
 * Returns 0 on success, -EEXIST if name is already registered or
 * -ENOMEM.
 */
int dcerpc_register_coder(const char *name,
                          p_syntax_id_t *interface,
                          struct dcerpc_procedure *procs);

/*
 * Create a DCE/RPC context on an existing smb2 context.
 * The caller retains ownership of smb2; dcerpc_destroy_context() will not
 * free it. Use this when you need fine-grained smb2 configuration before
 * connecting IPC$ / opening a pipe.
 */
struct dcerpc_context *dcerpc_create_context(struct smb2_context *smb2);
/*
 * Convenience: create smb2 from an SMB URL, apply user/domain and query
 * args from the URL, connect IPC$, and return a dcerpc context that owns
 * the smb2 lifecycle. dcerpc_destroy_context() will disconnect IPC$ and
 * free the smb2 context.
 *
 * URL format: smb://[[domain;]user@]server[:port]/[share[/path]][?args]
 * Query args (via smb2_parse_url): sign, seal, sec=ntlmssp|krb5, etc.
 * Signing is not forced; pass ?sign when desired.
 * Tree connect always uses IPC$ (named-pipe transport); share in the URL
 * is ignored for connect. Still call dcerpc_connect_context() for the pipe.
 *
 * Returns NULL on failure.
 */
struct dcerpc_context *dcerpc_create_context_smb(const char *smb_url);
void dcerpc_free_data(struct dcerpc_context *dce, void *data);
const char *dcerpc_get_error(struct dcerpc_context *dce);
int dcerpc_connect_context_async(struct dcerpc_context *dce,
                                 const char *path, p_syntax_id_t *syntax,
                                 dcerpc_cb cb, void *cb_data);
/*
 * Synchronous open+bind of a DCE/RPC named pipe (wraps
 * dcerpc_connect_context_async + event wait).
 *
 * Returns 0 on success. On failure returns non-zero; check
 * dcerpc_get_error() / smb2_get_error().
 */
int dcerpc_connect_context(struct dcerpc_context *dce,
                           const char *path, p_syntax_id_t *syntax);
/*
 * Free a dcerpc context. Always closes an open named pipe (best-effort).
 * If the context was created with dcerpc_create_context_smb(), also
 * disconnects IPC$ and destroys the owned smb2 context. If created with
 * dcerpc_create_context(), the caller's smb2 is left intact.
 */
void dcerpc_destroy_context(struct dcerpc_context *dce);

struct smb2_context *dcerpc_get_smb2_context(struct dcerpc_context *dce);
void *dcerpc_get_pdu_payload(struct dcerpc_pdu *pdu);

int dcerpc_open_async(struct dcerpc_context *dce, dcerpc_cb cb, void *cb_data);
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
int dcerpc_call_async(struct dcerpc_context *dce,
                      int opnum,
                      dcerpc_coder req_coder, void *req,
                      dcerpc_coder rep_coder, int decode_size,
                      dcerpc_cb cb, void *cb_data);

/*
 * Synchronous DCE/RPC request (wraps dcerpc_call_async + event wait).
 *
 * Returns the decoded reply root on success (same ownership as the async
 * callback's command_data). Free with dcerpc_free_data(dce, rep).
 * Returns NULL on failure; check dcerpc_get_error() / smb2_get_error().
 */
void *dcerpc_call(struct dcerpc_context *dce,
                  int opnum,
                  dcerpc_coder req_coder, void *req,
                  dcerpc_coder rep_coder, int decode_size);

int dcerpc_do_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov,
                    int *offset, void *ptr,
                    dcerpc_coder coder);
/*
 * Read a YAML file and decode it with coder into a newly allocated structure
 * of decode_size bytes.
 *
 * Creates a temporary smb2/dcerpc context internally; the caller does not
 * pass or manage a dcerpc_context. The returned pointer is a dcerpc mem-tree
 * root (same model as a successful dcerpc_call_async reply). Nested decode
 * allocations and the file buffer (loaded via dcerpc_alloc_data so YAML
 * string pointers into the buffer stay valid) are owned by that root. Free
 * with dcerpc_free_data(NULL, ptr) — the dce argument is unused.
 *
 * Returns NULL on error.
 * The top-level YAML key is taken from the file and must match what coder
 * expects (e.g. "CONFIG", "PASSWD", "NetrShareEnum").
 */
void *dcerpc_read_yaml_file(const char *filename,
                            dcerpc_coder coder,
                            int decode_size);
#define DCERPC_DECODE 0
#define DCERPC_ENCODE 1
struct dcerpc_pdu *dcerpc_allocate_pdu(struct dcerpc_context *dce,
                                       enum dcerpc_encoding encoding,
                                       int direction, int payload_size);
void dcerpc_free_pdu(struct dcerpc_context *dce, struct dcerpc_pdu *pdu);

/*
 * Allocate size bytes associated with pdu. Freed automatically when the
 * PDU is destroyed (dcerpc_free_pdu), or with dcerpc_free_data() if the
 * primary payload was transferred out of the PDU (e.g. call reply root).
 */
void *dcerpc_alloc_data(struct dcerpc_pdu *pdu, size_t size);

void dcerpc_set_size_is(struct dcerpc_pdu *pdu, uint32_t size_is);
uint32_t dcerpc_get_size_is(struct dcerpc_pdu *pdu);
void dcerpc_set_switch_is(struct dcerpc_pdu *pdu, int switch_is);
int dcerpc_get_switch_is(struct dcerpc_pdu *pdu);
/*
 * Override MaximumLength (bytes) for the next RPC_UNICODE_STRING /
 * RPC_UNICODE_STRINGz encode. 0 means derive MaximumLength from content.
 * Used when the client must advertise a receive buffer larger than the
 * current string (e.g. MS-RRP BaseRegEnumKey lpNameIn). No-ops unless
 * the PDU is NDR encode. Cleared after the matching Buffer array is
 * encoded. Should be even (UTF-16 byte count).
 */
void dcerpc_set_unicode_max_length(struct dcerpc_pdu *pdu, uint16_t max_length);
uint16_t dcerpc_get_unicode_max_length(struct dcerpc_pdu *pdu);
void dcerpc_set_request(struct dcerpc_pdu *pdu, void *request);
void *dcerpc_get_request(struct dcerpc_pdu *pdu);

int ndr_ptr_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, int *offset, void *ptr,
                  enum ptr_type type, dcerpc_coder coder);
int ndr_carray_coder(char *name, struct dcerpc_context *ctx,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     uint32_t num, void *ptr, int elem_size, dcerpc_coder coder);
int ndr_uint8_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, int *offset, void *ptr);
int ndr_uint16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset, void *ptr);
int ndr_uint32_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset, void *ptr);
int ndr_uint3264_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                       struct dcerpc_iovec *iov, int *offset, void *ptr);
int ndr_union_coder(char *name, struct dcerpc_context *ctx,
                    struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, int *offset,
                    uint32_t *switch_is, void *ptr, dcerpc_coder coder);
int ndr_utf16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                    struct dcerpc_iovec *iov, int *offset, void *ptr);
int ndr_utf16z_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset, void *ptr);
int ndr_uuid_coder(char *name, struct dcerpc_context *dce,
                   struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, int *offset,
                   void *ptr);
int ndr_sid_coder(char *name, struct dcerpc_context *dce,
                  struct dcerpc_pdu *pdu,
                  struct dcerpc_iovec *iov, int *offset,
                  void *ptr);

int dcerpc_ptr_coder(char *name, struct dcerpc_context *dce, struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset, void *ptr,
                     enum ptr_type type, dcerpc_coder coder);
int dcerpc_uint8_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                       struct dcerpc_iovec *iov, int *offset, void *ptr);
int dcerpc_uint16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset, void *ptr);
int dcerpc_uint16_coder_pp(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov, int *offset, void *ptr,
                           struct dcerpc_uint32_pretty_printer *pp);
int dcerpc_uint32_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset, void *ptr);
int dcerpc_uint32_coder_pp(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                           struct dcerpc_iovec *iov, int *offset, void *ptr,
                           struct dcerpc_uint32_pretty_printer *pp);
int dcerpc_uint64_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset, void *ptr);
int dcerpc_utf16_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                       struct dcerpc_iovec *iov, int *offset, void *ptr);
int dcerpc_utf16z_coder(char *name, struct dcerpc_context *ctx, struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset, void *ptr);
int dcerpc_carray_coder(char *name, struct dcerpc_context *ctx,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        uint32_t num, void *ptr, int elem_size, dcerpc_coder coder);
/*
 * Like dcerpc_carray_coder() for an array of plain values (integers,
 * strings, SIDs, ...): NDR is identical; YAML/JSON show a list of bare
 * values. The element coder is called with a NULL name.
 */
int dcerpc_scalar_carray_coder(char *name, struct dcerpc_context *ctx,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        uint32_t num, void *ptr, int elem_size, dcerpc_coder coder);
int dcerpc_union_coder(char *name, struct dcerpc_context *ctx,
                       struct dcerpc_pdu *pdu,
                       struct dcerpc_iovec *iov, int *offset,
                       uint32_t *switch_is, void *ptr, dcerpc_coder coder);
int dcerpc_struct_coder(char *name, struct dcerpc_context *ctx,
                        struct dcerpc_pdu *pdu,
                        struct dcerpc_iovec *iov, int *offset,
                        void *ptr, dcerpc_coder coder);
int dcerpc_context_handle_coder(char *name, struct dcerpc_context *dce,
                                struct dcerpc_pdu *pdu,
                                struct dcerpc_iovec *iov, int *offset,
                                void *ptr);
int dcerpc_uuid_coder(char *name, struct dcerpc_context *ctx,
                      struct dcerpc_pdu *pdu,
                      struct dcerpc_iovec *iov, int *offset, void *ptr);
int dcerpc_sid_coder(char *name, struct dcerpc_context *dce,
                     struct dcerpc_pdu *pdu,
                     struct dcerpc_iovec *iov, int *offset,
                     void *ptr);

/*
 * [size_is(len)] byte data[] — a conformant byte array.
 * NDR: max_count followed by the bytes. YAML/JSON: a hex string.
 * On decode data is allocated from the pdu (dcerpc_alloc_data).
 * ptr is struct dcerpc_bytes *.
 */
#define DCERPC_BYTES_MAX 0x4000000
struct dcerpc_bytes {
        uint32_t len;
        uint8_t *data;
};
int dcerpc_bytes_coder(char *name, struct dcerpc_context *dce,
                       struct dcerpc_pdu *pdu,
                       struct dcerpc_iovec *iov, int *offset,
                       void *ptr);

/*
 * Blob: a [size_is(len)] unique byte array whose bytes are a packet-form
 * object (e.g. a self-relative SECURITY_DESCRIPTOR coded by
 * dcerpc_SECURITY_DESCRIPTOR_coder). The C struct holds the decoded object
 * pointer instead of the bytes; idlcomp emits these for [blob(T)] fields.
 *
 * dcerpc_blob_len_coder codes the length field: computed from obj on NDR
 * encode, omitted in YAML/JSON. dcerpc_blob_coder codes the byte array:
 * objp is the address of the object pointer field. In YAML/JSON the object
 * is shown directly and a NULL object is an absent key. Full libdcerpc only.
 */
int dcerpc_blob_len_coder(char *name, struct dcerpc_context *dce,
                          struct dcerpc_pdu *pdu,
                          struct dcerpc_iovec *iov, int *offset,
                          uint32_t *len, void *obj, dcerpc_coder coder);
int dcerpc_blob_coder(char *name, struct dcerpc_context *dce,
                      struct dcerpc_pdu *pdu,
                      struct dcerpc_iovec *iov, int *offset,
                      uint32_t len, void *objp, size_t obj_size,
                      dcerpc_coder coder);

/*
 * [size_is(max_count), length_is(len)] byte data[] — a conformant-varying
 * byte array. NDR: max_count, offset (always 0), len, then len bytes.
 * YAML/JSON: the len bytes as a hex string; max_count is not carried and
 * is set to len on decode.
 * On decode data is allocated from the pdu (dcerpc_alloc_data).
 * ptr is struct dcerpc_varying_bytes *.
 */
struct dcerpc_varying_bytes {
        uint32_t max_count;
        uint32_t len;
        uint8_t *data;
};
int dcerpc_varying_bytes_coder(char *name, struct dcerpc_context *dce,
                               struct dcerpc_pdu *pdu,
                               struct dcerpc_iovec *iov, int *offset,
                               void *ptr);
/*
 * RPC_UNICODE_STRING (MS-DTYP). Buffer is not required to be NUL-terminated.
 * ptr is char ** (UTF-8).
 *
 * RPC_UNICODE_STRINGz is the same layout with a NUL-terminated Buffer —
 * this is RRP_UNICODE_STRING in MS-RRP. Same nult pattern as
 * ndr_utf16_coder / ndr_utf16z_coder.
 *
 * To advertise a MaximumLength larger than the current content (e.g. MS-RRP
 * EnumKey / EnumValue / QueryInfoKey buffer parameters), call
 * dcerpc_set_unicode_max_length() immediately before encoding the string.
 */
int dcerpc_RPC_UNICODE_STRING_coder(char *name, struct dcerpc_context *dce,
                                    struct dcerpc_pdu *pdu,
                                    struct dcerpc_iovec *iov, int *offset,
                                    void *ptr);
int dcerpc_RPC_UNICODE_STRINGz_coder(char *name, struct dcerpc_context *dce,
                                     struct dcerpc_pdu *pdu,
                                     struct dcerpc_iovec *iov, int *offset,
                                     void *ptr);
/* MS-RRP name for the NUL-terminated form */
#define dcerpc_RRP_UNICODE_STRING_coder dcerpc_RPC_UNICODE_STRINGz_coder

#ifdef __cplusplus
}
#endif

#endif /* !_DCERPC_H_ */
