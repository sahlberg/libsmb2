/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Internal helpers shared between the libdcerpc sources.
 */
#ifndef _DCERPC_PRIVATE_H_
#define _DCERPC_PRIVATE_H_

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

/* A UTF-16LE string; val[] holds len code units in little-endian order */
struct dcerpc_utf16_buf {
        int len;
        uint16_t val[1];
};

/* NULL if utf8 is not valid UTF-8. Release with free(). */
struct dcerpc_utf16_buf *dcerpc_utf8_to_utf16(const char *utf8);
/* Unpaired surrogates become U+FFFD. Release with free(). */
char *dcerpc_utf16_to_utf8(const uint16_t *utf16, size_t len);

struct dcerpc_context;
struct dcerpc_iovec;
int dcerpc_set_uint8(struct dcerpc_context *ctx, struct dcerpc_iovec *iov, uint8_t value);

struct dcerpc_pdu;
uint32_t dcerpc_pdu_direction(struct dcerpc_pdu *pdu);
enum dcerpc_encoding dcerpc_pdu_encoding(struct dcerpc_pdu *pdu);
int dcerpc_pdu_is_conformance_run(struct dcerpc_pdu *pdu);
void dcerpc_pdu_raise_max_alignment(struct dcerpc_pdu *pdu, int alignment);
int dcerpc_get_cr(struct dcerpc_pdu *pdu);

int dcerpc_align_3264(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov);
/* A varying byte array field checked against size_is and length_is */
int dcerpc_varying_bytes_checked_coder(char *name, struct dcerpc_context *ctx,
                                       struct dcerpc_pdu *pdu,
                                       struct dcerpc_iovec *iov, void *ptr);
/* An array for a decoder, refused if count can not be in what is left */
void *dcerpc_alloc_array(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                         uint64_t count, size_t esize);

struct dcerpc_server_call;
void dcerpc_pdu_set_server_call(struct dcerpc_pdu *pdu,
                                struct dcerpc_server_call *call);

/* RPC_SID coder for all non-NDR encodings */
int text_sid_coder(char *name, struct dcerpc_context *dce,
                   struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, void *ptr);

/* YAML/JSON helpers */
char *dcerpc_pdu_yaml_key(struct dcerpc_pdu *pdu);
char *dcerpc_pdu_yaml_val(struct dcerpc_pdu *pdu);
void dcerpc_pdu_clear_yaml_key(struct dcerpc_pdu *pdu);
char *dcerpc_pdu_json_key(struct dcerpc_pdu *pdu);
int dcerpc_json_next_key(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov);
/* MS-DTYP packet-form data is always little-endian; calls nest. */
void dcerpc_pdu_packet_form_begin(struct dcerpc_pdu *pdu);
void dcerpc_pdu_packet_form_end(struct dcerpc_pdu *pdu);

#endif /* !_DCERPC_PRIVATE_H_ */
