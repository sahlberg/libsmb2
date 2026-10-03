/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Internal helpers shared between the libdcerpc sources.
 */
#ifndef _DCERPC_PRIVATE_H_
#define _DCERPC_PRIVATE_H_

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

struct dcerpc_context;
struct dcerpc_iovec;
int dcerpc_set_uint8(struct dcerpc_context *ctx, struct dcerpc_iovec *iov,
                     int *offset, uint8_t value);

struct dcerpc_pdu;
int dcerpc_pdu_direction(struct dcerpc_pdu *pdu);
enum dcerpc_encoding dcerpc_pdu_encoding(struct dcerpc_pdu *pdu);
int dcerpc_pdu_is_conformance_run(struct dcerpc_pdu *pdu);
void dcerpc_pdu_raise_max_alignment(struct dcerpc_pdu *pdu, int alignment);
int dcerpc_get_cr(struct dcerpc_pdu *pdu);

int dcerpc_align_3264(struct dcerpc_context *ctx, int offset);

/* RPC_SID coder for all non-NDR encodings */
int text_sid_coder(char *name, struct dcerpc_context *dce,
                   struct dcerpc_pdu *pdu,
                   struct dcerpc_iovec *iov, int *offset, void *ptr);

/* YAML/JSON helpers */
char *dcerpc_pdu_yaml_key(struct dcerpc_pdu *pdu);
char *dcerpc_pdu_yaml_val(struct dcerpc_pdu *pdu);
void dcerpc_pdu_clear_yaml_key(struct dcerpc_pdu *pdu);
char *dcerpc_pdu_json_key(struct dcerpc_pdu *pdu);
int dcerpc_json_next_key(struct dcerpc_pdu *pdu, struct dcerpc_iovec *iov,
                         int *offset);
/* MS-DTYP packet-form data is always little-endian; calls nest. */
void dcerpc_pdu_packet_form_begin(struct dcerpc_pdu *pdu);
void dcerpc_pdu_packet_form_end(struct dcerpc_pdu *pdu);

#endif /* !_DCERPC_PRIVATE_H_ */
