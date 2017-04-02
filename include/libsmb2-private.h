/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _LIBSMB2_PRIVATE_H_
#define _LIBSMB2_PRIVATE_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

#define MAX_ERROR_SIZE 256

#define PAD_TO_32BIT(len) ((len + 0x03) & 0xfffffffc)

#define SMB2_SPL_SIZE 4
#define SMB2_HEADER_SIZE 64

#define SMB2_MAX_VECTORS 256

struct smb2_iovec {
        char *buf;
        size_t len;
        void (*free)(void *);
};

struct smb2_io_vectors {
        size_t num_done;
        int total_size;
        int niov;
        struct smb2_iovec iov[SMB2_MAX_VECTORS];
};

struct smb2_async {
        uint64_t async_id;
};

struct smb2_sync {
        uint32_t process_id;
        uint32_t tree_id;
};
        
struct smb2_header {
        uint8_t protocol_id[4];
        uint16_t struct_size;
        uint16_t credit_charge;
        uint32_t status;
        uint16_t command;
        uint16_t credit_request_response;
        uint32_t flags;
        uint32_t next_command;
        uint64_t message_id;
        union {
                struct smb2_async async;
                struct smb2_sync sync;
        };
        uint64_t session_id;
        uint8_t signature[16];
};

struct smb2_context {
        int fd;
        int is_connected;

        uint16_t security_mode;

        char *server;
        char *share;

        smb2_command_cb connect_cb;
        void *connect_data;

        int credits;
        
        char client_guid[16];
        
        uint32_t tree_id;
        uint64_t message_id;
        uint64_t session_id;

        /* For sending PDUs */
	struct smb2_pdu *outqueue;
	struct smb2_pdu *waitqueue;

        /* buffer to avoid having to malloc the headers */
        char header[SMB2_SPL_SIZE + SMB2_HEADER_SIZE];

        /* For receiving PDUs */
        struct smb2_io_vectors in;

        /* Pointer to the current PDU that we are receiving the reply for.
         * Only valid once the full smb2 header has been received.
         */
        struct smb2_pdu *pdu;

        uint32_t max_transact_size;
        uint32_t max_read_size;
        uint32_t max_write_size;
        uint16_t dialect;
        
        char error_string[MAX_ERROR_SIZE];
};

#define SMB2_MAX_PDU_SIZE 16*1024*1024

struct smb2_pdu {
        struct smb2_pdu *next;
        struct smb2_header header;

        struct smb2_pdu *next_compound;

        smb2_command_cb cb;
        void *cb_data;

        /* buffer to avoid having to malloc the headers */
        char hdr[SMB2_HEADER_SIZE];

        /* For sending/receiving
         * out contains at least two vectors:
         * [0]  64 bytes for the smb header
         * [1+] command and and extra parameters
         *
         * in contains at least one vector:
         * [0+] command and and extra parameters
         */
        struct smb2_io_vectors out;
        struct smb2_io_vectors in;
};

/* UCS2 is always in Little Endianness */
struct ucs2 {
        int len;
        uint16_t val[1];
};

/* Returns a string converted to UCS2 format. Use free() to release
 * the ucs2 string.
 */
struct ucs2 *utf8_to_ucs2(const char *utf8);
        
/* Returns a string converted to UTF8 format. Use free() to release
 * the utf8 string.
 */
char *ucs2_to_utf8(const uint16_t *str, int len);

/* Convert a win timestamp to a unix timeval */
void win_to_timeval(uint64_t smb2_time, struct smb2_timeval *tv);

/* Covnert unit timeval to a win timestamp */
uint64_t timeval_to_win(struct smb2_timeval *tv);

void smb2_set_error(struct smb2_context *smb2, const char *error_string,
                    ...) __attribute__((format(printf, 2, 3)));

struct smb2_iovec *smb2_add_iovector(struct smb2_context *smb2,
                                     struct smb2_io_vectors *v,
                                     char *buf, int len, void (*free)(void *));

int smb2_pad_to_64bit(struct smb2_context *smb2, struct smb2_io_vectors *v);

struct smb2_pdu *smb2_allocate_pdu(struct smb2_context *smb2,
                                   enum smb2_command command,
                                   smb2_command_cb cb, void *cb_data);
void smb2_add_compound_pdu(struct smb2_context *smb2,
                           struct smb2_pdu *pdu, struct smb2_pdu *next_pdu);
void smb2_free_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu);

int smb2_queue_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu);
int smb2_process_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu);
        
struct smb2_pdu *smb2_find_pdu(struct smb2_context *smb2, uint64_t message_id);
void smb2_free_iovector(struct smb2_context *smb2, struct smb2_io_vectors *v);

int smb2_encode_header(struct smb2_context *smb2, struct smb2_iovec *iov,
                       struct smb2_header *hdr);
int smb2_decode_header(struct smb2_context *smb2, struct smb2_iovec *iov,
                       struct smb2_header *hdr);
        
int smb2_set_uint8(struct smb2_iovec *iov, int offset, uint8_t value);
int smb2_set_uint16(struct smb2_iovec *iov, int offset, uint16_t value);
int smb2_set_uint32(struct smb2_iovec *iov, int offset, uint32_t value);
int smb2_set_uint64(struct smb2_iovec *iov, int offset, uint64_t value);

int smb2_get_uint8(struct smb2_iovec *iov, int offset, uint8_t *value);
int smb2_get_uint16(struct smb2_iovec *iov, int offset, uint16_t *value);
int smb2_get_uint32(struct smb2_iovec *iov, int offset, uint32_t *value);
int smb2_get_uint64(struct smb2_iovec *iov, int offset, uint64_t *value);

int smb2_process_close_reply(struct smb2_context *smb2,
                             struct smb2_pdu *pdu);
int smb2_process_create_reply(struct smb2_context *smb2,
                              struct smb2_pdu *pdu);
int smb2_process_echo_reply(struct smb2_context *smb2,
                            struct smb2_pdu *pdu);
int smb2_process_logoff_reply(struct smb2_context *smb2,
                              struct smb2_pdu *pdu);
int smb2_process_negotiate_reply(struct smb2_context *smb2,
                                 struct smb2_pdu *pdu);
int smb2_process_query_directory_reply(struct smb2_context *smb2,
                                       struct smb2_pdu *pdu);
int smb2_process_query_info_reply(struct smb2_context *smb2,
                                  struct smb2_pdu *pdu);
int smb2_process_read_reply(struct smb2_context *smb2,
                            struct smb2_pdu *pdu);
int smb2_process_session_setup_reply(struct smb2_context *smb2,
                                     struct smb2_pdu *pdu);
int smb2_process_tree_connect_reply(struct smb2_context *smb2,
                                    struct smb2_pdu *pdu);
int smb2_process_tree_disconnect_reply(struct smb2_context *smb2,
                                       struct smb2_pdu *pdu);
int smb2_process_write_reply(struct smb2_context *smb2,
                             struct smb2_pdu *pdu);

int smb2_decode_fileidfulldirectoryinformation(
        struct smb2_context *smb2,
        struct smb2_fileidfulldirectoryinformation *fs,
        struct smb2_iovec *vec);

int smb2_decode_file_basic_information(
        struct smb2_context *smb2,
        struct smb2_file_basic_information *fs,
        struct smb2_iovec *vec);
int smb2_decode_file_standard_information(
        struct smb2_context *smb2,
        struct smb2_file_standard_information *fs,
        struct smb2_iovec *vec);
int smb2_decode_file_all_information(
        struct smb2_context *smb2,
        struct smb2_file_all_information *fs,
        struct smb2_iovec *vec);


#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_PRIVATE_H_ */
