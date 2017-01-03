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

#define MAX_ERROR_SIZE 256

#define PAD_TO_32BIT(len) ((len + 0x03) & 0xfffffffc)

#define SMB2_SPL_SIZE 4
#define SMB2_HEADER_SIZE 64

#define SMB2_MAX_VECTORS 4

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
        
        char error_string[MAX_ERROR_SIZE];
};

#define SMB2_MAX_PDU_SIZE 16*1024*1024

struct smb2_pdu {
        struct smb2_pdu *next;
        struct smb2_header header;

        smb2_command_cb cb;
        void *cb_data;

        /* buffer to avoid having to malloc the headers */
        char hdr[SMB2_SPL_SIZE + SMB2_HEADER_SIZE];

        /* For sending/receiving
         * out contains at least three vectors:
         * [0]  4 bytes for the stream protocol length
         * [1]  64 bytes for the smb header
         * [2+] command and and extra parameters
         *
         * in contains at least one vectos:
         * [0+] command and and extra parameters
         */
        struct smb2_io_vectors out;
        struct smb2_io_vectors in;
};

void smb2_set_error(struct smb2_context *smb2, const char *error_string,
                    ...) __attribute__((format(printf, 2, 3)));

struct smb2_pdu *smb2_allocate_pdu(struct smb2_context *smb2,
                                   enum smb2_command command,
                                   smb2_command_cb cb, void *cb_data);
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

int smb2_process_echo_reply(struct smb2_context *smb2,
                            struct smb2_pdu *pdu);
int smb2_process_logoff_reply(struct smb2_context *smb2,
                              struct smb2_pdu *pdu);
int smb2_process_negotiate_reply(struct smb2_context *smb2,
                                 struct smb2_pdu *pdu);
int smb2_process_session_setup_reply(struct smb2_context *smb2,
                                     struct smb2_pdu *pdu);
        
#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_PRIVATE_H_ */
