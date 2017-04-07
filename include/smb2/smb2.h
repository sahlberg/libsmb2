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

#ifndef _SMB2_H_
#define _SMB2_H_

#include <smb2-errors.h>

#ifdef __cplusplus
extern "C" {
#endif

struct smb2_timeval {
        uint32_t tv_sec;
        uint32_t tv_usec;
};

#define SMB2_FLAGS_SERVER_TO_REDIR    0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND      0x00000002
#define SMB2_FLAGS_RELATED_OPERATIONS 0x00000004
#define SMB2_FLAGS_SIGNED             0x00000008
#define SMB2_FLAGS_PRIORITY_MASK      0x00000070
#define SMB2_FLAGS_DFS_OPERATIONS     0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION   0x20000000
        
enum smb2_command {
        SMB2_NEGOTIATE       = 0,
        SMB2_SESSION_SETUP,
        SMB2_LOGOFF,
        SMB2_TREE_CONNECT,
        SMB2_TREE_DISCONNECT,
        SMB2_CREATE,
        SMB2_CLOSE,
        /* SMB2_FLUSH, */
        SMB2_READ            = 8,
        SMB2_WRITE,
        /* SMB2_LOCK, */
        /* SMB2_IOCTL, */
        /* SMB2_CANCEL, */
        SMB2_ECHO            = 13,
        SMB2_QUERY_DIRECTORY,
        /* SMB2_CHANGE_NOTIFY, */
        SMB2_QUERY_INFO      = 16,
        /* SMB2_SET_INFO, */
        /* SMB2_OPLOCK_BREAK, */
};

/*
 * SMB2 NEGOTIATE
 */
#define SMB2_NEGOTIATE_SIGNING_ENABLED  0x0001
#define SMB2_NEGOTIATE_SIGNING_REQUIRED 0x0002

#define SMB2_VERSION_0202     0x0202
#define SMB2_VERSION_0210     0x0210
#define SMB2_VERSION_0300     0x0300
#define SMB2_VERSION_0302     0x0302

#define SMB2_GLOBAL_CAP_DFS                0x00000001
#define SMB2_GLOBAL_CAP_LEASING            0x00000002
#define SMB2_GLOBAL_CAP_LARGE_MTU          0x00000004
#define SMB2_GLOBAL_CAP_MULTI_CHANNEL      0x00000008
#define SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010
#define SMB2_GLOBAL_CAP_DIRECTORY_LEASING  0x00000020
#define SMB2_GLOBAL_CAP_ENCRYPTION         0x00000040
        
#define SMB2_NEGOTIATE_MAX_DIALECTS 10

#define SMB2_NEGOTIATE_REQUEST_SIZE 36
        
struct smb2_negotiate_request {
        uint16_t dialect_count;
        uint16_t security_mode;
        uint32_t capabilities;
        unsigned char client_guid[16];
        uint64_t client_start_time;
        uint16_t dialects[SMB2_NEGOTIATE_MAX_DIALECTS];
};

#define SMB2_NEGOTIATE_REPLY_SIZE 65

struct smb2_negotiate_reply {
        uint16_t security_mode;
        uint16_t dialect_revision;
        unsigned char server_guid[16];
        uint32_t capabilities;
        uint32_t max_transact_size;
        uint32_t max_read_size;
        uint32_t max_write_size;
        uint64_t system_time;
        uint64_t server_start_time;
        uint16_t security_buffer_length;
        uint16_t security_buffer_offset;
        char *security_buffer;
};

/* session setup flags */
#define SMB2_SESSION_FLAG_BINDING 0x01

/* session setup capabilities */
#define SMB2_GLOBAL_CAP_DFS     0x00000001
#define SMB2_GLOBAL_CAP_UNUSED1 0x00000002
#define SMB2_GLOBAL_CAP_UNUSED2 0x00000004
#define SMB2_GLOBAL_CAP_UNUSED4 0x00000008

#define SMB2_SESSION_SETUP_REQUEST_SIZE 25

struct smb2_session_setup_request {
        uint8_t flags;
        uint8_t security_mode;
        uint32_t capabilities;
        uint32_t channel;
        uint64_t previous_session_id;
        uint16_t security_buffer_length;
        char *security_buffer;
};

#define SMB2_SESSION_FLAG_IS_GUEST        0x0001
#define SMB2_SESSION_FLAG_IS_NULL         0x0002
#define SMB2_SESSION_FLAG_IS_ENCRYPT_DATA 0x0004

#define SMB2_SESSION_SETUP_REPLY_SIZE 9

struct smb2_session_setup_reply {
        uint16_t session_flags;
        uint16_t security_buffer_length;
        uint16_t security_buffer_offset;
        char *security_buffer;
};

#define SMB2_TREE_CONNECT_REQUEST_SIZE 9
        
#define SMB2_SHAREFLAG_CLUSTER_RECONNECT 0x0001

struct smb2_tree_connect_request {
        uint16_t flags;
        uint16_t path_length;
        uint16_t *path;
};

#define SMB2_SHARE_TYPE_DISK  0x01
#define SMB2_SHARE_TYPE_PIPE  0x02
#define SMB2_SHARE_TYPE_PRINT 0x03

#define SMB2_SHAREFLAG_MANUAL_CACHING              0x00000000
#define SMB2_SHAREFLAG_DFS                         0x00000001
#define SMB2_SHAREFLAG_DFS_ROOT                    0x00000002
#define SMB2_SHAREFLAG_AUTO_CACHING                0x00000010
#define SMB2_SHAREFLAG_VDO_CACHING                 0x00000020
#define SMB2_SHAREFLAG_NO_CACHING                  0x00000030
#define SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS    0x00000100
#define SMB2_SHAREFLAG_FORCE_SHARED_DELETE         0x00000200
#define SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING     0x00000400  
#define SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM 0x00000800
#define SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK        0x00001000
#define SMB2_SHAREFLAG_ENABLE_HASH_V1              0x00002000
#define SMB2_SHAREFLAG_ENABLE_HASH_V2              0x00004000
#define SMB2_SHAREFLAG_ENCRYPT_DATA                0x00008000

#define SMB2_SHARE_CAP_DFS                         0x00000008
#define SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY     0x00000010
#define SMB2_SHARE_CAP_SCALEOUT                    0x00000020
#define SMB2_SHARE_CAP_CLUSTER                     0x00000040
#define SMB2_SHARE_CAP_ASYMMETRIC                  0x00000080

#define SMB2_TREE_CONNECT_REPLY_SIZE 16

struct smb2_tree_connect_reply {
        uint8_t share_type;
        uint32_t share_flags;
        uint32_t capabilities;
        uint32_t maximal_access;
};

#define SMB2_CREATE_REQUEST_SIZE 57

#define SMB2_OPLOCK_LEVEL_NONE      0x00
#define SMB2_OPLOCK_LEVEL_II        0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE 0x08
#define SMB2_OPLOCK_LEVEL_BATCH     0x09
#define SMB2_OPLOCK_LEVEL_LEASE     0xff

#define SMB2_IMPERSONATION_ANONYMOUS      0x00000000
#define SMB2_IMPERSONATION_IDENTIFICATION 0x00000001
#define SMB2_IMPERSONATION_IMPERSONATION  0x00000002
#define SMB2_IMPERSONATION_DELEGATE       0x00000003

/* Access mask common to all objects */
#define SMB2_FILE_READ_EA           0x00000008
#define SMB2_FILE_WRITE_EA          0x00000010
#define SMB2_FILE_DELETE_CHILD      0x00000040
#define SMB2_FILE_READ_ATTRIBUTES   0x00000080
#define SMB2_FILE_WRITE_ATTRIBUTES  0x00000100
#define SMB2_DELETE                 0x00010000
#define SMB2_READ_CONTROL           0x00020000
#define SMB2_WRITE_DAC              0x00040000
#define SMB2_WRITE_OWNER            0x00080000
#define SMB2_SYNCHRONIZE            0x00100000
#define SMB2_ACCESS_SYSTEM_SECURITY 0x01000000
#define SMB2_MAXIMUM_ALLOWED        0x02000000
#define SMB2_GENERIC_ALL            0x10000000
#define SMB2_GENERIC_EXECUTE        0x20000000
#define SMB2_GENERIC_WRITE          0x40000000
#define SMB2_GENERIC_READ           0x80000000
        
/* Access mask unique for file/pipe/printer */
#define SMB2_FILE_READ_DATA         0x00000001
#define SMB2_FILE_WRITE_DATA        0x00000002
#define SMB2_FILE_APPEND_DATA       0x00000004
#define SMB2_FILE_EXECUTE           0x00000020

/* Access mask unique for directories */
#define SMB2_FILE_LIST_DIRECTORY    0x00000001
#define SMB2_FILE_ADD_FILE          0x00000002
#define SMB2_FILE_ADD_SUBDIRECTORY  0x00000004
#define SMB2_FILE_TRAVERSE          0x00000020

/* File attributes */        
#define SMB2_FILE_ATTRIBUTE_READONLY            0x00000001
#define SMB2_FILE_ATTRIBUTE_HIDDEN              0x00000002
#define SMB2_FILE_ATTRIBUTE_SYSTEM              0x00000004
#define SMB2_FILE_ATTRIBUTE_DIRECTORY           0x00000010
#define SMB2_FILE_ATTRIBUTE_ARCHIVE             0x00000020
#define SMB2_FILE_ATTRIBUTE_NORMAL              0x00000080
#define SMB2_FILE_ATTRIBUTE_TEMPORARY           0x00000100
#define SMB2_FILE_ATTRIBUTE_SPARSE_FILE         0x00000200
#define SMB2_FILE_ATTRIBUTE_REPARSE_POINT       0x00000400
#define SMB2_FILE_ATTRIBUTE_COMPRESSED          0x00000800
#define SMB2_FILE_ATTRIBUTE_OFFLINE             0x00001000
#define SMB2_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define SMB2_FILE_ATTRIBUTE_ENCRYPTED           0x00004000
#define SMB2_FILE_ATTRIBUTE_INTEGRITY_STREAM    0x00008000
#define SMB2_FILE_ATTRIBUTE_NO_SCRUB_DATA       0x00020000

/* Share access */        
#define SMB2_FILE_SHARE_READ 0x00000001
#define SMB2_FILE_SHARE_WRITE 0x00000002
#define SMB2_FILE_SHARE_DELETE 0x00000004

/* Create disposition */
#define SMB2_FILE_SUPERSEDE    0x00000000
#define SMB2_FILE_OPEN         0x00000001
#define SMB2_FILE_CREATE       0x00000002
#define SMB2_FILE_OPEN_IF      0x00000003
#define SMB2_FILE_OVERWRITE    0x00000004
#define SMB2_FILE_OVERWRITE_IF 0x00000005

/* Create options */
#define SMB2_FILE_DIRECTORY_FILE            0x00000001
#define SMB2_FILE_WRITE_THROUGH             0x00000002
#define SMB2_FILE_SEQUENTIAL_ONLY           0x00000004
#define SMB2_FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define SMB2_FILE_SYNCHRONOUS_IO_ALERT      0x00000010
#define SMB2_FILE_SYNCHRONOUS_IO_NONALERT   0x00000020
#define SMB2_FILE_NON_DIRECTORY_FILE        0x00000040
#define SMB2_FILE_COMPLETE_IF_OPLOCKED      0x00000100
#define SMB2_FILE_NO_EA_KNOWLEDGE           0x00000200
#define SMB2_FILE_RANDOM_ACCESS             0x00000800
#define SMB2_FILE_DELETE_ON_CLOSE           0x00001000
#define SMB2_FILE_OPEN_BY_FILE_ID           0x00002000
#define SMB2_FILE_OPEN_FOR_BACKUP_INTENT    0x00004000
#define SMB2_FILE_NO_COMPRESSION            0x00008000
#define SMB2_FILE_OPEN_REMOTE_INSTANCE      0x00000400
#define SMB2_FILE_OPEN_REQUIRING_OPLOCK     0x00010000
#define SMB2_FILE_DISALLOW_EXCLUSIVE        0x00020000
#define SMB2_FILE_RESERVE_OPFILTER          0x00100000
#define SMB2_FILE_OPEN_REPARSE_POINT        0x00200000
#define SMB2_FILE_OPEN_NO_RECALL            0x00400000
#define SMB2_FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000

struct smb2_create_request {
        uint8_t security_flags;
        uint8_t requested_oplock_level;
        uint32_t impersonation_level;
        uint64_t smb_create_flags;
        uint32_t desired_access;
        uint32_t file_attributes;
        uint32_t share_access;
        uint32_t create_disposition;
        uint32_t create_options;
        const char *name;       /* name in UTF8 */
        uint32_t create_context_length;
        char *create_context;
};

#define SMB2_CREATE_REPLY_SIZE 89

#define SMB2_FD_SIZE 16
typedef char smb2_file_id[SMB2_FD_SIZE];
        
struct smb2_create_reply {
        uint8_t oplock_level;
        uint8_t flags;
        uint32_t create_action;
        uint64_t creation_time;
        uint64_t last_access_time;
        uint64_t last_write_time;
        uint64_t change_time;
        uint64_t allocation_size;
        uint64_t end_of_file;
        uint32_t file_attributes;
        smb2_file_id file_id;
        uint32_t create_context_length;
        uint32_t create_context_offset;
        char *create_context;
};

#define SMB2_CLOSE_REQUEST_SIZE 24

#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB 0x0001

struct smb2_close_request {
        uint16_t flags;
        smb2_file_id file_id;
};

#define SMB2_CLOSE_REPLY_SIZE 60

struct smb2_close_reply {
        uint16_t flags;
        uint64_t creation_time;
        uint64_t last_access_time;
        uint64_t last_write_time;
        uint64_t change_time;
        uint64_t allocation_size;
        uint64_t end_of_file;
        uint32_t file_attributes;
};

#define SMB2_QUERY_DIRECTORY_REQUEST_SIZE 33

/* File information class */
#define SMB2_FILE_DIRECTORY_INFORMATION         0x01
#define SMB2_FILE_FULL_DIRECTORY_INFORMATION    0x02
#define SMB2_FILE_BOTH_DIRECTORY_INFORMATION    0x03
#define SMB2_FILE_NAMES_INFORMATION             0x0c
#define SMB2_FILE_ID_BOTH_DIRECTORY_INFORMATION 0x25
#define SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION 0x26

/* query flags */
#define SMB2_RESTART_SCANS       0x01
#define SMB2_RETURN_SINGLE_ENTRY 0x02
#define SMB2_INDEX_SPECIFIED     0x04
#define SMB2_REOPEN              0x10

/* Structure for SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION.
 * This is also used as the dirent content.
 */
struct smb2_fileidfulldirectoryinformation {
        uint32_t next_entry_offset;
        uint32_t file_index;
        struct smb2_timeval creation_time;
        struct smb2_timeval last_access_time;
        struct smb2_timeval last_write_time;
        struct smb2_timeval change_time;
        uint64_t end_of_file;
        uint64_t allocation_size;
        uint32_t file_attributes;
        uint32_t ea_size;
        uint64_t file_id;
        char *name;
};

struct smb2_query_directory_request {
        uint8_t file_information_class;
        uint8_t flags;
        uint32_t file_index;
        smb2_file_id file_id;
        char *name;       /* name in UTF8 */
        uint32_t output_buffer_length;
};

#define SMB2_QUERY_DIRECTORY_REPLY_SIZE 9

struct smb2_query_directory_reply {
        uint16_t output_buffer_offset;
        uint32_t output_buffer_length;
        char *output_buffer;
};

#define SMB2_READ_REQUEST_SIZE 49

#define SMB2_READFLAG_READ_UNBUFFERED 0x01

#define SMB2_CHANNEL_NONE               0x00000000
#define SMB2_CHANNEL_RDMA_V1            0x00000001
#define SMB2_CHANNEL_RDMA_V1_INVALIDATE 0x00000002

struct smb2_read_request {
        uint8_t flags;
        uint32_t length;
        uint64_t offset;
        char *buf;
        smb2_file_id file_id;
        uint32_t minimum_count;
        uint32_t channel;
        uint32_t remaining_bytes;
        uint16_t read_channel_info_length;
        char *read_channel_info;
};

#define SMB2_READ_REPLY_SIZE 17

struct smb2_read_reply {
        uint8_t data_offset;
        uint32_t data_length;
        uint32_t data_remaining;
};

#define SMB2_QUERY_INFO_REQUEST_SIZE 41

/* info type */
#define SMB2_0_INFO_FILE       0x01
#define SMB2_0_INFO_FILESYSTEM 0x02
#define SMB2_0_INFO_SECURITY   0x03
#define SMB2_0_INFO_QUOTA      0x04

/* additional info */
#define OWNER_SECURITY_INFORMATION     0x00000001
#define GROUP_SECURITY_INFORMATION     0x00000002
#define DACL_SECURITY_INFORMATION      0x00000004
#define SACL_SECURITY_INFORMATION      0x00000008
#define LABEL_SECURITY_INFORMATION     0x00000010
#define ATTRIBUTE_SECURITY_INFORMATION 0x00000020
#define SCOPE_SECURITY_INFORMATION     0x00000040
#define BACKUP_SECURITY_INFORMATION    0x00000100

/* flags */
#define SL_RESTART_SCAN        0x00000001
#define SL_RETURN_SINGLE_ENTRY 0x00000002
#define SL_INDEX_SPECIFIED     0x00000004

/*
 * FILE_BASIC_INFORMATION
 */
struct smb2_file_basic_information {
        struct smb2_timeval creation_time;
        struct smb2_timeval last_access_time;
        struct smb2_timeval last_write_time;
        struct smb2_timeval change_time;
        uint32_t file_attributes;
};

/*
 * FILE_STANDARD_INFORMATION
 */
struct smb2_file_standard_information {
        uint64_t allocation_size;
        uint64_t end_of_file;
        uint32_t number_of_links;
        uint8_t delete_pending;
        uint8_t directory;
};

/*
 * FILE_ALL_INFORMATION.
 */
struct smb2_file_all_information {
        struct smb2_file_basic_information basic;
        struct smb2_file_standard_information standard;
        uint64_t index_number;
        uint32_t ea_size;
        uint32_t access_flags;
        uint64_t current_byte_offset;
        uint32_t mode;
        uint32_t alignment_requirement;
        char *name_information;
};

/* File information class */
#define SMB2_FILE_ALL_INFORMATION               0x12

struct smb2_query_info_request {
        uint8_t info_type;
        uint8_t file_information_class;
        uint32_t output_buffer_length;
        uint32_t input_buffer_length;
        char *input_buffer;
        uint32_t additional_information;
        uint32_t flags;
        smb2_file_id file_id;
};

#define SMB2_QUERY_INFO_REPLY_SIZE 9

struct smb2_query_info_reply {
        uint16_t output_buffer_offset;
        uint32_t output_buffer_length;
        char *output_buffer;
};

#define SMB2_WRITE_REQUEST_SIZE 49

#define SMB2_WRITEFLAG_WRITE_THROUGH    0x00000001
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED 0x00000002

struct smb2_write_request {
        uint32_t length;
        uint64_t offset;
        char *buf;
        smb2_file_id file_id;
        uint32_t channel;
        uint32_t remaining_bytes;
        uint16_t write_channel_info_length;
        char *write_channel_info;
        uint32_t flags;
};

#define SMB2_WRITE_REPLY_SIZE 17

struct smb2_write_reply {
        uint32_t count;
        uint32_t remaining;
};

#define SMB2_ECHO_REQUEST_SIZE 4
#define SMB2_ECHO_REPLY_SIZE 4

#define SMB2_LOGOFF_REQUEST_SIZE 4
#define SMB2_LOGOFF_REPLY_SIZE 4

#define SMB2_TREE_DISCONNECT_REQUEST_SIZE 4
#define SMB2_TREE_DISCONNECT_REPLY_SIZE 4

#ifdef __cplusplus
}
#endif

#endif /* !_SMB2_H_ */
