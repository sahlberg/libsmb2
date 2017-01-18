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

#ifdef __cplusplus
extern "C" {
#endif

#define STATUS_SUCCESS                  0x00000000
#define STATUS_MORE_PROCESSING_REQUIRED 0xC0000016


#define SMB2_FLAGS_SERVER_TO_REDIR    0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND      0x00000002
#define SMB2_FLAGS_RELATED_OPERATIONS 0x00000004
#define SMB2_FLAGS_SIGNED             0x00000008
#define SMB2_FLAGS_PRIORITY_MASK      0x00000070
#define SMB2_FLAGS_DFS_OPERATIONS     0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION   0x20000000
        
enum smb2_command {
        SMB2_NEGOTIATE       = 0x0000,
        SMB2_SESSION_SETUP,
        SMB2_LOGOFF,
        SMB2_TREE_CONNECT,
        SMB2_TREE_DISCONNECT,
        SMB2_CREATE,
        SMB2_CLOSE,
        SMB2_FLUSH,
        SMB2_READ,
        SMB2_WRITE,
        SMB2_LOCK,
        SMB2_IOCTL,
        SMB2_CANCEL,
        SMB2_ECHO,
        SMB2_QUERY_DIRECTORY,
        SMB2_CHANGE_NOTIFY,
        SMB2_QUERY_INFO,
        SMB2_SET_INFO,
        SMB2_OPLOCK_BREAK,
};

/*
 * SMB2 NEGOTIATE
 */
#define SMB2_NEGOTIATE_SIGNING_ENABLED  0x0001
#define SMB2_NEGOTIATE_SIGNING_REQUIRED 0x0002

#define SMB2_NUM_DIALECTS 2
#define SMB2_VERSION_0202     0x0202
#define SMB2_VERSION_0210     0x0210
#define SMB2_VERSION_WILDCARD 0x02FF

#define SMB2_GLOBAL_CAP_DFS                0x00000001
#define SMB2_GLOBAL_CAP_LEASING            0x00000002
#define SMB2_GLOBAL_CAP_LARGE_MTU          0x00000004
#define SMB2_GLOBAL_CAP_MULTI_CHANNEL      0x00000008
#define SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010
#define SMB2_GLOBAL_CAP_DIRECTORY_LEASING  0x00000020
#define SMB2_GLOBAL_CAP_ENCRYPTION         0x00000040
        
#define SMB2_NEGOTIATE_MAX_DIALECTS 10

#define NEGOTIATE_REQUEST_SIZE 36
        
struct negotiate_request {
        uint16_t struct_size;
        uint16_t dialect_count;
        uint16_t security_mode;
        uint32_t capabilities;
        unsigned char client_guid[16];
        uint64_t client_start_time;
        uint16_t dialects[SMB2_NEGOTIATE_MAX_DIALECTS];
};

#define NEGOTIATE_REPLY_SIZE 65

struct negotiate_reply {
        uint16_t struct_size;
        uint16_t security_mode;
        uint16_t dialect_revision;
        unsigned char server_guid[16];
        uint32_t capabilities;
        uint32_t max_transact_size;
        uint32_t max_read_size;
        uint32_t max_write_size;
        uint64_t system_time;
        uint64_t server_start_time;
        uint16_t security_buffer_offset;
        uint16_t security_buffer_length;
        char *security_buffer;
};

/* session setup flags */
#define SMB2_SESSION_FLAG_BINDING 0x01

/* session setup capabilities */
#define SMB2_GLOBAL_CAP_DFS     0x00000001
#define SMB2_GLOBAL_CAP_UNUSED1 0x00000002
#define SMB2_GLOBAL_CAP_UNUSED2 0x00000004
#define SMB2_GLOBAL_CAP_UNUSED4 0x00000008

#define SESSION_SETUP_REQUEST_SIZE 25

struct session_setup_request {
        uint16_t struct_size;
        uint8_t flags;
        uint8_t security_mode;
        uint32_t capabilities;
        uint32_t channel;
        uint16_t security_buffer_offset;
        uint16_t security_buffer_length;
        uint64_t previous_session_id;
        char *security_buffer;
};

#define SMB2_SESSION_FLAG_IS_GUEST        0x0001
#define SMB2_SESSION_FLAG_IS_NULL         0x0002
#define SMB2_SESSION_FLAG_IS_ENCRYPT_DATA 0x0004

struct session_setup_reply {
        uint16_t struct_size;
        uint16_t session_flags;
        uint16_t security_buffer_offset;
        uint16_t security_buffer_length;
        char *security_buffer;
};

#define TREE_CONNECT_REQUEST_SIZE 9
        
#define SMB2_SHAREFLAG_CLUSTER_RECONNECT 0x0001

struct tree_connect_request {
        uint16_t struct_size;
        uint16_t flags;
        uint16_t path_offset;
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

struct tree_connect_reply {
        uint16_t struct_size;
        uint8_t share_type;
        uint32_t share_flags;
        uint32_t capabilities;
        uint32_t maximal_access;
};
        
#ifdef __cplusplus
}
#endif

#endif /* !_SMB2_H_ */
