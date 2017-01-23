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

#ifndef _LIBSMB2_H_
#define _LIBSMB2_H_

#ifdef __cplusplus
extern "C" {
#endif

struct smb2_context;

/*
 * Generic callback for completion of smb2_*_async().
 * command_data depends on status.
 */
typedef void (*smb2_command_cb)(struct smb2_context *smb2, int status,
                                void *command_data, void *cb_data);

/*
 * Create an SMB2 context.
 * Function returns
 *  NULL : Failed to create a context.
 *  *nfs : A pointer to an smb2 context.
 */
struct smb2_context *smb2_init_context(void);

/*
 * Destroy an smb2 context.
 */
void smb2_destroy_context(struct smb2_context *smb2);

/*
 * The following three functions are used to integrate libsmb2 in an event
 * system.
 */
/*
 * Returns the file descriptor that libsmb2 uses.
 */
int smb2_get_fd(struct smb2_context *smb2);
/*
 * Returns which events that we need to poll for for the smb2 file descriptor.
 */
int smb2_which_events(struct smb2_context *smb2);
/*
 * Called to process the events when events become available for the smb2
 * file descriptor.
 *
 * Returns:
 *  0 : Success
 * <0 : Unrecoverable failure. At this point the context can no longer be
 *      used and must be freed by calling smb2_destroy_context().
 *
 */
int smb2_service(struct smb2_context *smb2, int revents);

/*
 * Set the security mode for the connection.
 * This is a combination of the flags SMB2_NEGOTIATE_SIGNING_ENABLED
 * and  SMB2_NEGOTIATE_SIGNING_REQUIRED
 * Default is 0.
 */
void smb2_set_security_mode(struct smb2_context *smb2, uint16_t security_mode);

/*
 * Returns the client_guid for this context.
 */
const char *smb2_get_client_guid(struct smb2_context *smb2);
        
/*
 * Asynchronous call to connect a TCP connection to the server
 *
 * Returns:
 *  0 if the call was initiated and a connection will be attempted. Result of
 * the connection will be reported through the callback function.
 * <0 if there was an error. The callback function will not be invoked.
 *
 * Callback parameters :
 * status can be either of :
 *    0     : Connection was successful. Command_data is NULL.
 *
 *   <0     : Failed to establish the connection. Command_data is NULL.
 */
int smb2_connect_async(struct smb2_context *smb2, const char *server,
                       smb2_command_cb cb, void *cb_data);

/*
 * Async call to connect to a share/
 *
 * Returns:
 *  0 if the call was initiated and a connection will be attempted. Result of
 * the connection will be reported through the callback function.
 * -errno if there was an error. The callback function will not be invoked.
 *
 * Callback parameters :
 * status can be either of :
 *    0     : Connection was successful. Command_data is NULL.
 *
 *   -errno : Failed to connect to the share. Command_data is NULL.
 */
int smb2_connect_share_async(struct smb2_context *smb2,
                             const char *server, const char *share,
                             smb2_command_cb cb, void *cb_data);

/*
 * Sync call to connect to a share/
 *
 * Returns:
 * 0      : Connected to the share successfully.
 * -errno : Failure.
 */
int smb2_connect_share(struct smb2_context *smb2,
                       const char *server, const char *share);
        
/*
 * This function returns a description of the last encountered error.
 */
const char *smb2_get_error(struct smb2_context *smb2);

struct smb2_url {
        char *domain;
        char *user;
        char *server;
        char *share;
        char *path;
};

/* Convert an smb2/nt error code into a string */
const char *nterror_to_str(uint32_t status);

/* Convert an smb2/nt error code into an errno value */
int nterror_to_errno(uint32_t status);
        
/*
 * This function is used to parse an SMB2 URL into as smb2_url structure.
 * SMB2 URL format :
 * smb2://[<domain;][<username>@]<host>/<share>/<path>
 *
 * Function will return a pointer to an iscsi smb2 structure if successful,
 * or it will return NULL and set smb2_get_error() accordingly if there was
 * a problem with the URL.
 *
 * The returned structure is freed by calling smb2_destroy_url()
 */
struct smb2_url *smb2_parse_url(struct smb2_context *smb2, const char *url);
void smb2_destroy_url(struct smb2_url *url);


/*
 * OPENDIR
 */
struct smb2dir;
/*
 * Async opendir()
 *
 * Returns
 *  0 : The operation was initiated. Result of the operation will be reported
 * through the callback function.
 * <0 : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          Command_data is struct smb2dir.
 *          This structure is freed using smb2_closedir().
 * -errno : An error occured.
 *          Command_data is NULL.
 */       
int smb2_opendir_async(struct smb2_context *smb2, const char *path,
                       smb2_command_cb cb, void *cb_data);

/*
 * Sync opendir()
 *
 * Returns NULL on failure.
 */
struct smb2dir *smb2_opendir(struct smb2_context *smb2, const char *path);

/*
 * closedir()
 */
/*
 * smb2_closedir() never blocks, thus no async version is needed.
 */
void smb2_closedir(struct smb2_context *smb2, struct smb2dir *smb2dir);

/*
 * readdir()
 */
/*
 * smb2_readdir() never blocks, thus no async version is needed.
 */
struct smb2dirent *smb2_readdir(struct smb2_context *smb2,
                                struct smb2dir *smb2dir);

/*
 * rewinddir()
 */
/*
 * smb2_rewinddir() never blocks, thus no async version is needed.
 */
void smb2_rewinddir(struct smb2_context *smb2, struct smb2dir *smb2dir);

/*
 * telldir()
 */
/*
 * smb2_telldir() never blocks, thus no async version is needed.
 */
long smb2_telldir(struct smb2_context *smb2, struct smb2dir *smb2dir);

/*
 * seekdir()
 */
/*
 * smb2_seekdir() never blocks, thus no async version is needed.
 */
void smb2_seekdir(struct smb2_context *smb2, struct smb2dir *smb2dir,
                  long loc);

/*
 * OPEN
 */
struct smb2fh;
/*
 * Async open()
 *
 * Opens or creates a file.
 * Supported flags are:
 * O_RDONLY
 * O_WRONLY
 * O_RDWR
 * O_SYNC
 * O_CREAT
 * O_EXCL
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          Command_data is struct smb2fh.
 *          This structure is freed using smb2_close().
 * -errno : An error occured.
 *          Command_data is NULL.
 */       
int smb2_open_async(struct smb2_context *smb2, const char *path, int flags,
                    smb2_command_cb cb, void *cb_data);

/*
 * Sync open()
 *
 * Returns NULL on failure.
 */
struct smb2fh *smb2_open(struct smb2_context *smb2, const char *path, int flags);

/*
 * CLOSE
 */
/*
 * Async close()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */       
int smb2_close_async(struct smb2_context *smb2, struct smb2fh *fh,
                     smb2_command_cb cb, void *cb_data);

/*
 * Sync close()
 */
int smb2_close(struct smb2_context *smb2, struct smb2fh *fh);

/*
 * PREAD
 */
/*
 * Async pread()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Number of bytes read.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */       
int smb2_pread_async(struct smb2_context *smb2, struct smb2fh *fh,
                     char *buf, uint32_t count, uint64_t offset,
                     smb2_command_cb cb, void *cb_data);

/*
 * Sync pread()
 */
int smb2_pread(struct smb2_context *smb2, struct smb2fh *fh,
               char *buf, uint32_t count, uint64_t offset);

/*
 * READ
 */
/*
 * Async read()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Number of bytes read.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */
int smb2_read_async(struct smb2_context *smb2, struct smb2fh *fh,
                    char *buf, uint32_t count,
                    smb2_command_cb cb, void *cb_data);

/*
 * Sync read()
 */
int smb2_read(struct smb2_context *smb2, struct smb2fh *fh,
              char *buf, uint32_t count);

#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_H_ */
