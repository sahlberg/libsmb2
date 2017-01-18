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
                                void *command_data, void *private_data);

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
                       smb2_command_cb cb, void *private_data);

/*
 * Asynchronous call to connect to a share/
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
 *   <0     : Failed to connect to the share. Command_data is NULL.
 */
int smb2_connect_share_async(struct smb2_context *smb2,
                             const char *server, const char *share,
                             smb2_command_cb cb, void *private_data);
        
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
 * Asynchronous SMB2 Negotiate
 *
 * Returns:
 *  0 if the call was initiated and a connection will be attempted. Result of
 * the connection will be reported through the callback function.
 * <0 if there was an error. The callback function will not be invoked.
 *
 * Callback parameters :
 * status is nt status code.
 * command_data is a struct session_setup_reply.
 */
int smb2_negotiate_async(struct smb2_context *smb2,
                         struct negotiate_request *req,
                         smb2_command_cb cb, void *cb_data);


/*
 * Asynchronous SMB2 Session Setup
 *
 * Returns:
 *  0 if the call was initiated and a connection will be attempted. Result of
 * the connection will be reported through the callback function.
 * <0 if there was an error. The callback function will not be invoked.
 *
 * Callback parameters :
 * status can be either of :
 *    0     : Session Setup was successful.
 *            Command_data is a struct negotiate_reply.
 *
 *   <0     : Session Setup failed. Command_data is NULL.
 */
int smb2_session_setup_async(struct smb2_context *smb2,
                             struct session_setup_request *req,
                             smb2_command_cb cb, void *cb_data);

/*
 * Asynchronous SMB2 Tree Connect
 *
 * Returns:
 *  0 if the call was initiated and a connection will be attempted. Result of
 * the connection will be reported through the callback function.
 * <0 if there was an error. The callback function will not be invoked.
 *
 * Callback parameters :
 * status can be either of :
 *    0     : Tree Connect was successful.
 *            Command_data is a struct tree_connect_reply.
 *
 *   <0     : Tree Connect failed. Command_data is NULL.
 */
int smb2_tree_connect_async(struct smb2_context *smb2,
                            struct tree_connect_request *req,
                            smb2_command_cb cb, void *cb_data);

/*
 * Asynchronous SMB2 Echo
 *
 * Returns:
 *  0 if the call was initiated and a connection will be attempted. Result of
 * the connection will be reported through the callback function.
 * <0 if there was an error. The callback function will not be invoked.
 *
 * Callback parameters :
 * status can be either of :
 *    0     : Echo was successful.
 *
 *   <0     : Echo failed.
 *
 * command_data is always NULL.
 */
int smb2_echo_async(struct smb2_context *smb2,
                    smb2_command_cb cb, void *cb_data);

/*
 * Asynchronous SMB2 Logoff
 *
 * Returns:
 *  0 if the call was initiated and a connection will be attempted. Result of
 * the connection will be reported through the callback function.
 * <0 if there was an error. The callback function will not be invoked.
 *
 * Callback parameters :
 * status can be either of :
 *    0     : Logoff was successful.
 *
 *   <0     : Logoff failed.
 *
 * command_data is always NULL.
 */
int smb2_logoff_async(struct smb2_context *smb2,
                      smb2_command_cb cb, void *cb_data);
        
#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_H_ */
