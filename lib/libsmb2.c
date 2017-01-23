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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <gssapi/gssapi.h>

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

static gss_OID_desc gss_mech_spnego = {
    6, "\x2b\x06\x01\x05\x05\x02"
};

struct private_auth_data {
        gss_ctx_id_t context;
        gss_cred_id_t cred;
        gss_name_t target_name;
        gss_OID mech_type;
        uint32_t req_flags;
        gss_buffer_desc output_token;
};

struct connect_data {
        smb2_command_cb cb;
        void *cb_data;
        char *g_server;

        const char *server;
        const char *share;

        /* UNC for the share in utf8 as well as ucs2 formats */
        char *utf8_unc;
        struct ucs2 *ucs2_unc;
                
        struct private_auth_data *auth_data;
};

struct smb2dir {
        smb2_command_cb cb;
        void *cb_data;
        smb2_file_id file_id;
        
        struct smb2_dirent_internal *entries;
        struct smb2_dirent_internal *current_entry;
        int index;
};

struct smb2fh {
        smb2_command_cb cb;
        void *cb_data;

        smb2_file_id file_id;
        uint64_t offset;
};

static int
send_session_setup_request(struct smb2_context *smb2,
                           struct connect_data *c_data,
                           gss_buffer_desc *input_token);

static void free_smb2dir(struct smb2dir *dir)
{

        while (dir->entries) {
                struct smb2_dirent_internal *e = dir->entries->next;

                free(dir->entries->dirent.name);
                free(dir->entries);
                dir->entries = e;
        }
        free(dir);
}

void smb2_seekdir(struct smb2_context *smb2, struct smb2dir *dir,
                  long loc)
{
        dir->current_entry = dir->entries;
        dir->index = 0;

        while (dir->current_entry && loc--) {
                dir->current_entry = dir->current_entry->next;
                dir->index++;
        }
}

long smb2_telldir(struct smb2_context *smb2, struct smb2dir *dir)
{
        return dir->index;
}

void smb2_rewinddir(struct smb2_context *smb2,
                    struct smb2dir *dir)
{
        dir->current_entry = dir->entries;
        dir->index = 0;
}

struct smb2dirent *smb2_readdir(struct smb2_context *smb2,
                                struct smb2dir *dir)
{
        struct smb2dirent *ent;

        if (dir->current_entry == NULL) {
                return NULL;
        }

        ent = &dir->current_entry->dirent;
        dir->current_entry = dir->current_entry->next;
        dir->index++;

        return ent;
}

void smb2_closedir(struct smb2_context *smb2, struct smb2dir *dir)
{
        free_smb2dir(dir);
}

static int
decode_dirents(struct smb2_context *smb2, struct smb2dir *dir,
               struct smb2_iovec *vec)
{
        uint32_t tmp, offset = 0;

        /* TODO Split this out into a generic parser for
         * struct smb2_fileidfulldirectoryinformation
         */
        do {
                struct smb2_dirent_internal *ent;
                uint32_t name_len;
                uint64_t t;

                /* Make sure we do not go beyond end of vector */
                if (offset >= vec->len) {
                        smb2_set_error(smb2, "Malformed query reply.\n");
                        return -1;
                }

                /* Make sure the name fits before end of vector.
                 * As the name is the final part of this blob this guarantees
                 * that all other fields also fit within the remainder of the
                 * vector.
                 */
                smb2_get_uint32(vec, offset + 60, &name_len);
                if (offset + 80 + name_len > vec->len) {
                        smb2_set_error(smb2, "Malformed name in query.\n");
                        return -1;
                }

                smb2_get_uint32(vec, offset, &tmp);
                
                ent = malloc(sizeof(struct smb2_dirent_internal));
                if (ent == NULL) {
                        smb2_set_error(smb2, "Failed to allocate "
                                       "dirent_internal");
                        return -1;
                }
                memset(ent, 0, sizeof(struct smb2_dirent_internal));
                SMB2_LIST_ADD(&dir->entries, ent);

                smb2_get_uint32(vec, offset + 4, &ent->dirent.file_index);
                smb2_get_uint64(vec, offset + 40, &ent->dirent.end_of_file);
                smb2_get_uint64(vec, offset + 48, &ent->dirent.allocation_size);
                smb2_get_uint32(vec, offset + 56, &ent->dirent.file_attributes);
                smb2_get_uint32(vec, offset + 64, &ent->dirent.ea_size);
                smb2_get_uint64(vec, offset + 72, &ent->dirent.file_id);

                ent->dirent.name =
                        ucs2_to_utf8((uint16_t *)&vec->buf[offset + 80],
                                     name_len / 2);

                smb2_get_uint64(vec, offset + 8, &t);
                win_to_timeval(t, &ent->dirent.creation_time);

                smb2_get_uint64(vec, offset + 16, &t);
                win_to_timeval(t, &ent->dirent.last_access_time);

                smb2_get_uint64(vec, offset + 24, &t);
                win_to_timeval(t, &ent->dirent.last_write_time);

                smb2_get_uint64(vec, offset + 32, &t);
                win_to_timeval(t, &ent->dirent.change_time);

                offset += tmp;
        } while (tmp);
        
        return 0;
}

static void
od_close_cb(struct smb2_context *smb2, int status,
         void *command_data, void *private_data)
{
        struct smb2dir *dir = private_data;

        if (status != SMB2_STATUS_SUCCESS) {
                dir->cb(smb2, -ENOMEM, NULL, dir->cb_data);
                free_smb2dir(dir);
                return;
        }

        dir->current_entry = dir->entries;
        dir->index = 0;

        /* dir will be freed in smb2_closedir() */
        dir->cb(smb2, 0, dir, dir->cb_data);
}

static void
query_cb(struct smb2_context *smb2, int status,
         void *command_data, void *private_data)
{
        struct smb2dir *dir = private_data;
        struct smb2_query_directory_reply *rep = command_data;

        if (status == SMB2_STATUS_SUCCESS) {
                struct smb2_iovec vec;
                struct smb2_query_directory_request req;

                vec.buf = rep->output_buffer;
                vec.len = rep->output_buffer_length;

                if (decode_dirents(smb2, dir, &vec) < 0) {
                        dir->cb(smb2, -ENOMEM, NULL, dir->cb_data);
                        free_smb2dir(dir);
                        return;
                }

                /* We need to get more data */
                memset(&req, 0, sizeof(struct smb2_query_directory_request));
                req.struct_size = SMB2_QUERY_DIRECTORY_REQUEST_SIZE;
                req.file_information_class = SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION;
                req.flags = 0;
                memcpy(req.file_id, dir->file_id, SMB2_FD_SIZE);
                req.output_buffer_length = 0xffff;
                req.name_offset = 0x60;
                req.name = "*";
                
                if (smb2_cmd_query_directory_async(smb2, &req, query_cb, dir) < 0) {
                        dir->cb(smb2, -ENOMEM, NULL, dir->cb_data);
                        free_smb2dir(dir);
                }
                return;
        }

        if (status == SMB2_STATUS_NO_MORE_FILES) {
                struct smb2_close_request req;

                /* We have all the data */
                memset(&req, 0, sizeof(struct smb2_close_request));
                req.struct_size = SMB2_CLOSE_REQUEST_SIZE;
                req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
                memcpy(req.file_id, dir->file_id, SMB2_FD_SIZE);
        
                if (smb2_cmd_close_async(smb2, &req, od_close_cb, dir) < 0) {
                        dir->cb(smb2, -ENOMEM, NULL, dir->cb_data);
                        free_smb2dir(dir);
                }
                return;
        }

        smb2_set_error(smb2, "Query directory failed with (0x%08x) %s",
                       status, nterror_to_str(status));
        dir->cb(smb2, -nterror_to_errno(status), NULL, dir->cb_data);
        free_smb2dir(dir);
}

static void
opendir_cb(struct smb2_context *smb2, int status,
           void *command_data, void *private_data)
{
        struct smb2dir *dir = private_data;
        struct smb2_create_reply *rep = command_data;
        struct smb2_query_directory_request req;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Opendir failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                dir->cb(smb2, -nterror_to_errno(status), NULL, dir->cb_data);
                free_smb2dir(dir);
                return;
        }

        memcpy(dir->file_id, rep->file_id, SMB2_FD_SIZE);
        
        memset(&req, 0, sizeof(struct smb2_query_directory_request));
        req.struct_size = SMB2_QUERY_DIRECTORY_REQUEST_SIZE;
        req.file_information_class = SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION;
        req.flags = 0;
        memcpy(req.file_id, dir->file_id, SMB2_FD_SIZE);
        req.output_buffer_length = 0xffff;
        req.name_offset = 0x60;
        req.name = "*";

        if (smb2_cmd_query_directory_async(smb2, &req, query_cb, dir) < 0) {
                smb2_set_error(smb2, "Failed to send query command");
                dir->cb(smb2, -ENOMEM, NULL, dir->cb_data);
                free_smb2dir(dir);
                return;
        }
}

int smb2_opendir_async(struct smb2_context *smb2, const char *path,
                       smb2_command_cb cb, void *cb_data)
{
        struct smb2_create_request req;
        struct smb2dir *dir;

        if (path == NULL) {
                path = "";
        }

        dir = malloc(sizeof(struct smb2dir));
        if (dir == NULL) {
                smb2_set_error(smb2, "Failed to allocate smb2dir");
                return -1;
        }
        memset(dir, 0, sizeof(struct smb2dir));
        dir->cb = cb;
        dir->cb_data = cb_data;

        memset(&req, 0, sizeof(struct smb2_create_request));
        req.struct_size = SMB2_CREATE_REQUEST_SIZE;
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        req.desired_access = SMB2_FILE_LIST_DIRECTORY | SMB2_FILE_READ_ATTRIBUTES;
        req.file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
        req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        req.create_disposition = SMB2_FILE_OPEN;
        req.create_options = SMB2_FILE_DIRECTORY_FILE;
        req.name_offset = 0x78;
        req.name = path;
        
        if (smb2_cmd_create_async(smb2, &req, opendir_cb, dir) < 0) {
                free_smb2dir(dir);
                smb2_set_error(smb2, "Failed to send opendir command");
                return -1;
        }
        
        return 0;
}

static char *display_status(int type, uint32_t err)
{
        gss_buffer_desc text;
        uint32_t msg_ctx;
        char *msg, *tmp;
        uint32_t maj, min;

        msg = NULL;
        msg_ctx = 0;
        do {
                maj = gss_display_status(&min, err, type,
                                         GSS_C_NO_OID, &msg_ctx, &text);
                if (maj != GSS_S_COMPLETE) {
                        return msg;
                }

                tmp = NULL;
                if (msg) {
                        tmp = msg;
                        min = asprintf(&msg, "%s, %*s", msg,
                                       (int)text.length, (char *)text.value);
                } else {
                        min = asprintf(&msg, "%*s", (int)text.length,
                                       (char *)text.value);
                }
                if (min == -1) return tmp;
                free(tmp);
                gss_release_buffer(&min, &text);
        } while (msg_ctx != 0);

        return msg;
}

static void set_gss_error(struct smb2_context *smb2, char *func,
                          uint32_t maj, uint32_t min)
{
        char *err_maj = display_status(GSS_C_GSS_CODE, maj);
        char *err_min = display_status(GSS_C_MECH_CODE, min);
        smb2_set_error(smb2, "%s: (%s, %s)", func, err_maj, err_min);
        free(err_min);
        free(err_maj);
}

static void free_auth_data(struct private_auth_data *auth)
{
        uint32_t maj, min;

        /* Delete context */
        if (auth->context) {
                maj = gss_delete_sec_context(&min, &auth->context,
                                             &auth->output_token);
                if (maj != GSS_S_COMPLETE) {
                        /* No logging, yet. Do we care? */
                }
        }
        /* Free output_token */
        gss_release_buffer(&min, &auth->output_token);

        /* Free the target name */
        if (auth->target_name) {
                gss_release_name(&min, &auth->target_name);
        }

        free(auth);
}

static void free_c_data(struct connect_data *c_data)
{
        if (c_data->auth_data) {
                free_auth_data(c_data->auth_data);
        }

        free(c_data->utf8_unc);
        free(c_data->ucs2_unc);
        free(c_data->g_server);
        free(discard_const(c_data->server));
        free(discard_const(c_data->share));
        free(c_data);
}


static void
tree_connect_cb(struct smb2_context *smb2, int status,
                void *command_data, void *private_data)
{
        struct connect_data *c_data = private_data;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Session setup failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                c_data->cb(smb2, -nterror_to_errno(status), NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }

        c_data->cb(smb2, 0, NULL, c_data->cb_data);
        free_c_data(c_data);
}

static void
session_setup_cb(struct smb2_context *smb2, int status,
                 void *command_data, void *private_data)
{
        struct connect_data *c_data = private_data;
        struct smb2_session_setup_reply *rep = command_data;
        struct smb2_tree_connect_request req;
        gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
        uint32_t min;
        int ret;

        /* release the previous token */
        gss_release_buffer(&min, &c_data->auth_data->output_token);
        c_data->auth_data->output_token.length = 0;
        c_data->auth_data->output_token.value = NULL;
        
        if (status == SMB2_STATUS_MORE_PROCESSING_REQUIRED) {
                input_token.length = rep->security_buffer_length;
                input_token.value = rep->security_buffer;

                if ((ret = send_session_setup_request(smb2, c_data,
                                                      &input_token)) < 0) {
                        c_data->cb(smb2, ret, NULL, c_data->cb_data);
                        free_c_data(c_data);
                        return;
                }
                return;
        }

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Session setup failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                c_data->cb(smb2, -nterror_to_errno(status), NULL,
                           c_data->cb_data);
                free_c_data(c_data);
                return;
        }

        memset(&req, 0, sizeof(struct smb2_tree_connect_request));
        req.struct_size = SMB2_TREE_CONNECT_REQUEST_SIZE;
        req.flags       = 0;
        req.path_offset = 0x48;
        req.path_length = 2 * c_data->ucs2_unc->len;
        req.path        = c_data->ucs2_unc->val;
        if (smb2_cmd_tree_connect_async(smb2, &req, tree_connect_cb,
                                        c_data) != 0) {
                c_data->cb(smb2, -ENOMEM, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }
}

/* Returns 0 for success and -errno for failure */
static int
send_session_setup_request(struct smb2_context *smb2,
                           struct connect_data *c_data,
                           gss_buffer_desc *input_token)
{
        uint32_t maj, min;
        struct smb2_session_setup_request req;

        /* TODO return -errno instead of just -1 */
        /* NOTE: this call is not async, a helper thread should be used if that
         * is an issue */
        maj = gss_init_sec_context(&min, c_data->auth_data->cred,
                                   &c_data->auth_data->context,
                                   c_data->auth_data->target_name,
                                   c_data->auth_data->mech_type,
                                   GSS_C_SEQUENCE_FLAG |
                                   GSS_C_MUTUAL_FLAG |
                                   GSS_C_REPLAY_FLAG |
                                   ((smb2->security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED)?GSS_C_INTEG_FLAG:0),
                                   GSS_C_INDEFINITE,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   input_token,
                                   NULL,
                                   &c_data->auth_data->output_token,
                                   NULL,
                                   NULL);
        if (GSS_ERROR(maj)) {
                set_gss_error(smb2, "gss_init_sec_context", maj, min);
                return -1;
        }

        if (maj == GSS_S_CONTINUE_NEEDED) {
                /* Session setup request. */
                memset(&req, 0, sizeof(struct smb2_session_setup_request));
                req.struct_size = SMB2_SESSION_SETUP_REQUEST_SIZE;
                req.security_mode = smb2->security_mode;
                req.security_buffer_offset = 0x58;
                req.security_buffer_length = c_data->auth_data->output_token.length;
                req.security_buffer = c_data->auth_data->output_token.value;
                
                if (smb2_cmd_session_setup_async(smb2, &req, session_setup_cb,
                                                 c_data) != 0) {
                        return -ENOMEM;
                }
        } else {
                /* TODO: cleanup and fail */
        }
        
        return 0;
}

static void
negotiate_cb(struct smb2_context *smb2, int status,
             void *command_data, void *private_data)
{
        struct connect_data *c_data = private_data;
        gss_buffer_desc target = GSS_C_EMPTY_BUFFER;
        uint32_t maj, min;
        int ret;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Negotiate failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                c_data->cb(smb2, -nterror_to_errno(status), NULL,
                           c_data->cb_data);
                free_c_data(c_data);
                return;
        }

        c_data->auth_data = malloc(sizeof(struct private_auth_data));
        if (c_data->auth_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate private_auth_data");
                c_data->cb(smb2, -ENOMEM, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }
        memset(c_data->auth_data, 0, sizeof(struct private_auth_data));
        c_data->auth_data->context = GSS_C_NO_CONTEXT;
                
        if (asprintf(&c_data->g_server, "cifs@%s", c_data->server) < 0) {
                smb2_set_error(smb2, "Failed to allocate server string");
                c_data->cb(smb2, -ENOMEM, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }

        target.value = c_data->g_server;
        target.length = strlen(c_data->g_server);

        maj = gss_import_name(&min, &target, GSS_C_NT_HOSTBASED_SERVICE,
                              &c_data->auth_data->target_name);

        if (maj != GSS_S_COMPLETE) {
                set_gss_error(smb2, "gss_import_name", maj, min);
                c_data->cb(smb2, -ENOMEM, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }

        /* TODO: acquire cred before hand if not using default creds,
         * with gss_acquire_cred_from() or gss_acquire_cred_with_password()
         */
        c_data->auth_data->cred = GSS_C_NO_CREDENTIAL;

        /* TODO: the proper mechanism (SPNEGO vs NTLM vs KRB5) should be
         * selected based on the SMB negotiation flags */
        c_data->auth_data->mech_type = &gss_mech_spnego;

        if ((ret = send_session_setup_request(smb2, c_data, NULL)) < 0) {
                c_data->cb(smb2, ret, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }
}

static void
connect_cb(struct smb2_context *smb2, int status,
           void *command_data _U_, void *private_data)
{
        struct connect_data *c_data = private_data;
        struct smb2_negotiate_request req;

        if (status != 0) {
                smb2_set_error(smb2, "Socket connect failed with %d",
                               status);
                c_data->cb(smb2, -status, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }
        
        memset(&req, 0, sizeof(struct smb2_negotiate_request));
        req.struct_size = SMB2_NEGOTIATE_REQUEST_SIZE;
        req.dialect_count = SMB2_NUM_DIALECTS;
        req.security_mode = smb2->security_mode;
        req.dialects[0] = SMB2_VERSION_0202;
        req.dialects[1] = SMB2_VERSION_0210;
        memcpy(req.client_guid, smb2_get_client_guid(smb2), 16);

        if (smb2_cmd_negotiate_async(smb2, &req, negotiate_cb, c_data) != 0) {
                c_data->cb(smb2, -ENOMEM, NULL, c_data->cb_data);
                free_c_data(c_data);
                return;
        }
}

int smb2_connect_share_async(struct smb2_context *smb2,
                             const char *server, const char *share,
                             smb2_command_cb cb, void *cb_data)
{
        struct connect_data *c_data;

        c_data = malloc(sizeof(struct connect_data));
        if (c_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate connect_data");
                return -ENOMEM;
        }
        memset(c_data, 0, sizeof(struct connect_data));
        c_data->server = strdup(server);
        if (c_data->server == NULL) {
                free_c_data(c_data);
                smb2_set_error(smb2, "Failed to strdup(server)");
                return -ENOMEM;
        }
        c_data->share = strdup(share);
        if (c_data->share == NULL) {
                free_c_data(c_data);
                smb2_set_error(smb2, "Failed to strdup(server)");
                return -ENOMEM;
        }
        if (asprintf(&c_data->utf8_unc, "\\\\%s\\%s", c_data->server,
                     c_data->share) < 0) {
                free_c_data(c_data);
                smb2_set_error(smb2, "Failed to allocate unc string.");
                return -ENOMEM;
        }

        c_data->ucs2_unc = utf8_to_ucs2(c_data->utf8_unc);
        if (c_data->ucs2_unc == NULL) {
                free_c_data(c_data);
                smb2_set_error(smb2, "Count not convert UNC:[%s] into UCS2",
                               c_data->utf8_unc);
                return -ENOMEM;
        }
                
        c_data->cb = cb;
        c_data->cb_data = cb_data;
 
        if (smb2_connect_async(smb2, server, connect_cb, c_data) != 0) {
                free_c_data(c_data);
                return -ENOMEM;
        }

        return 0;
}

static void free_smb2fh(struct smb2fh *fh)
{
        free(fh);
}

static void
open_cb(struct smb2_context *smb2, int status,
        void *command_data, void *private_data)
{
        struct smb2fh *fh = private_data;
        struct smb2_create_reply *rep = command_data;

        if (status != SMB2_STATUS_SUCCESS) {
                fh->cb(smb2, -nterror_to_errno(status),
                       NULL, fh->cb_data);
                free_smb2fh(fh);
                return;
        }

        memcpy(fh->file_id, rep->file_id, SMB2_FD_SIZE);
        fh->cb(smb2, 0, fh, fh->cb_data);
}

int smb2_open_async(struct smb2_context *smb2, const char *path, int flags,
                    smb2_command_cb cb, void *cb_data)
{
        struct smb2fh *fh;
        struct smb2_create_request req;
        uint32_t desired_access = 0;
        uint32_t create_disposition = 0;
        uint32_t create_options = 0;
        uint32_t file_attributes = 0;

        fh = malloc(sizeof(struct smb2fh));
        if (fh == NULL) {
                smb2_set_error(smb2, "Failed to allocate smbfh");
                return -ENOMEM;
        }
        memset(fh, 0, sizeof(struct smb2fh));

        fh->cb = cb;
        fh->cb_data = cb_data;

        /* Create disposition */
        if (flags & O_CREAT) {
                if (flags & O_EXCL) {
                        create_disposition = SMB2_FILE_CREATE;
                } else {
                        create_disposition = SMB2_FILE_OVERWRITE_IF;
                }
        } else {
                if (flags & (O_WRONLY | O_RDWR)) {
                        create_disposition = SMB2_FILE_OVERWRITE;
                } else {
                        create_disposition = SMB2_FILE_OPEN;
                }
        }

        /* desired access */
        if (flags & (O_RDWR | O_WRONLY)) {
                desired_access |= SMB2_FILE_WRITE_DATA |
                        SMB2_FILE_WRITE_EA |
                        SMB2_FILE_WRITE_ATTRIBUTES;
        }
        if (flags & O_RDWR || !(flags & O_WRONLY)) {
                desired_access |= SMB2_FILE_READ_DATA |
                        SMB2_FILE_READ_EA |
                        SMB2_FILE_READ_ATTRIBUTES;
        }

        /* create options */
        create_options |= SMB2_FILE_NON_DIRECTORY_FILE;


        if (flags & O_SYNC) {
                desired_access |= SMB2_SYNCHRONIZE;
                create_options |= SMB2_FILE_NO_INTERMEDIATE_BUFFERING;
        }

        memset(&req, 0, sizeof(struct smb2_create_request));
        req.struct_size = SMB2_CREATE_REQUEST_SIZE;
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        req.desired_access = desired_access;
        req.file_attributes = file_attributes;
        req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        req.create_disposition = create_disposition;
        req.create_options = create_options;
        req.name_offset = 0x78;
        req.name = path;

        if (smb2_cmd_create_async(smb2, &req, open_cb, fh) < 0) {
                smb2_set_error(smb2, "Failed to send create command");
                return -ENOMEM;
        }

        return 0;
}

static void
close_cb(struct smb2_context *smb2, int status,
         void *command_data, void *private_data)
{
        struct smb2fh *fh = private_data;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Close failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                fh->cb(smb2, -nterror_to_errno(status), NULL, fh->cb_data);
                free_smb2fh(fh);
                return;
        }

        fh->cb(smb2, 0, NULL, fh->cb_data);
        free_smb2fh(fh);
}
        
int smb2_close_async(struct smb2_context *smb2, struct smb2fh *fh,
                     smb2_command_cb cb, void *cb_data)
{
        struct smb2_close_request req;

        fh->cb = cb;
        fh->cb_data = cb_data;

        memset(&req, 0, sizeof(struct smb2_close_request));
        req.struct_size = SMB2_CLOSE_REQUEST_SIZE;
        req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
        memcpy(req.file_id, fh->file_id, SMB2_FD_SIZE);

        if (smb2_cmd_close_async(smb2, &req, close_cb, fh) < 0) {
                smb2_set_error(smb2, "Failed to send close command");
                return -ENOMEM;
        }

        return 0;
}

struct read_data {
        smb2_command_cb cb;
        void *cb_data;

        struct smb2fh *fh;
        uint64_t offset;
};

static void
read_cb(struct smb2_context *smb2, int status,
         void *command_data, void *private_data)
{
        struct read_data *rd = private_data;
        struct smb2_read_reply *rep = command_data;

        if (status && status != SMB2_STATUS_END_OF_FILE) {
                smb2_set_error(smb2, "Read failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                rd->cb(smb2, -nterror_to_errno(status), NULL, rd->cb_data);
                free(rd);
                return;
        }

        if (status == SMB2_STATUS_SUCCESS) {
                rd->fh->offset = rd->offset + rep->data_length;
        }

        rd->cb(smb2, rep->data_length, NULL, rd->cb_data);
        free(rd);
}

int smb2_pread_async(struct smb2_context *smb2, struct smb2fh *fh,
                     char *buf, uint32_t count, uint64_t offset,
                     smb2_command_cb cb, void *cb_data)
{
        struct smb2_read_request req;
        struct read_data *rd;

        rd = malloc(sizeof(struct read_data));
        if (rd == NULL) {
                smb2_set_error(smb2, "Failed to allocate read_data");
                return -ENOMEM;
        }
        memset(rd, 0, sizeof(struct read_data));
                
        rd->cb = cb;
        rd->cb_data = cb_data;
        rd->fh = fh;
        rd->offset = offset;

        memset(&req, 0, sizeof(struct smb2_read_request));
        req.struct_size = SMB2_READ_REQUEST_SIZE;
        req.flags = 0;
        req.length = count;
        req.offset = offset;
        req.buf = buf;
        memcpy(req.file_id, fh->file_id, SMB2_FD_SIZE);
        req.minimum_count = 0;
        req.channel = SMB2_CHANNEL_NONE;
        req.remaining_bytes = 0;
        req.read_channel_info_offset = 0;
        req.read_channel_info = NULL;

        if (smb2_cmd_read_async(smb2, &req, read_cb, rd) < 0) {
                smb2_set_error(smb2, "Failed to send read command");
                return -ENOMEM;
        }

        return 0;
}        

int smb2_read_async(struct smb2_context *smb2, struct smb2fh *fh,
                     char *buf, uint32_t count,
                     smb2_command_cb cb, void *cb_data)
{
        return smb2_pread_async(smb2, fh, buf, count, fh->offset,
                                cb, cb_data);
}

int smb2_lseek(struct smb2_context *smb2, struct smb2fh *fh,
               int64_t offset, int whence)
{
        switch(whence) {
        case SEEK_SET:
                if (offset < 0) {
                        smb2_set_error(smb2, "Lseek() offset would become"
                                       "negative");
                        return -EINVAL;
                }
                fh->offset = offset;
                return fh->offset;
        case SEEK_CUR:
                if (fh->offset + offset < 0) {
                        smb2_set_error(smb2, "Lseek() offset would become"
                                       "negative");
                        return -EINVAL;
                }
                fh->offset += offset;
                return fh->offset;
        case SEEK_END:
                smb2_set_error(smb2, "SEEK_END not implemented");
                return -EINVAL;
        default:
                smb2_set_error(smb2, "Invalid whence(%d) for lseek",
                               whence);
                return -EINVAL;
        }
}
