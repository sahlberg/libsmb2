/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-ls-sync <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>/<share>/<path>\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        struct smb2dir *dir;
        struct smb2dirent *ent;

        if (argc < 2) {
                usage();
        }
        
	smb2 = smb2_init_context();
        if (smb2 == NULL) {
                fprintf(stderr, "Failed to init context\n");
                exit(0);
        }

        url = smb2_parse_url(smb2, argv[1]);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n",
                        smb2_get_error(smb2));
                exit(0);
        }
                
        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

	if (smb2_connect_share(smb2, url->server, url->share) < 0) {
		printf("smb2_connect_share failed. %s\n", smb2_get_error(smb2));
		exit(10);
	}

	dir = smb2_opendir(smb2, url->path);
	if (dir == NULL) {
		printf("smb2_opendir failed. %s\n", smb2_get_error(smb2));
		exit(10);
	}

        while (ent = smb2_readdir(smb2, dir)) {
                printf("%s ", ent->name);

                printf("[");
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_READONLY) {
                        printf("READ-ONLY,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_HIDDEN) {
                        printf("HIDDEN,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_SYSTEM) {
                        printf("SYSTEM,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY) {
                        printf("DIRECTORY,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_ARCHIVE) {
                        printf("ARCHIVE,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_NORMAL) {
                        printf("NORMAL,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_TEMPORARY) {
                        printf("TEMPORARY,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_SPARSE_FILE) {
                        printf("SPARSE_FILE,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_REPARSE_POINT) {
                        printf("REPARSE_POINT,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_COMPRESSED) {
                        printf("COMPRESSED,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_OFFLINE) {
                        printf("OFFLINE,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) {
                        printf("NOT_CONTENT_INDEXED,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_ENCRYPTED) {
                        printf("ENCREYPTED,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_INTEGRITY_STREAM) {
                        printf("INTEGRITY_STREAM,");
                }
                if (ent->file_attributes & SMB2_FILE_ATTRIBUTE_NO_SCRUB_DATA) {
                        printf("NO_SCRUP_DATA,");
                }
                printf("]");
                
                printf("\n");
        }

        smb2_closedir(smb2, dir);
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);
        
	return 0;
}
