/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2020 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <inttypes.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-dcerpc.h"
#include "libsmb2-dcerpc-srvsvc.h"

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

int is_finished;
struct dcerpc_service *service;
uint8_t buf[65536];
struct smb2_iovec iov = {buf, sizeof(buf), NULL};
int offset;


struct rpc_cb_data {
        struct dcerpc_procedure *proc;
        void *req;
        struct dcerpc_pdu *req_pdu;
        void *rep;
        struct dcerpc_pdu *rep_pdu;
};

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "dcerpc <smb2-url> request.yaml\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/IPC$/<service-name>\n");
        exit(1);
}

void si_cb(struct dcerpc_context *dce, int status,
                void *command_data, void *cb_data)
{
        struct rpc_cb_data *rpc_cb_data = cb_data;
        int offset;

        offset = 0;
        memset(buf, 0, sizeof(buf));

        printf("YAML:\n");
        printf("---\n");
        rpc_cb_data->rep = command_data;
        rpc_cb_data->rep_pdu = dcerpc_allocate_pdu(dce, ENCODING_YAML, DCERPC_ENCODE, rpc_cb_data->proc->rep_size);
        if (rpc_cb_data->rep_pdu == NULL) {
                printf("failed to allocate Response pdu\n");
                exit(10);
        }
        
        /* We might need to reference req from the reply */
        dcerpc_set_request(rpc_cb_data->rep_pdu, rpc_cb_data->req);
        if (dcerpc_do_coder(rpc_cb_data->proc->name, dce, rpc_cb_data->rep_pdu, &iov, &offset, rpc_cb_data->rep, rpc_cb_data->proc->rep_coder)) {
                printf("Failed to encode REP as YAML\n");
                exit(10);
        }
        printf("%s\n", iov.buf);

        
        free(rpc_cb_data->req);
        dcerpc_free_pdu(dce, rpc_cb_data->req_pdu);
        dcerpc_free_data(dce, rpc_cb_data->rep);
        dcerpc_free_pdu(dce, rpc_cb_data->rep_pdu);
        
        free(rpc_cb_data);

        is_finished = 1;
}

void co_cb(struct dcerpc_context *dce, int status,
           void *command_data, void *cb_data)
{
        int i;
        char *name;
        struct rpc_cb_data *rpc_cb_data;

        if (status != SMB2_STATUS_SUCCESS) {
                printf("failed to connect to SRVSVC (%s) %s\n",
                       strerror(-status), dcerpc_get_error(dce));
                exit(10);
        }

        rpc_cb_data = calloc(1, sizeof(*rpc_cb_data));
        if (rpc_cb_data == NULL) {
                printf("Failed to allocate rpc_cb_data structure\n");
                exit(9);
        }
        
        /* Find the name of the procedure */
        name = (char *)&iov.buf[offset];
        while (offset < iov.len && iov.buf[offset] != ':') {
                offset++;
        }
        for (i = 0; service->procs[i].name; i++) {
                if (!strncmp(name, service->procs[i].name, offset)) {
                        rpc_cb_data->proc = &service->procs[i];
                        break;
                }
        }
        offset = 0;

        if (rpc_cb_data->proc == NULL) {
                printf("Could not find a procedure with the name %s\n", name);
                exit(9);
        }

        rpc_cb_data->req = calloc(1, rpc_cb_data->proc->req_size);
        if (rpc_cb_data->req == NULL) {
                printf("failed to allocate Request structure\n");
                exit(10);
        }

        rpc_cb_data->req_pdu = dcerpc_allocate_pdu(dce, ENCODING_YAML, DCERPC_DECODE, rpc_cb_data->proc->req_size);
        if (rpc_cb_data->req_pdu == NULL) {
                printf("Failed to allocate request PDU\n");
                exit(9);
        }
        if (dcerpc_do_coder(rpc_cb_data->proc->name, dce, rpc_cb_data->req_pdu, &iov, &offset, rpc_cb_data->req, rpc_cb_data->proc->req_coder)) {
                printf("Failed to decode REQ from YAML\n");
                exit(10);
        }

        if (dcerpc_call_async(dce,
                              rpc_cb_data->proc->opnum,
                              rpc_cb_data->proc->req_coder, rpc_cb_data->req,
                              rpc_cb_data->proc->rep_coder, rpc_cb_data->proc->rep_size,
                              si_cb, rpc_cb_data) != 0) {
                printf("dcerpc_call_async failed with %s\n",
                       dcerpc_get_error(dce));
                exit(10);
        }
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct dcerpc_context *dce;
        struct smb2_url *url;
	struct pollfd pfd;
        int i, fd;

        if (argc < 2) {
                usage();
        }

        if (argc < 3) {
                read(0, iov.buf, iov.len);
        } else {
                fd = open(argv[2], O_RDONLY);
                if (fd == -1) {
                        printf("Failed to open yaml file : %s\n", argv[2]);
                        exit(9);
                }
                read(fd, iov.buf, iov.len);
                close(fd);
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
        if (url->user) {
                smb2_set_user(smb2, url->user);
        }

        smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

        if (smb2_connect_share(smb2, url->server, url->share, NULL) < 0) {
		printf("Failed to connect to IPC$. %s\n",
                       smb2_get_error(smb2));
		exit(10);
        }

        dce = dcerpc_create_context(smb2);
        if (dce == NULL) {
		printf("Failed to create dce context. %s\n",
                       smb2_get_error(smb2));
		exit(10);
        }

        for (i = 0; dcerpc_services[i].name; i++) {
                service = &dcerpc_services[i];
                if (!strcmp(service->name, url->path)) {
                        break;
                }
        }
        if (service->name == NULL) {
                printf("Could not find a service with the name %s\n", url->path);
                exit(10);
        }
        
        if (dcerpc_connect_context_async(dce, url->path, service->interface,
                       co_cb, NULL) != 0) {
		printf("Failed to connect dce context. %s\n",
                       smb2_get_error(smb2));
		exit(10);
        }

        while (!is_finished) {
		pfd.fd = smb2_get_fd(smb2);
		pfd.events = smb2_which_events(smb2);

		if (poll(&pfd, 1, 1000) < 0) {
			printf("Poll failed");
			exit(10);
		}
                if (pfd.revents == 0) {
                        continue;
                }
		if (smb2_service(smb2, pfd.revents) < 0) {
			printf("smb2_service failed with : %s\n",
                               smb2_get_error(smb2));
			break;
		}
	}

        dcerpc_destroy_context(dce);
        smb2_disconnect_share(smb2);
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);
        
	return 0;
}
