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


int idx;
int num_ops;
struct opdata {
        uint8_t buf[65536];
        struct smb2_iovec iov;        
        int offset;
};
#define MAXOPDATA 16
struct opdata opdata[MAXOPDATA];

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

void do_request(struct dcerpc_context *dce);

void si_cb(struct dcerpc_context *dce, int status,
                void *command_data, void *cb_data)
{
        struct rpc_cb_data *rpc_cb_data = cb_data;

        opdata[idx].offset = 0;
        memset(opdata[idx].iov.buf, 0, opdata[idx].iov.len);

        if (command_data == NULL) {
                printf("No Response pdu\n");
                exit(10);
        }
        
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
        if (dcerpc_do_coder(rpc_cb_data->proc->name, dce, rpc_cb_data->rep_pdu,
                            &opdata[idx].iov, &opdata[idx].offset,
                            rpc_cb_data->rep, rpc_cb_data->proc->rep_coder)) {
                printf("Failed to encode REP as YAML\n");
                exit(10);
        }
        printf("%s\n", opdata[idx].iov.buf);

        
        free(rpc_cb_data->req);
        dcerpc_free_pdu(dce, rpc_cb_data->req_pdu);
        dcerpc_free_data(dce, rpc_cb_data->rep);
        dcerpc_free_pdu(dce, rpc_cb_data->rep_pdu);
        
        free(rpc_cb_data);

        idx++;
        if (idx < num_ops) {
                do_request(dce);
        } else {
                is_finished = 1;
        }
}

void do_request(struct dcerpc_context *dce)
{
        int i;
        char *name;
        struct rpc_cb_data *rpc_cb_data;

        rpc_cb_data = calloc(1, sizeof(*rpc_cb_data));
        if (rpc_cb_data == NULL) {
                printf("Failed to allocate rpc_cb_data structure\n");
                exit(9);
        }
        
        /* Find the name of the procedure */
        name = (char *)&opdata[idx].iov.buf[opdata[idx].offset];
        while (opdata[idx].offset < opdata[idx].iov.len && opdata[idx].iov.buf[opdata[idx].offset] != ':') {
                opdata[idx].offset++;
        }
        for (i = 0; service->procs[i].name; i++) {
                if (!strncmp(name, service->procs[i].name, opdata[idx].offset)) {
                        rpc_cb_data->proc = &service->procs[i];
                        break;
                }
        }
        opdata[idx].offset = 0;

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
        if (dcerpc_do_coder(rpc_cb_data->proc->name, dce, rpc_cb_data->req_pdu,
                            &opdata[idx].iov, &opdata[idx].offset,
                            rpc_cb_data->req, rpc_cb_data->proc->req_coder)) {
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

void co_cb(struct dcerpc_context *dce, int status,
           void *command_data, void *cb_data)
{
        if (status != SMB2_STATUS_SUCCESS) {
                printf("failed to connect to SRVSVC (%s) %s\n",
                       strerror(-status), dcerpc_get_error(dce));
                exit(10);
        }

        do_request(dce);
}

int main(int argc, char *argv[])
{
        struct smb2_context *smb2;
        struct dcerpc_context *dce;
        struct smb2_url *url;
	struct pollfd pfd;
        int i, fd, count;
        uint8_t tmp[65536];
        ssize_t n;
        char *start, *p, *sep;

        for (i = 0; i < MAXOPDATA; i++) {
                opdata[i].iov.buf = &opdata[i].buf[0];
                opdata[i].iov.len = 65536;
        }
        
        if (argc < 2) {
                usage();
        }

        memset(tmp, 0, sizeof(tmp));
        if (argc < 3) {
                n = read(0, tmp, sizeof(tmp) - 1);
        } else {
                fd = open(argv[2], O_RDONLY);
                if (fd == -1) {
                        printf("Failed to open yaml file : %s\n", argv[2]);
                        exit(9);
                }
                n = read(fd, tmp, sizeof(tmp) - 1);
                close(fd);
        }
        if (n < 0) {
                printf("Failed to read yaml\n");
                exit(9);
        }
        tmp[n] = '\0';

        /*
         * Split the yaml into one buffer per request.
         * Requests are separated by a line consisting of just "---".
         */
        count = 0;
        start = (char *)tmp;
        p = start;
        while (1) {
                size_t len;

                sep = NULL;
                for (; *p; p++) {
                        if ((p == (char *)tmp || p[-1] == '\n') &&
                            p[0] == '-' && p[1] == '-' && p[2] == '-' &&
                            (p[3] == '\n' || p[3] == '\0' ||
                             (p[3] == '\r' && (p[4] == '\n' || p[4] == '\0')))) {
                                sep = p;
                                break;
                        }
                }

                len = (sep ? sep : (char *)tmp + n) - start;
                while (len > 0 && (start[len - 1] == '\n' ||
                                   start[len - 1] == '\r')) {
                        len--;
                }
                while (len > 0 && (*start == '\n' || *start == '\r')) {
                        start++;
                        len--;
                }

                if (len > 0) {
                        if (count >= MAXOPDATA) {
                                printf("Too many yaml requests (max %d)\n",
                                       MAXOPDATA);
                                exit(9);
                        }
                        if (len >= sizeof(opdata[count].buf)) {
                                printf("Yaml request too large\n");
                                exit(9);
                        }
                        memcpy(opdata[count].buf, start, len);
                        opdata[count].buf[len] = '\0';
                        count++;
                }

                if (!sep) {
                        break;
                }

                /* Skip past the "---" line */
                p = sep + 3;
                if (*p == '\r') {
                        p++;
                }
                if (*p == '\n') {
                        p++;
                }
                start = p;
        }

        if (count == 0) {
                printf("No yaml requests found\n");
                exit(9);
        }
        num_ops = count;

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
        if (url->domain) {
                smb2_set_domain(smb2, url->domain);
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
