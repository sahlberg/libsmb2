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

/* Response encoding: YAML (default) or JSON via -j/--json */
enum dcerpc_encoding output_encoding = ENCODING_YAML;

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
                "dcerpc [-j|--json] <smb2-url> [request.yaml]\n\n"
                "  -j, --json   Encode responses as JSON instead of YAML\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>[:<port>]/IPC$/<service-name>\n"
                "Request file is YAML (or stdin if omitted). Multiple requests\n"
                "in one file are separated by a line consisting of only ---.\n");
        exit(1);
}

/*
 * Look up a scalar field "name" in a response encoded as YAML or JSON.
 * YAML:  "name: value" (optional list prefix "- ")
 * JSON:  "\"name\": value" or "\"name\": \"value\""
 * Returns a newly allocated string with the value, or NULL if not found.
 * Nested keys with an empty value after the colon are skipped.
 */
static char *
lookup_response_field(const char *text, const char *name)
{
        const char *p = text;
        size_t name_len = strlen(name);

        while (*p) {
                const char *line = p;
                const char *eol;
                const char *colon;
                const char *key;
                const char *val;
                size_t key_len, val_len;

                eol = strchr(p, '\n');
                if (eol == NULL) {
                        eol = p + strlen(p);
                }

                while (line < eol && (*line == ' ' || *line == '\t')) {
                        line++;
                }
                /* optional YAML list prefix */
                if (line + 1 < eol && line[0] == '-' && line[1] == ' ') {
                        line += 2;
                        while (line < eol && *line == ' ') {
                                line++;
                        }
                }
                /* optional trailing comma from JSON */
                /* handled when trimming the value below */

                colon = memchr(line, ':', eol - line);
                if (colon && colon > line) {
                        key = line;
                        key_len = (size_t)(colon - line);
                        /* JSON keys are quoted: "name" */
                        if (key_len >= 2 && key[0] == '"' &&
                            key[key_len - 1] == '"') {
                                key++;
                                key_len -= 2;
                        }
                        if (key_len == name_len && !memcmp(key, name, key_len)) {
                                val = colon + 1;
                                while (val < eol && *val == ' ') {
                                        val++;
                                }
                                val_len = (size_t)(eol - val);
                                while (val_len > 0 &&
                                       (val[val_len - 1] == '\r' ||
                                        val[val_len - 1] == ' ' ||
                                        val[val_len - 1] == ',')) {
                                        val_len--;
                                }
                                /* JSON string value: strip surrounding quotes */
                                if (val_len >= 2 && val[0] == '"' &&
                                    val[val_len - 1] == '"') {
                                        val++;
                                        val_len -= 2;
                                }
                                if (val_len > 0) {
                                        char *ret = malloc(val_len + 1);

                                        if (ret == NULL) {
                                                return NULL;
                                        }
                                        memcpy(ret, val, val_len);
                                        ret[val_len] = '\0';
                                        return ret;
                                }
                        }
                }

                if (*eol == '\0') {
                        break;
                }
                p = eol + 1;
        }

        return NULL;
}

/*
 * Parse a placeholder body as either "name" or "name:-N".
 * @name@        -> field name, 1 step back (previous reply)
 * @name:-N@     -> field name, N steps back (N >= 1)
 *
 * Returns 0 on success, -1 if the body is not a valid placeholder form.
 */
static int
parse_placeholder(const char *body, size_t body_len,
                  char *name, size_t name_size, int *steps_back)
{
        size_t i, j, name_len;
        int n;
        int all_digits;

        if (body_len == 0 || body_len >= name_size) {
                return -1;
        }

        /* Default: previous reply */
        *steps_back = 1;
        name_len = body_len;

        /*
         * Optional relative form: name:-N  (N is a positive decimal integer).
         * Find ":-" followed only by digits through the end of the body.
         */
        for (i = 0; i + 2 < body_len; i++) {
                if (body[i] != ':' || body[i + 1] != '-') {
                        continue;
                }
                if (i == 0) {
                        /* empty field name before ":-" */
                        return -1;
                }
                all_digits = 1;
                for (j = i + 2; j < body_len; j++) {
                        if (body[j] < '0' || body[j] > '9') {
                                all_digits = 0;
                                break;
                        }
                }
                if (!all_digits || i + 2 >= body_len) {
                        /*
                         * Not the relative-index form (e.g. a name that
                         * happens to contain ":-"); keep scanning.
                         */
                        continue;
                }
                name_len = i;
                n = 0;
                for (j = i + 2; j < body_len; j++) {
                        n = n * 10 + (body[j] - '0');
                        if (n > MAXOPDATA) {
                                return -1;
                        }
                }
                if (n < 1) {
                        return -1;
                }
                *steps_back = n;
                break;
        }

        memcpy(name, body, name_len);
        name[name_len] = '\0';
        return 0;
}

/*
 * Replace placeholders in the request YAML with scalar values from earlier
 * response YAMLs:
 *   @name@      - value of "name" from the previous reply (idx - 1)
 *   @name:-n@   - value of "name" from the reply n steps back (idx - n)
 *
 * cur_idx is the index of the request being prepared; responses for
 * completed ops 0 .. cur_idx-1 live in opdata[].buf.
 */
static int
apply_response_substitutions(struct opdata *req, int cur_idx)
{
        uint8_t tmp[sizeof(req->buf)];
        size_t out_len = 0;
        const char *src = (const char *)req->buf;
        const char *at1, *at2;

        while ((at1 = strchr(src, '@')) != NULL) {
                size_t body_len, value_len, chunk;
                char name[256];
                char *value;
                int steps_back;
                int src_idx;
                const char *yaml;

                at2 = strchr(at1 + 1, '@');
                if (at2 == NULL) {
                        break;
                }

                body_len = (size_t)(at2 - (at1 + 1));
                if (body_len == 0 || body_len >= sizeof(name) ||
                    memchr(at1 + 1, '\n', body_len) != NULL) {
                        /* Not a valid placeholder; copy through first '@' */
                        chunk = (size_t)(at1 - src) + 1;
                        if (out_len + chunk >= sizeof(tmp)) {
                                printf("YAML too large after substitution\n");
                                return -1;
                        }
                        memcpy(tmp + out_len, src, chunk);
                        out_len += chunk;
                        src = at1 + 1;
                        continue;
                }
                if (parse_placeholder(at1 + 1, body_len, name, sizeof(name),
                                       &steps_back)) {
                        printf("Invalid placeholder @%.*s@\n",
                               (int)body_len, at1 + 1);
                        return -1;
                }

                chunk = (size_t)(at1 - src);
                if (out_len + chunk >= sizeof(tmp)) {
                        printf("YAML too large after substitution\n");
                        return -1;
                }
                memcpy(tmp + out_len, src, chunk);
                out_len += chunk;

                if (steps_back > cur_idx) {
                        printf("No response %d steps back for @%s@ "
                               "(only %d previous response%s)\n",
                               steps_back, name, cur_idx,
                               cur_idx == 1 ? "" : "s");
                        return -1;
                }
                src_idx = cur_idx - steps_back;
                yaml = (const char *)opdata[src_idx].buf;

                value = lookup_response_field(yaml, name);
                if (value == NULL) {
                        if (steps_back == 1) {
                                printf("No value for @%s@ in previous "
                                       "response\n", name);
                        } else {
                                printf("No value for @%s:-%d@ in response "
                                       "%d steps back\n",
                                       name, steps_back, steps_back);
                        }
                        return -1;
                }
                value_len = strlen(value);
                if (out_len + value_len >= sizeof(tmp)) {
                        free(value);
                        printf("YAML too large after substitution\n");
                        return -1;
                }
                memcpy(tmp + out_len, value, value_len);
                out_len += value_len;
                free(value);

                src = at2 + 1;
        }

        {
                size_t chunk = strlen(src);

                if (out_len + chunk >= sizeof(tmp)) {
                        printf("YAML too large after substitution\n");
                        return -1;
                }
                memcpy(tmp + out_len, src, chunk);
                out_len += chunk;
        }
        tmp[out_len] = '\0';

        memcpy(req->buf, tmp, out_len + 1);
        return 0;
}

void do_request(struct dcerpc_context *dce);

void si_cb(struct dcerpc_context *dce, int status,
                void *command_data, void *cb_data)
{
        struct rpc_cb_data *rpc_cb_data = cb_data;

        opdata[idx].offset = 0;
        memset(opdata[idx].iov.buf, 0, opdata[idx].iov.len);

        if (command_data == NULL) {
                printf("No Response pdu (status=%d) %s\n",
                       status, dcerpc_get_error(dce));
                exit(10);
        }
        
        if (output_encoding == ENCODING_JSON) {
                printf("JSON:\n");
        } else {
                printf("YAML:\n");
                printf("---\n");
        }
        rpc_cb_data->rep = command_data;
        rpc_cb_data->rep_pdu = dcerpc_allocate_pdu(dce, output_encoding, DCERPC_ENCODE, rpc_cb_data->proc->rep_size);
        if (rpc_cb_data->rep_pdu == NULL) {
                printf("failed to allocate Response pdu\n");
                exit(10);
        }
        
        /* We might need to reference req from the reply */
        dcerpc_set_request(rpc_cb_data->rep_pdu, rpc_cb_data->req);
        if (dcerpc_do_coder(rpc_cb_data->proc->name, dce, rpc_cb_data->rep_pdu,
                            &opdata[idx].iov, &opdata[idx].offset,
                            rpc_cb_data->rep, rpc_cb_data->proc->rep_coder)) {
                printf("Failed to encode REP as %s\n",
                       output_encoding == ENCODING_JSON ? "JSON" : "YAML");
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

        /*
         * If this is not the first request in the chain, replace any
         * @field@ / @field:-n@ placeholders with values from earlier
         * response YAMLs (still held in opdata[0 .. idx-1] after si_cb
         * encoded them).
         */
        if (idx > 0) {
                if (apply_response_substitutions(&opdata[idx], idx)) {
                        exit(9);
                }
        }

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
        int i, fd, count, argi;
        uint8_t tmp[65536];
        ssize_t n;
        char *start, *p, *sep;
        const char *smb_url;
        const char *yaml_path;

        for (i = 0; i < MAXOPDATA; i++) {
                opdata[i].iov.buf = &opdata[i].buf[0];
                opdata[i].iov.len = 65536;
        }

        /* Parse optional flags before positional arguments */
        argi = 1;
        while (argi < argc && argv[argi][0] == '-') {
                if (!strcmp(argv[argi], "-j") || !strcmp(argv[argi], "--json")) {
                        output_encoding = ENCODING_JSON;
                        argi++;
                } else if (!strcmp(argv[argi], "-h") || !strcmp(argv[argi], "--help")) {
                        usage();
                } else {
                        fprintf(stderr, "Unknown option: %s\n", argv[argi]);
                        usage();
                }
        }

        if (argi >= argc) {
                usage();
        }
        smb_url = argv[argi++];
        yaml_path = (argi < argc) ? argv[argi] : NULL;

        memset(tmp, 0, sizeof(tmp));
        if (yaml_path == NULL) {
                n = read(0, tmp, sizeof(tmp) - 1);
        } else {
                fd = open(yaml_path, O_RDONLY);
                if (fd == -1) {
                        printf("Failed to open yaml file : %s\n", yaml_path);
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

        url = smb2_parse_url(smb2, smb_url);
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
