/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _DCERPC_SERVER_H_
#define _DCERPC_SERVER_H_

/*
 * The server side of connection-oriented DCE/RPC over a named pipe,
 * without the transport: the caller moves the bytes. Whatever carries the
 * pipe (an SMB2 server, a kernel upcall, a test) creates a
 * dcerpc_server_pipe when a client opens the pipe, passes everything the
 * client writes to dcerpc_server_pipe_write() and answers its reads with
 * dcerpc_server_pipe_read().
 *
 * The runtime does BIND and ALTER_CONTEXT, with one presentation context
 * per interface and transfer syntax (NDR32 or NDR64, in either byte
 * order, as each interface allows) and bind time feature negotiation;
 * reassembles fragmented REQUESTs; dispatches them; and fragments the
 * RESPONSEs to the negotiated size. Replies are little-endian, as
 * Windows sends them. Authentication trailers are ignored.
 *
 * An interface is served either from its IDL coders and a table of stub
 * implementations (dcerpc_server_add_interface()), which decode the
 * request, call the stub and encode the reply, or by a raw dispatcher that
 * gets the request stub bytes and may answer later
 * (dcerpc_server_add_raw_interface()).
 *
 * None of this is thread-safe; use a server and its pipes from one thread.
 * It does not need libsmb2.
 */

#include <stddef.h>
#include <stdint.h>

#include <dcerpc/dcerpc.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dcerpc_server;
struct dcerpc_server_pipe;
struct dcerpc_server_call;

/* NDR flavors an interface accepts */
#define DCERPC_SERVER_NDR32_LE   0x00000001U
#define DCERPC_SERVER_NDR32_BE   0x00000002U
#define DCERPC_SERVER_NDR64_LE   0x00000004U
#define DCERPC_SERVER_NDR64_BE   0x00000008U
#define DCERPC_SERVER_ALL_NDR    0x0000000fU

/* FAULT status codes ([C706] Appendix E, [MS-RPCE] 2.2.2.11) */
#define DCERPC_FAULT_OTHER            0x00000001U
#define DCERPC_FAULT_ACCESS_DENIED    0x00000005U
#define DCERPC_FAULT_NDR              0x000006f7U
#define DCERPC_FAULT_CONTEXT_MISMATCH 0x1c00001aU
#define DCERPC_FAULT_OP_RNG_ERROR     0x1c010002U
#define DCERPC_FAULT_UNK_IF           0x1c010003U
#define DCERPC_FAULT_PROTO_ERROR      0x1c01000bU

/*
 * Raw dispatcher for an interface: called for every complete REQUEST.
 * The call must be finished, now or later, with exactly one of
 * dcerpc_server_call_reply() and dcerpc_server_call_fault(), which free
 * it. Return 0, or -1 to fault the call with DCERPC_FAULT_OTHER (only if
 * it has not been finished).
 */
typedef int (*dcerpc_server_dispatch_fn)(struct dcerpc_server_call *call,
                                         void *private_data);

/*
 * An endpoint: the interfaces served on the named pipe pipe_name (e.g.
 * "lsarpc"), which BIND_ACK names as \PIPE\<pipe_name>.
 */
struct dcerpc_server *dcerpc_server_create(const char *pipe_name);
/* All pipes of srv must have been destroyed. */
void dcerpc_server_destroy(struct dcerpc_server *srv);
/*
 * Never send fragments larger than max bytes (rounded down to a multiple
 * of 8), whatever the client's BIND allows: for a transport that carries
 * at most that much per read. Returns -1 if max is too small for a
 * RESPONSE with any stub.
 */
int dcerpc_server_set_max_xmit_frag(struct dcerpc_server *srv, uint16_t max);

/* How much a log message matters */
#define DCERPC_SERVER_LOG_ERROR  0  /* bad input, or the server failed */
#define DCERPC_SERVER_LOG_INFO   1  /* a client asked for what isn't served */
#define DCERPC_SERVER_LOG_DEBUG  2  /* every BIND result and every call,
                                       with each request and reply as a
                                       hex dump and as YAML */

/*
 * Called with each message the endpoint logs, up to level: one line,
 * without a newline, starting with the pipe name. Messages above level
 * are not even built, so only ask for DCERPC_SERVER_LOG_DEBUG when they
 * are wanted. Without a log function nothing is logged.
 */
typedef void (*dcerpc_server_log_fn)(void *private_data, int level,
                                     const char *msg);
void dcerpc_server_set_log(struct dcerpc_server *srv, int level,
                           dcerpc_server_log_fn fn, void *private_data);
const char *dcerpc_server_get_pipe_name(struct dcerpc_server *srv);

/*
 * Serve interface with its coders (procs, e.g. lsa_procs) and stubs, a
 * table terminated by an entry with a NULL name. A stub gets the decoded
 * request and a zeroed reply to fill; it allocates what the reply points
 * to with dcerpc_alloc_data(pdu, ...), and finds its call with
 * dcerpc_pdu_server_call(pdu). It returns 0 to send the reply, a FAULT
 * status (DCERPC_FAULT_*) to send that instead, or -1 for
 * DCERPC_FAULT_OTHER. Opnums without a stub are faulted with
 * DCERPC_FAULT_OP_RNG_ERROR.
 *
 * flavors is a DCERPC_SERVER_* mask. Returns 0, or -1 if the interface is
 * already served.
 */
int dcerpc_server_add_interface(struct dcerpc_server *srv,
                                const p_syntax_id_t *interface,
                                const struct dcerpc_procedure *procs,
                                const struct dcerpc_stub *stubs,
                                uint32_t flavors);
int dcerpc_server_add_raw_interface(struct dcerpc_server *srv,
                                    const p_syntax_id_t *interface,
                                    dcerpc_server_dispatch_fn fn,
                                    void *private_data,
                                    uint32_t flavors);

/* A client's open of the pipe. private_data is the caller's. */
struct dcerpc_server_pipe *dcerpc_server_pipe_create(struct dcerpc_server *srv,
                                                     void *private_data);
/*
 * Calls still in flight are detached: they must still be finished, but
 * their reply is dropped.
 */
void dcerpc_server_pipe_destroy(struct dcerpc_server_pipe *pipe);
void *dcerpc_server_pipe_get_private(struct dcerpc_server_pipe *pipe);
struct dcerpc_server *dcerpc_server_pipe_get_server(struct dcerpc_server_pipe *pipe);

/*
 * Bytes the client wrote. Every complete PDU is processed (and every
 * complete REQUEST dispatched) before this returns; a partial PDU is kept
 * for the next write. Returns -1, and drops what was buffered, if the
 * stream is not DCE/RPC.
 */
int dcerpc_server_pipe_write(struct dcerpc_server_pipe *pipe,
                             const uint8_t *buf, size_t len);
/*
 * The next pipe message for a client read: up to max bytes of the
 * current fragment. Returns the number of bytes copied, 0 when there is
 * no output. *more is set when the fragment did not fit and the rest is
 * returned by the next read (STATUS_BUFFER_OVERFLOW for SMB2).
 */
size_t dcerpc_server_pipe_read(struct dcerpc_server_pipe *pipe,
                               uint8_t *buf, size_t max, int *more);
int dcerpc_server_pipe_has_output(struct dcerpc_server_pipe *pipe);
/* Calls dispatched but not yet finished */
int dcerpc_server_pipe_calls_pending(struct dcerpc_server_pipe *pipe);

/* The call's request */
uint16_t dcerpc_server_call_opnum(struct dcerpc_server_call *call);
const p_syntax_id_t *dcerpc_server_call_interface(struct dcerpc_server_call *call);
const uint8_t *dcerpc_server_call_stub(struct dcerpc_server_call *call,
                                       size_t *len);
/* NDR flavor of the request stub: DCERPC_NDR64 and/or DCERPC_BIG_ENDIAN */
uint32_t dcerpc_server_call_flags(struct dcerpc_server_call *call);
/* NDR flavor the reply stub must be in: little-endian, DCERPC_NDR64 or 0 */
uint32_t dcerpc_server_call_reply_flags(struct dcerpc_server_call *call);
/* NULL once the pipe has been destroyed */
struct dcerpc_server_pipe *dcerpc_server_call_get_pipe(struct dcerpc_server_call *call);

/*
 * Finish a call with a reply stub (in dcerpc_server_call_reply_flags()
 * NDR) or a FAULT, and free it. The output is queued on the pipe unless
 * the pipe is gone. Return 0, or -1 if it could not be queued.
 */
int dcerpc_server_call_reply(struct dcerpc_server_call *call,
                             const uint8_t *stub, size_t len);
int dcerpc_server_call_fault(struct dcerpc_server_call *call,
                             uint32_t status);

#ifdef __cplusplus
}
#endif

#endif /* !_DCERPC_SERVER_H_ */
