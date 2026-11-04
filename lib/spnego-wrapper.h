/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifndef SPEGNO_WRAPPER_H
#define SPEGNO_WRAPPER_H 1

/*
   Copyright (C) 2024 by Brian Dodge <bdodge09@gmail.com>
   Copyright (C) 2024 by André Guilherme <andregui17@outlook.com>

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

#ifdef __cplusplus
extern "C" {
#endif

#define SPNEGO_MECHANISM_KRB5       (0x0001)
#define SPNEGO_MECHANISM_NTLMSSP    (0x0002)
#define SPNEGO_MECHANISM_OTHER      (0x0004)
#define SPNEGO_MECHANISM_IAKERB     (0x0008)

int smb2_spnego_create_negotiate_reply_blob(struct smb2_context *smb2,
                int allow_ntlmssp,
                void **neg_init_token);

int smb2_spnego_wrap_gssapi(struct smb2_context *smb2,
                const uint8_t *ntlmssp_token,
                const int token_len,
                void **blob);

/* NegTokenInit whose only mech is IAKerb (1.3.6.1.5.2.5). mech_token is
 * the GSS initial context token from gss_mech_iakerb. */
int smb2_spnego_wrap_iakerb_init(struct smb2_context *smb2,
                const uint8_t *mech_token,
                const int token_len,
                void **blob);

/* Initiator negTokenResp carrying the next IAKerb mechanism token. */
int smb2_spnego_wrap_iakerb_resp(struct smb2_context *smb2,
                const uint8_t *mech_token,
                const int token_len,
                void **blob);

/* Points *mic at the mechListMIC of a negTokenResp. Returns its length,
 * 0 if there is none, or -EINVAL. */
int smb2_spnego_find_mech_list_mic(struct smb2_context *smb2,
                const uint8_t *spnego,
                const int spnego_len,
                const uint8_t **mic);

/* negState of a negTokenResp, -ENOENT if it has none, -EINVAL if it
 * is malformed. */
int smb2_spnego_get_neg_state(struct smb2_context *smb2,
                const uint8_t *spnego,
                const int spnego_len);

/* Initiator negTokenResp carrying only the mechListMIC. */
int smb2_spnego_wrap_mic_resp(struct smb2_context *smb2,
                const uint8_t *mic,
                const int mic_len,
                void **blob);

/* Acceptor negTokenResp: negState, then supportedMech IAKerb, the
 * responseToken and the mechListMIC when given. */
int smb2_spnego_wrap_acceptor_resp(struct smb2_context *smb2,
                const int neg_state,
                const int supported_mech_iakerb,
                const uint8_t *mech_token, const int token_len,
                const uint8_t *mic, const int mic_len,
                void **blob);

/* If the negTokenInit's preferred mech is IAKerb, points *token at its
 * mechToken and returns the length. *mech_types is the DER MechTypeList
 * the mechListMIC covers. Returns 0 if IAKerb is not preferred or there
 * is no mechToken, -EINVAL on a malformed token. */
int smb2_spnego_unwrap_iakerb_init(struct smb2_context *smb2,
                const uint8_t *spnego, const int spnego_len,
                const uint8_t **mech_types, int *mech_types_len,
                const uint8_t **token);

int smb2_spnego_unwrap_targ(struct smb2_context *smb2,
                const uint8_t *spnego, const int spnego_len,
                uint8_t **token, uint32_t *mechanisms);

int smb2_spnego_wrap_ntlmssp_challenge(struct smb2_context *smb2,
                const uint8_t *ntlmssp_token,
                const int token_len, const int supported_mech,
                void **neg_targ_token);

int smb2_spnego_wrap_ntlmssp_auth(struct smb2_context *smb2,
                const uint8_t *ntlmssp_token,
                const int token_len, void **neg_targ_token);

int smb2_spnego_wrap_authenticate_result(struct smb2_context *smb2,
                const int authorized_ok,
                const uint8_t *mic, const int mic_len, void **blob);

/* Acceptor negTokenResp choosing NTLMSSP when it is not the initiator's
 * preferred mech: accept-incomplete, supportedMech, no token. */
int smb2_spnego_select_ntlmssp(struct smb2_context *smb2, void **blob);

/* The mechs of a negTokenInit: the initiator's preferred one, the set of
 * all of them (SPNEGO_MECHANISM_*) and the DER MechTypeList that the
 * mechListMIC covers. -EINVAL if it is not a negTokenInit. */
int smb2_spnego_parse_mech_types(struct smb2_context *smb2,
                const uint8_t *spnego, const int spnego_len,
                uint32_t *first_mech, uint32_t *mechanisms,
                const uint8_t **mech_types, int *mech_types_len);

int smb2_spnego_unwrap_gssapi(struct smb2_context *smb2,
                const uint8_t *spnego, const int spnego_len,
                const int suppress_errors,
                uint8_t **token, uint32_t *mechanisms);

int smb2_spnego_unwrap_blob(struct smb2_context *smb2,
                const uint8_t *spnego,
                const int spnego_len,
                const int suppress_errors,
                uint8_t **response_token,
                uint32_t *mechanisms);

#ifdef __cplusplus
}
#endif

#endif /* SPEGNO_WRAPPER_H */

