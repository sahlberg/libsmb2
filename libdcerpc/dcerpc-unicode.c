/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
 * UTF-8 <-> UTF-16LE conversion for the string coders, so that libdcerpc
 * does not need libsmb2 for it.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <dcerpc/dcerpc.h>
#include "dcerpc-private.h"

/*
 * Decode one code point from *s and advance *s past it.
 * Returns the code point, or -1 if the UTF-8 is not valid: a stray
 * continuation byte, a truncated or overlong sequence, a surrogate or a
 * value above U+10FFFF.
 */
static int32_t
utf8_next(const unsigned char **s)
{
        const unsigned char *p = *s;
        uint32_t cp, min;
        int n, i;

        if (p[0] < 0x80) {
                *s = p + 1;
                return p[0];
        }
        if ((p[0] & 0xe0) == 0xc0) {
                n = 1;
                cp = p[0] & 0x1f;
                min = 0x80;
        } else if ((p[0] & 0xf0) == 0xe0) {
                n = 2;
                cp = p[0] & 0x0f;
                min = 0x800;
        } else if ((p[0] & 0xf8) == 0xf0) {
                n = 3;
                cp = p[0] & 0x07;
                min = 0x10000;
        } else {
                return -1;
        }
        for (i = 1; i <= n; i++) {
                /* this also stops at the terminating NUL */
                if ((p[i] & 0xc0) != 0x80) {
                        return -1;
                }
                cp = (cp << 6) | (p[i] & 0x3f);
        }
        if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp < 0xe000)) {
                return -1;
        }
        *s = p + n + 1;
        return (int32_t)cp;
}

struct dcerpc_utf16_buf *
dcerpc_utf8_to_utf16(const char *utf8)
{
        const unsigned char *s = (const unsigned char *)utf8;
        struct dcerpc_utf16_buf *buf;
        size_t len = 0;
        int32_t cp;

        /* First pass validates and counts the UTF-16 code units */
        while (*s) {
                cp = utf8_next(&s);
                if (cp < 0) {
                        return NULL;
                }
                len += cp < 0x10000 ? 1 : 2;
        }

        buf = malloc(offsetof(struct dcerpc_utf16_buf, val) +
                     (len ? len : 1) * sizeof(uint16_t));
        if (buf == NULL) {
                return NULL;
        }
        buf->len = (int)len;

        s = (const unsigned char *)utf8;
        len = 0;
        while (*s) {
                cp = utf8_next(&s);
                if (cp < 0x10000) {
                        buf->val[len++] = htole16((uint16_t)cp);
                } else {
                        cp -= 0x10000;
                        buf->val[len++] = htole16(0xd800 | (cp >> 10));
                        buf->val[len++] = htole16(0xdc00 | (cp & 0x3ff));
                }
        }
        return buf;
}

/* Append code point cp as UTF-8 to out (if not NULL), return its length */
static size_t
utf8_put(char *out, uint32_t cp)
{
        if (cp < 0x80) {
                if (out) {
                        out[0] = (char)cp;
                }
                return 1;
        }
        if (cp < 0x800) {
                if (out) {
                        out[0] = (char)(0xc0 | (cp >> 6));
                        out[1] = (char)(0x80 | (cp & 0x3f));
                }
                return 2;
        }
        if (cp < 0x10000) {
                if (out) {
                        out[0] = (char)(0xe0 | (cp >> 12));
                        out[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
                        out[2] = (char)(0x80 | (cp & 0x3f));
                }
                return 3;
        }
        if (out) {
                out[0] = (char)(0xf0 | (cp >> 18));
                out[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
                out[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
                out[3] = (char)(0x80 | (cp & 0x3f));
        }
        return 4;
}

/*
 * Convert (or with out == NULL, measure) len UTF-16LE code units.
 * A surrogate that is not part of a pair becomes U+FFFD.
 */
static size_t
utf16_convert(char *out, const uint16_t *utf16, size_t len)
{
        size_t i, n = 0;
        uint32_t cp, lo;

        for (i = 0; i < len; i++) {
                uint16_t unit;

                /* the units may be unaligned when they point into a buffer */
                memcpy(&unit, &utf16[i], sizeof(unit));
                cp = le16toh(unit);
                if (cp >= 0xd800 && cp < 0xdc00 && i + 1 < len) {
                        memcpy(&unit, &utf16[i + 1], sizeof(unit));
                        lo = le16toh(unit);
                        if (lo >= 0xdc00 && lo < 0xe000) {
                                cp = 0x10000 + ((cp & 0x3ff) << 10) +
                                        (lo & 0x3ff);
                                i++;
                        } else {
                                cp = 0xfffd;
                        }
                } else if (cp >= 0xd800 && cp < 0xe000) {
                        cp = 0xfffd;
                }
                n += utf8_put(out ? out + n : NULL, cp);
        }
        return n;
}

char *
dcerpc_utf16_to_utf8(const uint16_t *utf16, size_t len)
{
        size_t n = utf16_convert(NULL, utf16, len);
        char *str;

        str = malloc(n + 1);
        if (str == NULL) {
                return NULL;
        }
        utf16_convert(str, utf16, len);
        str[n] = '\0';
        return str;
}
