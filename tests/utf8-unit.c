/* Offline UTF-8 regression checks; LGPL-2.1-or-later. */
#include <stdio.h>
#include <stdlib.h>
#include "../lib/unicode.c"

static int failures, checks;

static void check(int ok, const char *what)
{
        checks++;
        if (!ok) failures++;
        printf("%-4s %s\n", ok ? "ok" : "FAIL", what);
}

/* Independent reference: count 1 bits from bit 7 down to the first 0 bit. */
static int ref_leading_ones(unsigned v)
{
        int n = 0;
        for (int bit = 7; bit >= 0 && (v >> bit & 1u); bit--) n++;
        return n;
}

static void valid(const char *label, const char *utf8, const uint16_t *units, int n)
{
        struct smb2_utf16 *u = smb2_utf8_to_utf16(utf8);
        int ok = u && u->len == n;
        for (int i = 0; ok && i < n; i++) ok = le16toh(u->val[i]) == units[i];
        char what[160];
        snprintf(what, sizeof what, "valid %s -> exact UTF-16LE (%d unit%s)", label, n, n == 1 ? "" : "s");
        check(ok, what);
        free(u);
}

static void malformed(const char *label, const char *utf8)
{
        struct smb2_utf16 *u = smb2_utf8_to_utf16(utf8);
        char what[160];
        snprintf(what, sizeof what, "malformed %s -> refused", label);
        check(u == NULL, what);
        free(u);
}

int main(void)
{
        int mismatches = 0;
        for (unsigned v = 0; v < 256; v++) {
                if (l1((char)v) != ref_leading_ones(v)) {
                        printf("l1 mismatch byte 0x%02x: l1=%d reference=%d\n", v, l1((char)v), ref_leading_ones(v));
                        mismatches++;
                }
        }
        check(mismatches == 0, "l1 == independent leading-ones reference for all 256 byte values");

        valid("ASCII plain.txt", "plain.txt", (const uint16_t[]){'p','l','a','i','n','.','t','x','t'}, 9);
        valid("NFC café.txt", "caf\xC3\xA9.txt", (const uint16_t[]){'c','a','f',0x00E9,'.','t','x','t'}, 8);
        valid("NFD cafe+U+0301.txt", "cafe\xCC\x81.txt", (const uint16_t[]){'c','a','f','e',0x0301,'.','t','x','t'}, 9);
        valid("Hangul U+D55C.txt", "\xED\x95\x9C.txt", (const uint16_t[]){0xD55C,'.','t','x','t'}, 5);
        valid("U+FEFF b", "\xEF\xBB\xBF" "b", (const uint16_t[]){0xFEFF,'b'}, 2);
        valid("genuine U+FFFD", "l\xEF\xBF\xBD", (const uint16_t[]){'l',0xFFFD}, 2);
        valid("supplementary U+1F600", "\xF0\x9F\x98\x80", (const uint16_t[]){0xD83D,0xDE00}, 2);
        valid("NFD dir e+U+0301-dir/inner.txt", "e\xCC\x81-dir/inner.txt",
              (const uint16_t[]){'e',0x0301,'-','d','i','r','/','i','n','n','e','r','.','t','x','t'}, 16);

        malformed("lone continuation 0x80", "a\x80");
        malformed("truncated 2-byte lead 0xC3", "caf\xC3");
        malformed("2-byte lead + ASCII", "\xC3" "A");
        malformed("overlong 2-byte 0xC0 0xAF", "\xC0\xAF");
        malformed("overlong 3-byte 0xE0 0x80 0xAF", "\xE0\x80\xAF");
        malformed("encoded surrogate U+D800", "\xED\xA0\x80");
        malformed("above U+10FFFF (0xF4 0x90 ...)", "\xF4\x90\x80\x80");
        malformed("5-byte lead 0xF8", "\xF8\x88\x80\x80\x80");
        malformed("byte 0xFF", "\xFF");

        printf("utf8-check checks=%d failures=%d\n", checks, failures);
        return failures ? 1 : 0;
}
