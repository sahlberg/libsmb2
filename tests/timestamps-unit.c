/* Offline FILETIME conversion regression checks; LGPL-2.1-or-later. */
#include <stdio.h>
#include <stdlib.h>
#include "../lib/timestamps.c"

#define EPOCH_AS_FILETIME 116444736000000000ULL
#define TICKS_PER_SEC     10000000ULL

static int failures, checks;

static void check(int ok, const char *what)
{
        checks++;
        if (!ok) failures++;
        printf("%-4s %s\n", ok ? "ok" : "FAIL", what);
}

/* Convert t and compare against the expected seconds and microseconds. */
static void to_timeval(const char *label, uint64_t t, long long sec, long usec)
{
        struct smb2_timeval tv;
        char what[160];

        smb2_win_to_timeval(t, &tv);
        snprintf(what, sizeof what, "%s -> sec %lld usec %ld (got %lld, %ld)",
                 label, sec, usec, (long long)tv.tv_sec, tv.tv_usec);
        check((long long)tv.tv_sec == sec && tv.tv_usec == usec, what);
}

/* win -> timeval -> win must give back the original FILETIME. */
static void round_trip(const char *label, uint64_t t)
{
        struct smb2_timeval tv;
        char what[160];

        smb2_win_to_timeval(t, &tv);
        snprintf(what, sizeof what, "round trip %s", label);
        check(tv.tv_usec >= 0 && tv.tv_usec <= 999999 &&
              smb2_timeval_to_win(&tv) == t / 10 * 10, what);
}

int main(void)
{
        const int wide_time_t = sizeof(time_t) > 4;

        to_timeval("epoch", EPOCH_AS_FILETIME, 0, 0);
        to_timeval("epoch + 1 tick", EPOCH_AS_FILETIME + 1, 0, 0);
        to_timeval("epoch + 1 us", EPOCH_AS_FILETIME + 10, 0, 1);
        to_timeval("epoch + 1.5 s", EPOCH_AS_FILETIME + 15000000, 1, 500000);
        to_timeval("epoch + 1 day", EPOCH_AS_FILETIME + 86400 * TICKS_PER_SEC, 86400, 0);
        to_timeval("2001-09-09 01:46:40 UTC", EPOCH_AS_FILETIME + 1000000000ULL * TICKS_PER_SEC,
                   1000000000, 0);

        to_timeval("epoch - 1 tick", EPOCH_AS_FILETIME - 1, -1, 999999);
        to_timeval("epoch - 1 us", EPOCH_AS_FILETIME - 10, -1, 999999);
        to_timeval("epoch - 1 s", EPOCH_AS_FILETIME - TICKS_PER_SEC, -1, 0);
        to_timeval("epoch - 1.5 s", EPOCH_AS_FILETIME - 15000000, -2, 500000);
        to_timeval("epoch - 1 day", EPOCH_AS_FILETIME - 86400 * TICKS_PER_SEC, -86400, 0);
        to_timeval("1969-12-31 23:59:59.999999 UTC", EPOCH_AS_FILETIME - 10, -1, 999999);
        if (wide_time_t) {
                to_timeval("FILETIME 0 (1601-01-01)", 0, -11644473600LL, 0);
                to_timeval("FILETIME 1 tick", 1, -11644473600LL, 0);
                to_timeval("FILETIME 10 (1 us after 1601)", 10, -11644473600LL, 1);
                to_timeval("1601-01-01 + 1 s", TICKS_PER_SEC, -11644473599LL, 0);
        }

        round_trip("epoch", EPOCH_AS_FILETIME);
        round_trip("epoch + 1 us", EPOCH_AS_FILETIME + 10);
        round_trip("epoch + 1.5 s", EPOCH_AS_FILETIME + 15000000);
        round_trip("epoch - 1 us", EPOCH_AS_FILETIME - 10);
        round_trip("epoch - 1 s", EPOCH_AS_FILETIME - TICKS_PER_SEC);
        round_trip("epoch - 1.5 s", EPOCH_AS_FILETIME - 15000000);
        round_trip("epoch - 1 day", EPOCH_AS_FILETIME - 86400 * TICKS_PER_SEC);
        if (wide_time_t) {
                round_trip("FILETIME 0", 0);
                round_trip("1601-01-01 + 123456 us", 1234560);
        }

        printf("timestamps-check checks=%d failures=%d\n", checks, failures);
        return failures ? 1 : 0;
}
