#!/bin/sh

. ./functions.sh

echo "Basic server side copy tests"

SRC_BIN=src.bin
DEST_BIN=dest.bin
LOCAL_COPY=dest.local
SRC_BIN_TESTURL=${TESTURL}/$SRC_BIN
DEST_BIN_TESTURL=${TESTURL}/$DEST_BIN

cleanup_files() {
    rm -f "$SRC_BIN" "$LOCAL_COPY"
}

upload_source() {
    ../utils/smb2-cp "./$SRC_BIN" "$SRC_BIN_TESTURL" > /dev/null || failure
}

download_dest() {
    rm -f "$LOCAL_COPY"
    ../utils/smb2-cp "$DEST_BIN_TESTURL" "./$LOCAL_COPY" > /dev/null || failure
}

verify_copy() {
    download_dest
    cmp "$SRC_BIN" "$LOCAL_COPY" > /dev/null 2>&1 || failure
}

run_case() {
    label=$1
    shift

    echo -n "Testing $label ... "
    ./prog_ssc "$@" > /dev/null || failure
    verify_copy
    success
}

cleanup_files

dd if=/dev/urandom of="$SRC_BIN" bs=1 count=0 2>/dev/null || failure
upload_source
run_case "zero-byte server-side-copy sync copychunk" \
    server-side-copy sync copychunk \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=4096 count=1 > /dev/null 2>&1 || failure
upload_source
run_case "4 KiB server-side-copy sync copychunk" \
    server-side-copy sync copychunk \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=1048575 count=1 > /dev/null 2>&1 || failure
upload_source
run_case "chunk-minus-1 server-side-copy sync copychunk" \
    server-side-copy sync copychunk \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=1M count=1 > /dev/null 2>&1 || failure
upload_source
run_case "1 MiB server-side-copy sync copychunk" \
    server-side-copy sync copychunk \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL" 1048576 16 0 1048576

dd if=/dev/urandom of="$SRC_BIN" bs=1M count=1 > /dev/null 2>&1 || failure
printf 'x' >> "$SRC_BIN" || failure
upload_source
run_case "chunk-plus-1 server-side-copy sync copychunk_write" \
    server-side-copy sync copychunk_write \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=1M count=1 > /dev/null 2>&1 || failure
upload_source
run_case "1 MiB server-side-copy async copychunk" \
    server-side-copy async copychunk \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=1M count=1 > /dev/null 2>&1 || failure
upload_source
run_case "1 MiB server-side-copy async copychunk_write" \
    server-side-copy async copychunk_write \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=1M count=1 > /dev/null 2>&1 || failure
upload_source
run_case "1 MiB direct copychunk sync copychunk" \
    copychunk sync copychunk \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=1M count=1 > /dev/null 2>&1 || failure
upload_source
run_case "1 MiB direct copychunk sync copychunk_write" \
    copychunk sync copychunk_write \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=1M count=1 > /dev/null 2>&1 || failure
upload_source
run_case "1 MiB direct copychunk async copychunk" \
    copychunk async copychunk \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=1M count=1 > /dev/null 2>&1 || failure
upload_source
run_case "1 MiB direct copychunk async copychunk_write" \
    copychunk async copychunk_write \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=1M count=20 > /dev/null 2>&1 || failure
upload_source
run_case "20 MiB server-side-copy sync copychunk" \
    server-side-copy sync copychunk \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

dd if=/dev/urandom of="$SRC_BIN" bs=1M count=20 > /dev/null 2>&1 || failure
upload_source
run_case "20 MiB server-side-copy sync copychunk_write" \
    server-side-copy sync copychunk_write \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

echo -n "Testing invalid ctl_code rejection ... "
./prog_ssc server-side-copy sync 0 \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL" > /dev/null 2>&1 && failure
success

# Requests more chunks in a single copychunk than the server supports
# (observed server limit is 256 chunks per request). This must be rejected
# by the *server*, not by client-side validation, so it exercises the
# server error/reply parsing path instead of the argument-checking path
# that "invalid ctl_code rejection" above exercises.
#
# The server reports this failure with STATUS_INVALID_PARAMETER using the
# normal IOCTL reply layout (carrying its copy limits in the output
# buffer) rather than the generic SMB2 error layout. Older/buggy handling
# of that case misparses the reply as a generic error and aborts with
# "Failed to parse fixed part of command payload. Unexpected size of
# Error reply." instead of a clean NT-status failure.
dd if=/dev/urandom of="$SRC_BIN" bs=1 count=512 > /dev/null 2>&1 || failure
upload_source
echo -n "Testing server-rejected copychunk (chunk count exceeds server limit) ... "
output=$(./prog_ssc server-side-copy sync copychunk_write \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL" 1 257 2>&1)

rc=$?
if [ "$rc" -eq 0 ] || [ "$rc" -ge 128 ]; then
    failure
fi
case "$output" in
    *"Failed to parse"*|*"Unexpected size of Error reply"*)
        failure
        ;;
esac
success

# Copies a file onto itself, so every chunk's source range and target
# range are identical (the simplest form of an overlapping copy within a
# single file). The server may legitimately reject this outright, or treat
# it as a no-op, depending on implementation -- either is acceptable here.
# What matters is that whatever status it uses to report this doesn't get
# misparsed the way the chunk-count-limit status did above. A wrong format
# guess in the *other* direction (treating a plain generic-error reply as
# IOCTL-shaped) wouldn't necessarily fail this request itself -- it could
# instead desync the stream and only surface as a failure on the *next*
# request, so a normal copy is run immediately afterward to catch that.
dd if=/dev/urandom of="$SRC_BIN" bs=65536 count=1 > /dev/null 2>&1 || failure
upload_source
echo -n "Testing self-overlapping copychunk (source == destination) ... "
output=$(./prog_ssc server-side-copy sync copychunk_write \
    "$SRC_BIN_TESTURL" "$SRC_BIN_TESTURL" 2>&1)
rc=$?
if [ "$rc" -ge 128 ]; then
    failure
fi
case "$output" in
    *"Failed to parse"*|*"Unexpected size of Error reply"*)
        failure
        ;;
esac
success

dd if=/dev/urandom of="$SRC_BIN" bs=4096 count=1 > /dev/null 2>&1 || failure
upload_source
run_case "post-self-overlap sanity server-side-copy sync copychunk" \
    server-side-copy sync copychunk \
    "$SRC_BIN_TESTURL" "$DEST_BIN_TESTURL"

cleanup_files

exit 0
