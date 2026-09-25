#!/bin/sh

. ./functions.sh

echo "test that smb2_cmd_cancel_async() can cancel a pending byte-range LOCK"

rm -f lockfile 2>/dev/null
dd if=/dev/zero of=lockfile bs=1 count=16 2>/dev/null

../utils/smb2-cp lockfile "${TESTURL}/LOCKFILE" > /dev/null || failure

echo -n "Testing prog_lock_cancel on root of share ... "
./prog_lock_cancel "${TESTURL}/LOCKFILE" > /dev/null || failure
success

rm -f lockfile

exit 0
