#!/bin/sh

. ./functions.sh

echo "test that smb2_add_unrelated_compound_pdu() does not tangle up independent requests"

rm -f unrelated_a unrelated_b 2>/dev/null
dd if=/dev/zero of=unrelated_a bs=1 count=111 2>/dev/null
dd if=/dev/zero of=unrelated_b bs=1 count=222 2>/dev/null

../utils/smb2-cp unrelated_a "${TESTURL}/UNRELATED_A" > /dev/null || failure
../utils/smb2-cp unrelated_b "${TESTURL}/UNRELATED_B" > /dev/null || failure

echo -n "Testing prog_unrelated_compound on root of share ... "
./prog_unrelated_compound "${TESTURL}" > /dev/null || failure
success

rm -f unrelated_a unrelated_b

exit 0
