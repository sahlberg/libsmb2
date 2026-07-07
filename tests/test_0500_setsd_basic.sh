#!/bin/sh

. ./functions.sh

echo "basic set-security-info test"

../utils/smb2-cp ./prog_setsd.c "${TESTURL}/SETSD"

echo -n "Testing prog_setsd on root of share/SETSD ... "
./prog_setsd "${TESTURL}/SETSD" > /dev/null || failure
success

exit 0
