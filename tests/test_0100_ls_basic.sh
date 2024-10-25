#!/bin/sh

. ./functions.sh

echo "basic ls test"

echo -n "Testing prog_ls on root of share ... "
../utils/smb2-ls "${TESTURL}/" > /dev/null || failure
success

exit 0
