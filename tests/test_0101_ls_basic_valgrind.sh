#!/bin/sh

. ./functions.sh

echo "basic ls test with valgrind"

echo -n "Testing prog_ls on root of share ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/smb2-ls "${TESTURL}/" >/dev/null 2>&1 || failure
success

exit 0
