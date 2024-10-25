#!/bin/sh

. ./functions.sh

echo "cp test with valgrind"

echo -n "Copy a file to the root of the share ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/smb2-cp ./prog_cat.c "${TESTURL}/CAT" >/dev/null 2>&1 || failure
success

echo -n "Copy a file from the root of the share ... "
rm foo.txt 2>/dev/null
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ../utils/smb2-cp "${TESTURL}/CAT" foo.txt >/dev/null 2>&1 || failure
success

echo -n "Verify file content match ... "
cmp prog_cat.c foo.txt || failure
success

exit 0
