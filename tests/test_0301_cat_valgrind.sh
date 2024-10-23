#!/bin/sh

. ./functions.sh

echo "basic cat test with valgrind"

# This test depends on the file CAT existing on the share used for testing
# TODO: should create the file first

echo -n "Testing prog_cat on root of share/CAT ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=1 ./prog_cat "${TESTURL}/CAT" >/dev/null 2>&1 || failure
success

exit 0
