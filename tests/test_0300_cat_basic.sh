#!/bin/sh

. ./functions.sh

echo "basic cat test"

# This test depends on the file CAT existing on the share used for testing
# TODO: should create the file first

echo -n "Testing prog_cat on root of share/CAT ... "
./prog_cat "${TESTURL}/CAT" > /dev/null || failure
success

exit 0
