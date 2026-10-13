#!/bin/sh

. ./functions.sh

echo "test that cancelling smb2_open_async_pdu()/smb2_opendir_async_pdu() frees everything"

../utils/smb2-cp ./prog_cat.c "${TESTURL}/CAT"

echo -n "Testing prog_cancel_pdu on root of share/CAT ... "
libtool --mode=execute valgrind --leak-check=full --error-exitcode=77 ./prog_cancel_pdu "${TESTURL}/CAT" >/dev/null 2>&1 || failure
success

exit 0
