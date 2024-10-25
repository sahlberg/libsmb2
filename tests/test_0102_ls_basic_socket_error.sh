#!/bin/sh

. ./functions.sh

echo "basic ls test with valgrind and session errors"

NUM_CALLS=`libtool --mode=execute strace ../utils/smb2-ls "${TESTURL}/" 2>&1 >/dev/null | grep readv |wc -l`

for IDX in `seq 1 $NUM_CALLS`; do
    echo -n "Testing prog_ls on root of share with socket failure at #${IDX} ..."
    READV_CLOSE=${IDX} LD_PRELOAD=./ld_sockerr.so libtool --mode=execute valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ../utils/smb2-ls "${TESTURL}/" >/dev/null 2>valgrind.out || failure
    success
done

exit 0
