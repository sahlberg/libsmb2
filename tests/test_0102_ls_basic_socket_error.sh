#!/bin/sh

. ./functions.sh

echo "basic ls test with valgrind"

echo -n "Testing prog_ls on root of share with socket failures "
for IDX in `seq 10 10`; do
    echo -n "Testing prog_ls on root of share with socket failure at #${IDX} ..."
    READV_CLOSE=${IDX} LD_PRELOAD=./ld_sockerr.so libtool --mode=execute valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ./prog_ls "${TESTURL}/" >/dev/null 2>valgrind.out || failure
    success
done

exit 0
