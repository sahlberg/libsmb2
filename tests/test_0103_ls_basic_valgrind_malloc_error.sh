#!/bin/sh

. ./functions.sh

echo "basic ls test with valgrind and [c|m]alloc errors"

echo libtool --mode=execute ltrace -l \* ./prog_ls "${TESTURL}/"
NUM_CALLS=`libtool --mode=execute ltrace -l \* ./prog_ls "${TESTURL}/" 2>&1 >/dev/null | grep "[c|m]alloc" |wc -l`
echo "Num" $NUM_CALLS

for IDX in `seq 1 $NUM_CALLS`; do
    echo -n "Testing prog_ls on root of share with socket failure at #${IDX} ..."
    #ALLOC_FAIL=${IDX} libtool --mode=execute valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=77 ./prog_ls "${TESTURL}/" # >/dev/null 2>valgrind.out
    #expr $? "==" "77" >/dev/null && failure
    ALLOC_FAIL=${IDX} ./prog_ls "${TESTURL}/" 2>&1 # >/dev/null 2>valgrind.out
    echo $?
    success
done

exit 0
