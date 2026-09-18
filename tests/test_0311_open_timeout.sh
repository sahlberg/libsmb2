#!/bin/sh

. ./functions.sh

echo "test that a create that never gets a reply is freed exactly once"

echo -n "Testing prog_open_timeout on share/libsmb2_issue_484 ... "
./prog_open_timeout "${TESTURL}/libsmb2_issue_484" > /dev/null
case $? in
    0) success ;;
    77) skipped "server does not drop the create, needs scrambla on the tests/libsmb2_issue_484 branch" ;;
    *) failure ;;
esac

exit 0
