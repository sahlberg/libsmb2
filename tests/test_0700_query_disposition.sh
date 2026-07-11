#!/bin/sh

. ./functions.sh

echo "Query file disposition info test"

TESTFILE=query-disposition.txt
TESTURL_FILE=${TESTURL}/${TESTFILE}

rm -f "$TESTFILE"
echo "delete me" > "$TESTFILE" || failure

echo -n "Uploading test file ... "
../utils/smb2-cp "./$TESTFILE" "$TESTURL_FILE" > /dev/null || failure
success

echo -n "Querying file disposition info ... "
./prog_query_disposition "$TESTURL_FILE" > /dev/null || failure
success

echo -n "Verifying delete-on-close removed the remote file ... "
../utils/smb2-cp "$TESTURL_FILE" ./should-not-exist 2>/dev/null && failure
rm -f ./should-not-exist
success

rm -f "$TESTFILE"

exit 0
