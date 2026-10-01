#!/bin/sh

. ./functions.sh

echo "test that smb2_cmd_cancel_async() can cancel a pending CHANGE_NOTIFY"

echo -n "Testing cancel sent immediately after CHANGE_NOTIFY ... "
./prog_notify_cancel "${TESTURL}" immediate > /dev/null || failure
success

echo -n "Testing cancel sent after CHANGE_NOTIFY has been pending a while ... "
./prog_notify_cancel "${TESTURL}" delayed > /dev/null || failure
success

echo -n "Testing cancel only targets the requested watch ... "
./prog_notify_cancel "${TESTURL}" targeted > /dev/null || failure
success

echo -n "Testing cancel for an already-completed MessageId is refused ... "
./prog_notify_cancel "${TESTURL}" completed > /dev/null || failure
success

echo -n "Testing cancel for a non-existent MessageId is refused ... "
./prog_notify_cancel "${TESTURL}" invalid > /dev/null || failure
success

exit 0
