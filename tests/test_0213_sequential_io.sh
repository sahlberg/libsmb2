#!/bin/sh
. "${srcdir:-.}/functions.sh"

echo -n "Testing queued reads, writes, seeks and close ... "
./prog_sequential_io "${TESTURL}/sequential-io-$$" || failure
success
