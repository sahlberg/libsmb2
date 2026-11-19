#!/bin/sh

. ./functions.sh

echo "basic cp read/write test"

echo -n "Testing cp to root of share ... "
rm testfile2 2>/dev/null
echo "HappyPenguins!" > testfile
../utils/smb2-cp testfile "${TESTURL}/testfile" > /dev/null || failure
success

echo -n "Testing cp from root of share ... "
../utils/smb2-cp "${TESTURL}/testfile"  testfile2 > /dev/null || failure
success

echo -n "Verify file content match ... "
cmp testfile testfile2 || failure
success

echo -n "Reject copying a local file onto a hard link to itself ... "
rm -f testfile.link
ln testfile testfile.link || failure
../utils/smb2-cp testfile testfile.link 2>/dev/null && failure
cmp testfile testfile2 || failure
rm -f testfile.link
success

echo -n "Reject copying an SMB file onto itself ... "
../utils/smb2-cp "${TESTURL}/testfile" "${TESTURL}/testfile" 2>/dev/null && failure
../utils/smb2-cp "${TESTURL}/testfile" testfile2 >/dev/null || failure
cmp testfile testfile2 || failure
success

# Optional user-specific shares mapped to different backing directories.
if [ -n "${TESTURL_PERSONAL_A:-}" ] && [ -n "${TESTURL_PERSONAL_B:-}" ]; then
    echo -n "Copy the same relative name between two personal shares ... "
    name="cp-personal-$$"
    ../utils/smb2-cp testfile "${TESTURL_PERSONAL_A}/${name}" >/dev/null || failure
    ../utils/smb2-cp "${TESTURL_PERSONAL_A}/${name}" "${TESTURL_PERSONAL_B}/${name}" >/dev/null || failure
    ../utils/smb2-cp "${TESTURL_PERSONAL_B}/${name}" testfile2 >/dev/null || failure
    cmp testfile testfile2 || failure
    success
fi

if [ -r /sys/devices/system/cpu/kernel_max ] && command -v timeout >/dev/null 2>&1; then
    echo -n "Stop at EOF when the source reports a larger size ... "
    timeout 5 ../utils/smb2-cp /sys/devices/system/cpu/kernel_max testfile2 >/dev/null || failure
    cmp /sys/devices/system/cpu/kernel_max testfile2 || failure
    success
fi

echo -n "Trim a longer destination, including for an empty source ... "
printf short > testfile
for input in testfile /dev/null; do
    ../utils/smb2-cp "$input" "${TESTURL}/testfile" >/dev/null || failure
    ../utils/smb2-cp "${TESTURL}/testfile" testfile2 >/dev/null || failure
    cmp "$input" testfile2 || failure
done
success

echo -n "Testing cp from a file that does not exist ... "
../utils/smb2-cp "${TESTURL}/testfile-not-exist"  testfile2 2>/dev/null && failure
success

exit 0
