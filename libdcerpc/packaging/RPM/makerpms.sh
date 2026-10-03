#!/bin/sh
#
# makerpms.sh  -  build libdcerpc RPM packages from the git sources
#
# libdcerpc lives in the libsmb2 git repository but is released on its
# own, with libdcerpc-<version> tags. The source tarball contains only
# the libdcerpc/ subdirectory and builds against an installed libsmb2.
#
# Usage: makerpms.sh [extra rpmbuild options]
#

EXTRA_OPTIONS="$1"

DIRNAME=$(dirname $0)
TOPDIR=${DIRNAME}/../..

SPECDIR=`rpm --eval %_specdir`
SRCDIR=`rpm --eval %_sourcedir`

SPECFILE="libdcerpc.spec"
SPECFILE_IN="libdcerpc.spec.in"
RPMBUILD="rpmbuild"

# libdcerpc-1.0.0  : a release
# libdcerpc-1.0.0-12-g1234abc : 12 commits after it, a devel release
#                               1.0.0.0.12.g1234abc.devel
TAG=`git describe --match 'libdcerpc-*'`
case "$TAG" in
    libdcerpc-*)
	TAG=${TAG##libdcerpc-}
	case "$TAG" in
	    *-*-g*)
		VERSION=`echo "$TAG" | sed 's/\([^-]\+\)-\([0-9]\+\)-\(g[0-9a-f]\+\)/\1.0.\2.\3.devel/'`
		;;
	    *)
		VERSION=$TAG
		;;
	esac
	;;
    *)
	echo "No libdcerpc-* tag found" >&2
	exit 1
	;;
esac

sed -e s/@VERSION@/$VERSION/g \
	< ${DIRNAME}/${SPECFILE_IN} \
	> ${DIRNAME}/${SPECFILE}

if echo | gzip -c --rsyncable - > /dev/null 2>&1 ; then
	GZIP="gzip -9 --rsyncable"
else
	GZIP="gzip -9"
fi

pushd ${TOPDIR}
echo -n "Creating libdcerpc-${VERSION}.tar.gz ... "
mkdir -p "${SRCDIR}"
git archive --prefix=libdcerpc-${VERSION}/ HEAD:libdcerpc | ${GZIP} > ${SRCDIR}/libdcerpc-${VERSION}.tar.gz
RC=$?
popd
echo "Done."
if [ $RC -ne 0 ]; then
        echo "Build failed!"
        exit 1
fi

mkdir -p ${SPECDIR}
cp -p ${DIRNAME}/${SPECFILE} ${SPECDIR}

echo "$(basename $0): Getting Ready to build release package"
${RPMBUILD} -ba --clean --rmsource ${EXTRA_OPTIONS} ${SPECDIR}/${SPECFILE} || exit 1

echo "$(basename $0): Done."

exit 0
