AC_INIT([libdcerpc],[1.0.0],[ronniesahlberg@gmail.com])

AC_PREREQ([2.69])
AC_CONFIG_SRCDIR([dcerpc.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects 1.11])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

dnl  Do not add default CFLAGS in AC_PROG_CC
: ${CFLAGS=""}
AC_PROG_CC
LT_INIT

AM_PROG_CC_C_O

dnl  Match libsmb2: we always want 64 bit file offsets
CFLAGS="${CFLAGS} -D_FILE_OFFSET_BITS=64"

dnl  libdcerpc is Linux only for now. It can never be built on Windows
dnl  since its symbols collide with Microsoft RPC.
case $host in
  *linux*)
    ;;
  *)
    AC_MSG_ERROR([libdcerpc is only supported on Linux])
    ;;
esac

dnl  libdcerpc uses libsmb2 as its transport. When built as part of the
dnl  libsmb2 tree the parent configure passes LIBSMB2_CFLAGS and
dnl  LIBSMB2_LIBS pointing at the uninstalled libsmb2, which makes
dnl  PKG_CHECK_MODULES skip the pkg-config lookup.
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([LIBSMB2], [libsmb2 >= 7.0.0])

AC_ARG_ENABLE([examples],
              [AS_HELP_STRING([--enable-examples],
                              [Build example programs])])

AM_CONDITIONAL([ENABLE_EXAMPLES],
               [test "$enable_examples" = "yes"])

AC_ARG_ENABLE([werror],
              [AS_HELP_STRING([--disable-werror],
              [Disables building with -Werror by default])])

AS_IF([test "$GCC" = "yes"], [
    WARN_CFLAGS="-Wall -Wshadow -Wno-write-strings -Wstrict-prototypes -Wpointer-arith -Wcast-align -Wno-strict-aliasing"
    AS_IF([test "$enable_werror" != "no"], [
        WARN_CFLAGS="${WARN_CFLAGS} -Werror"
    ])
])
AC_SUBST([WARN_CFLAGS])

dnl  The dcerpc utility loads coders with dlopen()
AC_SEARCH_LIBS([dlopen], [dl], [],
               [AC_MSG_ERROR([dlopen not found, libdl is required])])

dnl  ncurses is optional; without it the winreg-tui utility is not built.
have_ncurses=no
AC_CHECK_HEADERS([ncurses.h], [
    AC_CHECK_LIB([ncurses], [initscr], [have_ncurses=yes])
])
AM_CONDITIONAL([HAVE_NCURSES], [test "$have_ncurses" = "yes"])
AS_IF([test "$have_ncurses" != "yes"], [
    AC_MSG_NOTICE([ncurses not found: winreg-tui will not be built])
])

AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netinet/in.h poll.h \
                  stdint.h stdlib.h string.h sys/poll.h sys/socket.h \
                  sys/stat.h sys/types.h sys/unistd.h unistd.h])

AC_CONFIG_FILES([
    Makefile
    examples/Makefile
    include/Makefile
    tests/Makefile
    utils/Makefile
    libdcerpc.pc
])
AC_OUTPUT
