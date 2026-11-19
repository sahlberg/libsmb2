/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Whether or not TCP sockets should be allowed to linger after closure */
#define CONFIGURE_OPTION_TCP_LINGER 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <CommonCrypto/CommonCryptor.h> header file. */
#if defined(__APPLE__) && defined(__has_include)
#if __has_include(<CommonCrypto/CommonCryptor.h>)
#define HAVE_COMMONCRYPTO_COMMONCRYPTOR_H 1
#endif
#endif

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the <gssapi/gssapi.h> header file. */
#define HAVE_GSSAPI_GSSAPI_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Whether we use gssapi_krb5 or not */
/* #undef HAVE_LIBKRB5 */

/* Define to 1 if you have the `nsl' library (-lnsl). */
/* #undef HAVE_LIBNSL */

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Whether we have linger */
#define HAVE_LINGER 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <netinet/tcp.h> header file. */
#define HAVE_NETINET_TCP_H 1

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* Whether sockaddr struct has sa_len */
#define HAVE_SOCKADDR_LEN 1

/* Whether we have sockaddr_Storage */
#define HAVE_SOCKADDR_STORAGE 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/errno.h> header file. */
#define HAVE_SYS_ERRNO_H 1

/* Define to 1 if you have the <sys/fcntl.h> header file. */
#define HAVE_SYS_FCNTL_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/poll.h> header file. */
#define HAVE_SYS_POLL_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define to 1 if you have the <sys/unistd.h> header file. */
#define HAVE_SYS_UNISTD_H 1

/* Define to 1 if you have the <sys/_iovec.h> header file. */
/* #undef HAVE_SYS__IOVEC_H */

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "libsmb2"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "ronniesahlberg@gmail.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libsmb2"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libsmb2 4.0.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libsmb2"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "4.0.0"

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "4.0.0"

/* Pick a CSPRNG for the NTLMv2 client challenge, SMB 3.1.1 preauth
 * salt, client GUID and per-PDU nonces.
 *
 * This shim config is the first include of every translation unit and is
 * also the header search path on Linux (see the smb2-module/apple
 * symlink), so only compiler-predefined macros can be tested here: a libc
 * version test (__GLIBC__ comes from <features.h>) is always false at this
 * point, and pulling <features.h> in early would freeze the feature-test
 * macros before the sources define _GNU_SOURCE. */
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
/* These libcs all provide arc4random_buf(). (Darwin since 10.7; the BSDs
 * forever. Their compilers predefine these macros, so the test works even
 * though this file is the first include of every translation unit.) */
#define HAVE_ARC4RANDOM_BUF 1
#elif defined(__linux__)
/* getrandom(2) needs no libc version probe on anything a Swift toolchain
 * ships for (glibc >= 2.25, musl >= 1.1.20); /dev/urandom stays as the
 * fallback for seccomp filters and old kernels. Bionic only gained the
 * wrapper in API 28, so Android relies on /dev/urandom alone. */
#ifndef __ANDROID__
#define HAVE_SYS_RANDOM_H 1
#define HAVE_GETRANDOM 1
#endif
#define HAVE_DEV_URANDOM 1
#endif
