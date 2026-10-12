# srvsvc ([MS-SRVS]) coders, generated from srvsvc.idl; see ../idl.am.

IFACE = srvsvc

noinst_LTLIBRARIES = libsrvsvc.la

libsrvsvc_la_CPPFLAGS = -I$(top_srcdir) \
			-I$(top_srcdir)/include \
			$(LIBSMB2_CFLAGS) \
			"-D_U_=__attribute__((unused))"
libsrvsvc_la_CFLAGS = $(WARN_CFLAGS)

nodist_libsrvsvc_la_SOURCES = srvsvc_coder.c

include $(top_srcdir)/idl.am

EXTRA_DIST = srvsvc.idl
