# netlogon ([MS-NRPC]) coders, generated from netlogon.idl; see ../idl.am.

IFACE = netlogon

noinst_LTLIBRARIES = libnetlogon.la

libnetlogon_la_CPPFLAGS = -I$(top_srcdir) \
			-I$(top_srcdir)/include \
			$(LIBSMB2_CFLAGS) \
			"-D_U_=__attribute__((unused))"
libnetlogon_la_CFLAGS = $(WARN_CFLAGS)

nodist_libnetlogon_la_SOURCES = netlogon_coder.c

include $(top_srcdir)/idl.am

EXTRA_DIST = netlogon.idl
