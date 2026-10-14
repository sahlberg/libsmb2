# samr ([MS-SAMR]) coders, generated from samr.idl; see ../idl.am.

IFACE = samr

noinst_LTLIBRARIES = libsamr.la

libsamr_la_CPPFLAGS = -I$(top_srcdir) \
			-I$(top_srcdir)/include \
			$(LIBSMB2_CFLAGS) \
			"-D_U_=__attribute__((unused))"
libsamr_la_CFLAGS = $(WARN_CFLAGS)

nodist_libsamr_la_SOURCES = samr_coder.c

include $(top_srcdir)/idl.am

EXTRA_DIST = samr.idl
