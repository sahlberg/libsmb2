# wkssvc ([MS-WKST]) coders, generated from wkssvc.idl; see ../idl.am.

IFACE = wkssvc

noinst_LTLIBRARIES = libwkssvc.la

libwkssvc_la_CPPFLAGS = -I$(top_srcdir) \
			-I$(top_srcdir)/include \
			$(LIBSMB2_CFLAGS) \
			"-D_U_=__attribute__((unused))"
libwkssvc_la_CFLAGS = $(WARN_CFLAGS)

nodist_libwkssvc_la_SOURCES = wkssvc_coder.c

include $(top_srcdir)/idl.am

EXTRA_DIST = wkssvc.idl
