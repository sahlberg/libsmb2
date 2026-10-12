# lsa ([MS-LSAT]) coders, generated from lsa.idl; see ../idl.am.

IFACE = lsa

noinst_LTLIBRARIES = liblsa.la

liblsa_la_CPPFLAGS = -I$(top_srcdir) \
			-I$(top_srcdir)/include \
			$(LIBSMB2_CFLAGS) \
			"-D_U_=__attribute__((unused))"
liblsa_la_CFLAGS = $(WARN_CFLAGS)

nodist_liblsa_la_SOURCES = lsa_coder.c

include $(top_srcdir)/idl.am

EXTRA_DIST = lsa.idl
