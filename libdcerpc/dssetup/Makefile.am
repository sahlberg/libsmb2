# dssetup ([MS-DSSP]) coders, generated from dssetup.idl; see ../idl.am.

IFACE = dssetup

noinst_LTLIBRARIES = libdssetup.la

libdssetup_la_CPPFLAGS = -I$(top_srcdir) \
			-I$(top_srcdir)/include \
			$(LIBSMB2_CFLAGS) \
			"-D_U_=__attribute__((unused))"
libdssetup_la_CFLAGS = $(WARN_CFLAGS)

nodist_libdssetup_la_SOURCES = dssetup_coder.c

include $(top_srcdir)/idl.am

EXTRA_DIST = dssetup.idl
