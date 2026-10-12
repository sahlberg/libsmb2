# epm (C706 endpoint mapper) coders, generated from epm.idl; see ../idl.am.

IFACE = epm

noinst_LTLIBRARIES = libepm.la

libepm_la_CPPFLAGS = -I$(top_srcdir) \
			-I$(top_srcdir)/include \
			$(LIBSMB2_CFLAGS) \
			"-D_U_=__attribute__((unused))"
libepm_la_CFLAGS = $(WARN_CFLAGS)

nodist_libepm_la_SOURCES = epm_coder.c

include $(top_srcdir)/idl.am

EXTRA_DIST = epm.idl
