# winreg ([MS-RRP]) coders, generated from winreg.idl; see ../idl.am.

IFACE = winreg

noinst_LTLIBRARIES = libwinreg.la

libwinreg_la_CPPFLAGS = -I$(top_srcdir) \
			-I$(top_srcdir)/include \
			$(LIBSMB2_CFLAGS) \
			"-D_U_=__attribute__((unused))"
libwinreg_la_CFLAGS = $(WARN_CFLAGS)

nodist_libwinreg_la_SOURCES = winreg_coder.c

include $(top_srcdir)/idl.am

EXTRA_DIST = winreg.idl
