AM_CFLAGS=$(WARN_CFLAGS)

lib_LTLIBRARIES = libdcerpc.la

# -I$(abs_top_srcdir)/lib for private headers used by dcerpc sources (compat.h, ...)
libdcerpc_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
			-I$(abs_top_srcdir)/include/smb2 \
			-I$(abs_top_srcdir)/lib \
			"-D_U_=__attribute__((unused))" \
			-DHAVE_DCERPC_FULL

libdcerpc_la_SOURCES = \
	dcerpc.c \
	dcerpc-srvsvc.c \
	dcerpc-dtyp.c \
	dcerpc-lsa.c \
	dcerpc-wkssvc.c \
	dcerpc-winreg.c \
	dcerpc-epm.c

SOCURRENT=1
SOREVISION=0
SOAGE=0

libdcerpc_la_LIBADD = ../lib/libsmb2.la
libdcerpc_la_LDFLAGS = \
	-version-info $(SOCURRENT):$(SOREVISION):$(SOAGE) \
	-bindir $(bindir) \
	-no-undefined -export-symbols $(srcdir)/libdcerpc.syms
libdcerpc_la_DEPENDENCIES = ../lib/libsmb2.la $(srcdir)/libdcerpc.syms

dist_noinst_DATA = libdcerpc.syms
