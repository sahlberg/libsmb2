if ENABLE_EXAMPLES
    MAYBE_EXAMPLES = examples
endif

SUBDIRS = include srvsvc wkssvc winreg lsa epm . utils tests $(MAYBE_EXAMPLES)
DIST_SUBDIRS = include srvsvc wkssvc winreg lsa epm . utils examples tests
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = $(WARN_CFLAGS)

lib_LTLIBRARIES = libdcerpc.la

libdcerpc_la_CPPFLAGS = -I$(srcdir)/include \
			-I$(builddir)/srvsvc \
			-I$(builddir)/wkssvc \
			-I$(builddir)/winreg \
			-I$(builddir)/lsa \
			-I$(builddir)/epm \
			$(LIBSMB2_CFLAGS) \
			"-D_U_=__attribute__((unused))"

libdcerpc_la_SOURCES = \
	dcerpc.c \
	dcerpc-dtyp.c \
	dcerpc-epm.c \
	dcerpc-private.h

SOCURRENT=1
SOREVISION=0
SOAGE=0

libdcerpc_la_LIBADD = srvsvc/libsrvsvc.la wkssvc/libwkssvc.la winreg/libwinreg.la lsa/liblsa.la epm/libepm.la $(LIBSMB2_LIBS)
libdcerpc_la_LDFLAGS = \
	-version-info $(SOCURRENT):$(SOREVISION):$(SOAGE) \
	-bindir $(bindir) \
	-no-undefined -export-symbols $(srcdir)/libdcerpc.syms
libdcerpc_la_DEPENDENCIES = $(srcdir)/libdcerpc.syms

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdcerpc.pc

EXTRA_DIST = \
	idlcomp.py \
	idl.am \
	libdcerpc.syms \
	libdcerpc.pc.in \
	libdcerpc.pc.cmake \
	config.h.cmake \
	CMakeLists.txt \
	dcerpc-examples \
	packaging \
	COPYING \
	README

test:
	cd tests; $(MAKE) test
