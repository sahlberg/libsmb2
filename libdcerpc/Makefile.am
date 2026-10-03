if ENABLE_EXAMPLES
    MAYBE_EXAMPLES = examples
endif

SUBDIRS = include . utils $(MAYBE_EXAMPLES)
DIST_SUBDIRS = include . utils examples tests
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = $(WARN_CFLAGS)

lib_LTLIBRARIES = libdcerpc.la

libdcerpc_la_CPPFLAGS = -I$(srcdir)/include \
			$(LIBSMB2_CFLAGS) \
			"-D_U_=__attribute__((unused))"

libdcerpc_la_SOURCES = \
	dcerpc.c \
	dcerpc-srvsvc.c \
	dcerpc-dtyp.c \
	dcerpc-lsa.c \
	dcerpc-wkssvc.c \
	dcerpc-winreg.c \
	dcerpc-epm.c \
	dcerpc-private.h

SOCURRENT=1
SOREVISION=0
SOAGE=0

libdcerpc_la_LIBADD = $(LIBSMB2_LIBS)
libdcerpc_la_LDFLAGS = \
	-version-info $(SOCURRENT):$(SOREVISION):$(SOAGE) \
	-bindir $(bindir) \
	-no-undefined -export-symbols $(srcdir)/libdcerpc.syms
libdcerpc_la_DEPENDENCIES = $(srcdir)/libdcerpc.syms

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdcerpc.pc

EXTRA_DIST = \
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
