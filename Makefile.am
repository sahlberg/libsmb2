if ENABLE_EXAMPLES
    MAYBE_EXAMPLES = examples
endif

if BUILD_LIBDCERPC
    MAYBE_LIBDCERPC = libdcerpc
endif

SUBDIRS = include lib $(MAYBE_LIBDCERPC) utils . $(MAYBE_EXAMPLES)
ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsmb2.pc

EXTRA_DIST = \
	libsmb2.pc.in

test: $(SUBDIRS)
	cd tests; make test
