if ENABLE_EXAMPLES
    MAYBE_EXAMPLES = examples
endif

if BUILD_LIBDCERPC
    MAYBE_LIBDCERPC = libdcerpc
endif

if BUILD_POSIX_UTILS
    MAYBE_UTILS = utils
endif

SUBDIRS = include lib $(MAYBE_LIBDCERPC) $(MAYBE_UTILS) . $(MAYBE_EXAMPLES)
ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsmb2.pc

EXTRA_DIST = \
	libsmb2.pc.in

test: all
	$(MAKE) -C tests test
