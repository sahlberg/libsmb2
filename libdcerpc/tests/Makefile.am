# Coder transcoding tests, run by "make check". Each test program holds
# the known-good NDR and YAML for one interface; coder-test.c runs them.
check_PROGRAMS = wkssvc-coder-test srvsvc-coder-test winreg-coder-test \
	lsa-coder-test samr-coder-test dssetup-coder-test epm-coder-test \
	codertest-coder-test
TESTS = $(check_PROGRAMS)

wkssvc_coder_test_SOURCES = wkssvc-coder-test.c coder-test.c coder-test.h
srvsvc_coder_test_SOURCES = srvsvc-coder-test.c coder-test.c coder-test.h
winreg_coder_test_SOURCES = winreg-coder-test.c coder-test.c coder-test.h
lsa_coder_test_SOURCES = lsa-coder-test.c coder-test.c coder-test.h
samr_coder_test_SOURCES = samr-coder-test.c coder-test.c coder-test.h
dssetup_coder_test_SOURCES = dssetup-coder-test.c coder-test.c coder-test.h
epm_coder_test_SOURCES = epm-coder-test.c coder-test.c coder-test.h
codertest_coder_test_SOURCES = codertest-coder-test.c coder-test.c coder-test.h
nodist_codertest_coder_test_SOURCES = codertest_coder.c codertest_coder.h

# codertest.idl is a test-only interface for NDR layouts the real
# interfaces do not exercise. Its coders use only the public libdcerpc API
# (idlcomp without --libdcerpc) and are built into the test program.
BUILT_SOURCES = codertest_coder.c codertest_coder.h

codertest_coder.c: $(srcdir)/codertest.idl $(top_srcdir)/idlcomp.py
	$(PYTHON3) $(top_srcdir)/idlcomp.py $(srcdir)/codertest.idl \
		-o codertest_coder.c.tmp --header codertest_coder.h \
		--server-header codertest_server.h
	mv codertest_coder.c.tmp $@

codertest_coder.h: codertest_coder.c
	@test -f $@ || { rm -f codertest_coder.c; \
		$(MAKE) $(AM_MAKEFLAGS) codertest_coder.c; }

CLEANFILES = codertest_coder.c codertest_coder.c.tmp codertest_coder.h \
	codertest_server.h

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/srvsvc \
	-I$(top_builddir)/wkssvc \
	-I$(top_builddir)/samr \
	-I$(top_builddir)/dssetup \
	-I$(top_builddir)/winreg \
	-I$(top_builddir)/lsa \
	-I$(top_builddir)/epm \
	$(LIBSMB2_CFLAGS) \
	"-D_U_=__attribute__((unused))"
AM_CFLAGS = $(WARN_CFLAGS)

LDADD = ../libdcerpc.la $(LIBSMB2_LIBS)

EXTRA_DIST = CMakeLists.txt codertest.idl

test: check
