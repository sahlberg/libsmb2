# Not part of the default build: smb2-dcerpc-coder-test predates the
# IDL-generated coders and needs updating before it compiles again.
noinst_PROGRAMS = smb2-dcerpc-coder-test

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(LIBSMB2_CFLAGS) \
	"-D_U_=__attribute__((unused))"
AM_CFLAGS = $(WARN_CFLAGS)

LDADD = ../libdcerpc.la $(LIBSMB2_LIBS)

test: $(noinst_PROGRAMS)
	./smb2-dcerpc-coder-test
