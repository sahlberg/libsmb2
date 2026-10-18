noinst_PROGRAMS = epm-srvsvc \
	smb2-lsa-lookupsids \
	smb2-share-info \
	smb2-winreg-enum

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/srvsvc \
	-I$(top_builddir)/wkssvc \
	-I$(top_builddir)/samr \
	-I$(top_builddir)/dssetup \
	-I$(top_builddir)/netlogon \
	-I$(top_builddir)/winreg \
	-I$(top_builddir)/lsa \
	-I$(top_builddir)/epm \
	$(LIBSMB2_CFLAGS) \
	"-D_U_=__attribute__((unused))" \
	-Wall -Werror

LDADD = ../libdcerpc.la $(LIBSMB2_LIBS)

EXTRA_DIST = CMakeLists.txt
