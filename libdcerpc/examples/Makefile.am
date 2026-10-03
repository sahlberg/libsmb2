noinst_PROGRAMS = epm-srvsvc \
	smb2-lsa-lookupsids \
	smb2-share-info \
	smb2-winreg-enum

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(LIBSMB2_CFLAGS) \
	"-D_U_=__attribute__((unused))" \
	-Wall -Werror

LDADD = ../libdcerpc.la $(LIBSMB2_LIBS)

EXTRA_DIST = CMakeLists.txt
