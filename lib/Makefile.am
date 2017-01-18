AM_CFLAGS=$(WARN_CFLAGS)

lib_LTLIBRARIES = libsmb2.la

libsmb2_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		      -I$(abs_top_srcdir)/include/smb2 \
		      "-D_U_=__attribute__((unused))"

libsmb2_la_SOURCES = \
	init.c \
	pdu.c \
	libsmb2.c \
	smb2-close.c \
	smb2-create.c \
	smb2-echo.c \
	smb2-logoff.c \
	smb2-negotiate.c \
	smb2-session-setup.c \
	smb2-tree-connect.c \
	socket.c \
	unicode.c

SOCURRENT=1
SOREVISION=0
SOAGE=0
libsmb2_la_LDFLAGS = \
	-version-info $(SOCURRENT):$(SOREVISION):$(SOAGE) -bindir $(bindir) \
	-no-undefined -export-symbols ${srcdir}/libsmb2.syms -lgssapi_krb5

dist_noinst_DATA = libsmb2.syms
