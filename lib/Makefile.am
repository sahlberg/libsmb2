AM_CFLAGS=$(WARN_CFLAGS)

lib_LTLIBRARIES = libsmb2.la

libsmb2_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		      -I$(abs_top_srcdir)/include/smb2 \
		      "-D_U_=__attribute__((unused))"

libsmb2_la_SOURCES = \
	alloc.c \
	errors.c \
	init.c \
	libsmb2.c \
	pdu.c \
	smb2-cmd-close.c \
	smb2-cmd-create.c \
	smb2-cmd-echo.c \
	smb2-cmd-error.c \
	smb2-cmd-logoff.c \
	smb2-cmd-negotiate.c \
	smb2-cmd-query-directory.c \
	smb2-cmd-query-info.c \
	smb2-cmd-read.c \
	smb2-cmd-session-setup.c \
	smb2-cmd-tree-connect.c \
	smb2-cmd-tree-disconnect.c \
	smb2-cmd-write.c \
	socket.c \
	sync.c \
	timestamps.c \
	unicode.c

SOCURRENT=1
SOREVISION=0
SOAGE=0
libsmb2_la_LDFLAGS = \
	-version-info $(SOCURRENT):$(SOREVISION):$(SOAGE) -bindir $(bindir) \
	-no-undefined -export-symbols ${srcdir}/libsmb2.syms -lgssapi_krb5

dist_noinst_DATA = libsmb2.syms
