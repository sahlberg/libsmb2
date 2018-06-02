AM_CFLAGS=$(WARN_CFLAGS)

lib_LTLIBRARIES = libsmb2.la

libsmb2_la_CPPFLAGS = -I$(abs_top_srcdir)/include \
		      -I$(abs_top_srcdir)/include/smb2 \
		      "-D_U_=__attribute__((unused))"

libsmb2_la_SOURCES = \
	alloc.c \
	errors.c \
	init.c \
	hmac-md5.c \
	krb5-wrapper.c \
	libsmb2.c \
	md4c.c \
	md5.c \
	ntlmssp.c \
	pdu.c \
	smb2-cmd-close.c \
	smb2-cmd-create.c \
	smb2-cmd-echo.c \
	smb2-cmd-error.c \
	smb2-cmd-flush.c \
	smb2-cmd-logoff.c \
	smb2-cmd-negotiate.c \
	smb2-cmd-query-directory.c \
	smb2-cmd-query-info.c \
	smb2-cmd-read.c \
	smb2-cmd-session-setup.c \
	smb2-cmd-set-info.c \
	smb2-cmd-tree-connect.c \
	smb2-cmd-tree-disconnect.c \
	smb2-cmd-write.c \
	smb2-data-file-info.c \
	smb2-data-filesystem-info.c \
	smb2-data-security-descriptor.c \
	smb2-share-enum.c \
	smb2-signing.c \
	socket.c \
	sync.c \
	timestamps.c \
	unicode.c

SOCURRENT=1
SOREVISION=0
SOAGE=0
libsmb2_la_LDFLAGS = \
	-version-info $(SOCURRENT):$(SOREVISION):$(SOAGE) -bindir $(bindir) \
	-no-undefined -export-symbols ${srcdir}/libsmb2.syms $(MAYBE_LIBKRB5) \
	$(MAYBE_LIBCRYPTO)

dist_noinst_DATA = libsmb2.syms
