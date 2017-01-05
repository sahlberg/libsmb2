noinst_PROGRAMS = smb2-ls

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/smb2 \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../lib/libsmb2.la -lpopt -lgssapi_krb5
smb2_ls_LDADD = $(COMMON_LIBS)
