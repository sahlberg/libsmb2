noinst_PROGRAMS = smb2-ls-async

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/smb2 \
	"-D_U_=__attribute__((unused))"

COMMON_LIBS = ../lib/libsmb2.la -lpopt
smb2_ls_async_LDADD = $(COMMON_LIBS)
