noinst_PROGRAMS = smb2-cat-async

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/smb2 \
	"-D_U_=__attribute__((unused))" \
	-Wall -Werror

COMMON_LIBS = ../lib/libsmb2.la
smb2_cat_async_LDADD = $(COMMON_LIBS)
