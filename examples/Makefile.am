noinst_PROGRAMS = smb2-cat-async smb2-cat-sync \
	smb2-ls-async smb2-ls-sync \
	smb2-put-sync \
	smb2-raw-stat-async \
	smb2-raw-getsd-async \
	smb2-stat-sync

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/smb2 \
	"-D_U_=__attribute__((unused))" \
	-Wall -Werror

COMMON_LIBS = ../lib/libsmb2.la -lpopt
smb2_cat_async_LDADD = $(COMMON_LIBS)
smb2_cat_sync_LDADD = $(COMMON_LIBS)
smb2_ls_async_LDADD = $(COMMON_LIBS)
smb2_ls_sync_LDADD = $(COMMON_LIBS)
smb2_put_sync_LDADD = $(COMMON_LIBS)
smb2_raw_stat_async_LDADD = $(COMMON_LIBS)
smb2_raw_getsd_async_LDADD = $(COMMON_LIBS)
smb2_stat_sync_LDADD = $(COMMON_LIBS)
