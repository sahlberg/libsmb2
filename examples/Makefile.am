noinst_PROGRAMS = smb2-cat-async smb2-cat-sync \
	smb2-ftruncate-sync \
	smb2-ls-async \
	smb2-ls-epoll \
	smb2-put-async \
	smb2-put-sync \
	smb2-raw-fsstat-async \
	smb2-raw-getsd-async \
	smb2-raw-stat-async \
	smb2-readlink \
	smb2-server-side-copy-sync \
	smb2-lseek-sync \
	smb2-share-enum-sync \
	smb2-stat-sync \
	smb2-statvfs-sync \
	smb2-truncate-sync \
	smb2-rename-sync \
	smb2-CMD-FIND	\
	smb2-server-sync \
	smb2-notify \
	smb2-set-security-info

if BUILD_LIBDCERPC
noinst_PROGRAMS += dcerpc \
	smb2-share-enum \
	smb2-lsa-lookupsids \
	smb2-share-info \
	smb2-winreg-enum \
	winreg-tui \
	epm-srvsvc \
	epm-enum
endif

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/smb2 \
	"-D_U_=__attribute__((unused))" \
	-Wall -Werror

COMMON_LIBS = ../lib/libsmb2.la
DCERPC_LIBS = ../libdcerpc/libdcerpc.la ../lib/libsmb2.la

if BUILD_LIBDCERPC
dcerpc_LDADD = $(DCERPC_LIBS)
smb2_lsa_lookupsids_LDADD = $(DCERPC_LIBS)
smb2_share_enum_LDADD = $(DCERPC_LIBS)
smb2_share_info_LDADD = $(DCERPC_LIBS)
smb2_winreg_enum_LDADD = $(DCERPC_LIBS)
winreg_tui_LDADD = $(DCERPC_LIBS) -lncurses
epm_srvsvc_LDADD = $(DCERPC_LIBS)
epm_enum_LDADD = $(DCERPC_LIBS)
endif
smb2_cat_async_LDADD = $(COMMON_LIBS)
smb2_cat_sync_LDADD = $(COMMON_LIBS)
smb2_ftruncate_sync_LDADD = $(COMMON_LIBS)
smb2_ls_async_LDADD = $(COMMON_LIBS)
smb2_ls_epoll_LDADD = $(COMMON_LIBS)
smb2_put_async_LDADD = $(COMMON_LIBS)
smb2_put_sync_LDADD = $(COMMON_LIBS)
smb2_raw_fsstat_async_LDADD = $(COMMON_LIBS)
smb2_raw_getsd_async_LDADD = $(COMMON_LIBS)
smb2_raw_stat_async_LDADD = $(COMMON_LIBS)
smb2_readlink_LDADD = $(COMMON_LIBS)
smb2_server_side_copy_sync_LDADD = $(COMMON_LIBS)
smb2_lseek_sync_LDADD = $(COMMON_LIBS)
smb2_share_enum_sync_LDADD = $(COMMON_LIBS)
smb2_stat_sync_LDADD = $(COMMON_LIBS)
smb2_statvfs_sync_LDADD = $(COMMON_LIBS)
smb2_truncate_sync_LDADD = $(COMMON_LIBS)
smb2_rename_sync_LDADD = $(COMMON_LIBS)
smb2_CMD_FIND_LDADD = $(COMMON_LIBS)
smb2_server_sync_LDADD = $(COMMON_LIBS)
smb2_notify_LDADD = $(COMMON_LIBS)
smb2_set_security_info_LDADD = $(COMMON_LIBS)
