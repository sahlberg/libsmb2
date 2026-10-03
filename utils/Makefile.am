bin_PROGRAMS = smb2-cp smb2-ls

if BUILD_LIBDCERPC
bin_PROGRAMS += dcerpc epm-enum
if HAVE_NCURSES
bin_PROGRAMS += winreg-tui
endif
endif

AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/include/smb2 \
	"-D_U_=__attribute__((unused))" \
	-Wall -Werror

COMMON_LIBS = ../lib/libsmb2.la
smb2_ls_LDADD = $(COMMON_LIBS)
smb2_cp_LDADD = $(COMMON_LIBS)

DCERPC_LIBS = ../libdcerpc/libdcerpc.la ../lib/libsmb2.la
dcerpc_LDADD = $(DCERPC_LIBS)
epm_enum_LDADD = $(DCERPC_LIBS)
winreg_tui_LDADD = $(DCERPC_LIBS) -lncurses
