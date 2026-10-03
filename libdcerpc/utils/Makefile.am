bin_PROGRAMS = dcerpc epm-enum

if HAVE_NCURSES
bin_PROGRAMS += winreg-tui
endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(LIBSMB2_CFLAGS) \
	"-D_U_=__attribute__((unused))" \
	-Wall -Werror

LDADD = ../libdcerpc.la $(LIBSMB2_LIBS)
winreg_tui_LDADD = $(LDADD) -lncurses

EXTRA_DIST = CMakeLists.txt
