AM_CPPFLAGS = -I${srcdir}/../include -I${srcdir}/../include/smb2 \
	"-D_U_=__attribute__((unused))" \
	"-D_R_(A,B)=__attribute__((format(printf,A,B)))"
AM_CFLAGS = $(WARN_CFLAGS)
LDADD = ../lib/libsmb2.la

noinst_PROGRAMS = prog_ls

T = `ls test_*.sh`

test: $(noinst_PROGRAMS)
	for TEST in $(T); do \
		echo "Running $$TEST"; \
		echo "--------------"; \
		sh $$TEST || exit 1; \
		echo "--------------"; \
		echo; \
	done
