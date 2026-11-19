AM_CPPFLAGS = -I${srcdir}/../include -I${srcdir}/../include/smb2 \
	"-D_U_=__attribute__((unused))" \
	"-D_R_(A,B)=__attribute__((format(printf,A,B)))"
AM_CFLAGS = $(WARN_CFLAGS)
LDADD = ../lib/libsmb2.la

noinst_PROGRAMS = prog_ls prog_mkdir prog_rmdir prog_cat \
	prog_cat_cancel prog_cancel_pdu prog_open_timeout prog_notify_cancel \
	prog_lock_cancel prog_setsd prog_ssc prog_unrelated_compound
noinst_PROGRAMS += metastat-0202-censored utf8-unit timestamps-unit lseek-unit

noinst_PROGRAMS += sync-stat-unit

noinst_PROGRAMS += set-info-unit io-limits-unit notify-handle-unit

noinst_PROGRAMS += aes128ccm-test
aes128ccm_test_SOURCES = aes128ccm-test.c ../lib/aes128ccm.c ../lib/aes-armv8.c \
        ../lib/aes.c ../lib/aes_apple.c ../lib/aes_reference.c
aes128ccm_test_LDADD = $(MAYBE_LIBCRYPTO)

noinst_PROGRAMS += entropy-unit iop-entropy-unit

iop_entropy_unit_SOURCES = iop-entropy-unit.c ../lib/ps2/entropy.c \
        ../lib/hmac.c ../lib/usha.c ../lib/sha224-256.c
iop_entropy_unit_CFLAGS = $(AM_CFLAGS) -DUSE_SHA384_SHA512=0
iop_entropy_unit_LDADD =

EXTRA_PROGRAMS = ld_sockerr
CLEANFILES = ld_sockerr.o ld_sockerr.so

ld_sockerr_SOURCES = ld_sockerr.c
ld_sockerr_CFLAGS = $(AM_CFLAGS) -fPIC

bin_SCRIPTS = ld_sockerr.so

ld_sockerr.o: ld_sockerr-ld_sockerr.o
	$(LIBTOOL) --mode=link $(CC) -o $@ $^

ld_sockerr.so: ld_sockerr.o
	$(CC) -shared -o ld_sockerr.so ld_sockerr.o -ldl

T = "$(srcdir)"/test_*.sh

test: $(noinst_PROGRAMS) $(bin_SCRIPTS)
	./aes128ccm-test
	./io-limits-unit
	./notify-handle-unit
	srcdir="$(srcdir)"; export srcdir; for TEST in $(T); do \
		echo "Running $$TEST"; \
		echo "--------------"; \
		case "$$TEST" in */*) ;; *) TEST="$(srcdir)/$$TEST";; esac; \
		"$$TEST" || exit 1; \
		echo "--------------"; \
		echo; \
	done
