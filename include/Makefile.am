smb2dir = $(includedir)/smb2
dist_smb2_HEADERS = \
	smb2/libsmb2.h \
	smb2/libsmb2-share-enum.h \
	smb2/libsmb2-raw.h \
	smb2/smb2.h \
	smb2/smb2-errors.h

if BUILD_LIBDCERPC
dcerpcdir = $(includedir)/dcerpc
dist_dcerpc_HEADERS = \
	dcerpc/dcerpc.h \
	dcerpc/dcerpc-dtyp.h \
	dcerpc/dcerpc-lsa.h \
	dcerpc/dcerpc-srvsvc.h \
	dcerpc/dcerpc-wkssvc.h \
	dcerpc/dcerpc-winreg.h \
	dcerpc/dcerpc-epm.h
endif

dist_noinst_HEADERS = \
	asprintf.h \
	libsmb2-private.h \
	portable-endian.h \
	slist.h
