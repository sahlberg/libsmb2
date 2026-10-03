# libdcerpc pkg-config file

prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_PREFIX@
libdir=@INSTALL_LIB_DIR@
includedir=@INSTALL_INC_DIR@

Name: libdcerpc
Description: DCE/RPC client library (SMB2 named-pipe transport via libsmb2)
Version: @LIBDCERPC_VERSION@
Requires: libsmb2 >= 7.0.0
Conflicts:
Libs: -L${libdir} -ldcerpc
Cflags: -I${includedir}
