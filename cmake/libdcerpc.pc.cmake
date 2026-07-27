# libdcerpc pkg-config file

prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_PREFIX@
libdir=@INSTALL_LIB_DIR@
includedir=@INSTALL_INC_DIR@

Name: libdcerpc
Description: DCE/RPC client library (SMB2 named-pipe transport via libsmb2)
Version: @PROJECT_VERSION@
Requires: libsmb2
Conflicts:
Libs: -L${libdir} -ldcerpc
Cflags: -I${includedir}
