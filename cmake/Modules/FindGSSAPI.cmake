#.rst:
# FindGSSAPI
# -------
# Finds the gssapi library
#
# This will will define the following variables::
#
# GSSAPI_FOUND - system has gssapi
# GSSAPI_INCLUDE_DIRS - the gssapi include directory
# GSSAPI_LIBRARIES - the gssapi libraries

find_library(GSSAPI_LIBRARY NAMES gssapi_krb5)

# gssapi_krb5 only imports krb5_* symbols from libkrb5, it does not define
# them, so anything that links libsmb2 with strict undefined-symbol checks
# (e.g. the macOS linker, or -Wl,--no-undefined) needs libkrb5 linked in
# explicitly too. This is best-effort only: a platform that bundles the
# krb5_* symbols into gssapi_krb5 itself (so the old gssapi_krb5-only link
# already worked) must not be broken just because a standalone libkrb5
# isn't separately found, so KRB5_LIBRARY is never a hard requirement.
find_library(KRB5_LIBRARY NAMES krb5)

find_path(GSSAPI_INCLUDE_DIR NAMES gssapi.h
                                   gssapi/gssapi.h)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GSSAPI
                                  REQUIRED_VARS GSSAPI_LIBRARY GSSAPI_INCLUDE_DIR)

if (GSSAPI_LIBRARY AND GSSAPI_INCLUDE_DIRS)
  set(GSSAPI_FOUND TRUE)
endif ()

if(GSSAPI_FOUND)
  set(GSSAPI_LIBRARIES ${GSSAPI_LIBRARY})
  if(KRB5_LIBRARY)
    list(APPEND GSSAPI_LIBRARIES ${KRB5_LIBRARY})
  endif()
  set(GSSAPI_INCLUDE_DIRS ${GSSAPI_INCLUDE_DIR})
endif()

mark_as_advanced(GSSAPI_LIBRARIES GSSAPI_INCLUDE_DIRS)
