# libdcerpc can be built on its own against an installed libsmb2
# (found with pkg-config), or as a subdirectory of the libsmb2 tree
# where it links the in-tree smb2 target. With -DWITH_LIBSMB2=OFF it
# is built without libsmb2, as coders only.
set(LIBDCERPC_VERSION 1.0.0)
set(LIBDCERPC_SOVERSION 1)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.10)
  project(libdcerpc VERSION ${LIBDCERPC_VERSION} LANGUAGES C)

  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "libdcerpc is only supported on Linux")
  endif()

  option(BUILD_SHARED_LIBS "Build shared libraries" ON)
  option(ENABLE_EXAMPLES "Build example programs" OFF)
  option(ENABLE_UTILS "Build and install the utilities" ON)

  include(GNUInstallDirs)
  set(INSTALL_BIN_DIR "${CMAKE_INSTALL_FULL_BINDIR}")
  set(INSTALL_LIB_DIR "${CMAKE_INSTALL_FULL_LIBDIR}")
  set(INSTALL_INC_DIR "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
  set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig")
  set(INSTALL_MAN_DIR "${CMAKE_INSTALL_FULL_MANDIR}")
else()
  set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin")
  set(INSTALL_MAN_DIR "${CMAKE_INSTALL_PREFIX}/share/man")
endif()

# WITH_LIBSMB2=OFF builds only the coders: no transport, so no binding or
# calls, and no dependency on libsmb2 at all. The utilities and the
# examples need the transport and are not built.
option(WITH_LIBSMB2 "Build the libsmb2 transport (OFF: only the coders)" ON)
if(WITH_LIBSMB2)
  set(HAVE_LIBSMB2 1)
  set(LIBDCERPC_REQUIRES "libsmb2 >= 7.0.0")
  if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSMB2 REQUIRED IMPORTED_TARGET libsmb2>=7.0.0)
    set(LIBDCERPC_SMB2 PkgConfig::LIBSMB2)
  else()
    set(LIBDCERPC_SMB2 smb2)
  endif()
else()
  set(LIBDCERPC_REQUIRES "")
  set(LIBDCERPC_SMB2 "")
  set(ENABLE_UTILS OFF)
  set(ENABLE_EXAMPLES OFF)
endif()

include(CheckIncludeFile)
foreach(HDR arpa/inet.h fcntl.h inttypes.h netinet/in.h poll.h stdint.h
            stdlib.h string.h sys/poll.h sys/socket.h sys/stat.h
            sys/types.h sys/unistd.h unistd.h)
  string(TOUPPER "HAVE_${HDR}" VAR)
  string(REGEX REPLACE "[/.]" "_" VAR "${VAR}")
  check_include_file(${HDR} ${VAR})
endforeach()
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

set(DCERPC_LIB_SOURCES
    dcerpc.c
    dcerpc-dtyp.c
    dcerpc-epm.c
    dcerpc-server.c
    dcerpc-unicode.c
    schannel.c
    dcerpc-private.h
)

# Interfaces whose coders and public header dcerpc/<iface>.h are
# generated from <iface>/<iface>.idl. The <iface>_* syms are kept in the
# source tree and must match the IDL; "make -C <iface> update" in an
# autotools build rewrites them.
set(DCERPC_IDL_IFACES srvsvc wkssvc winreg lsa samr dssetup netlogon epm)

find_program(PYTHON3 python3)
if(NOT PYTHON3)
  message(FATAL_ERROR "python3 is required to generate the IDL coders")
endif()

function(dcerpc_idl IFACE)
  set(GEN ${CMAKE_CURRENT_BINARY_DIR}/${IFACE})
  add_custom_command(
    OUTPUT ${GEN}/${IFACE}_coder.c ${GEN}/dcerpc/${IFACE}.h
    COMMAND ${CMAKE_COMMAND} -E make_directory ${GEN}/dcerpc
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_CURRENT_SOURCE_DIR}/libdcerpc.syms ${GEN}/${IFACE}.syms
    COMMAND ${PYTHON3} ${CMAKE_CURRENT_SOURCE_DIR}/idlcomp.py
            ${CMAKE_CURRENT_SOURCE_DIR}/${IFACE}/${IFACE}.idl --libdcerpc
            -o ${GEN}/${IFACE}_coder.c.tmp
            --header ${GEN}/dcerpc/${IFACE}.h
            --update-syms ${GEN}/${IFACE}.syms
    COMMAND ${CMAKE_COMMAND} -E compare_files ${GEN}/${IFACE}.syms
            ${CMAKE_CURRENT_SOURCE_DIR}/libdcerpc.syms
    COMMAND ${CMAKE_COMMAND} -E rename ${GEN}/${IFACE}_coder.c.tmp ${GEN}/${IFACE}_coder.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/idlcomp.py
            ${CMAKE_CURRENT_SOURCE_DIR}/${IFACE}/${IFACE}.idl
            ${CMAKE_CURRENT_SOURCE_DIR}/libdcerpc.syms
    COMMENT "Generating ${IFACE} coders from ${IFACE}.idl"
    VERBATIM)
endfunction()

set(DCERPC_IDL_INCLUDES)
set(DCERPC_IDL_HEADERS)
foreach(IFACE ${DCERPC_IDL_IFACES})
  dcerpc_idl(${IFACE})
  set(GEN ${CMAKE_CURRENT_BINARY_DIR}/${IFACE})
  list(APPEND DCERPC_LIB_SOURCES ${GEN}/${IFACE}_coder.c ${GEN}/dcerpc/${IFACE}.h)
  list(APPEND DCERPC_IDL_INCLUDES $<BUILD_INTERFACE:${GEN}>)
  list(APPEND DCERPC_IDL_HEADERS ${GEN}/dcerpc/${IFACE}.h)
endforeach()

add_library(dcerpc ${DCERPC_LIB_SOURCES})
target_compile_definitions(dcerpc PRIVATE HAVE_CONFIG_H _FILE_OFFSET_BITS=64
                                  "_U_=__attribute__((unused))")
target_include_directories(dcerpc
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           ${DCERPC_IDL_INCLUDES})
# Our config.h must win over libsmb2's when built in the libsmb2 tree.
target_include_directories(dcerpc BEFORE PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
# For dcerpc-private.h in the generated <iface>/<iface>.c.
target_include_directories(dcerpc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dcerpc PUBLIC ${LIBDCERPC_SMB2})
set_target_properties(dcerpc PROPERTIES
                      VERSION ${LIBDCERPC_VERSION}
                      SOVERSION ${LIBDCERPC_SOVERSION}
                      OUTPUT_NAME dcerpc)

install(TARGETS dcerpc EXPORT dcerpc
        RUNTIME DESTINATION ${INSTALL_BIN_DIR}
        ARCHIVE DESTINATION ${INSTALL_LIB_DIR}
        LIBRARY DESTINATION ${INSTALL_LIB_DIR})
install(DIRECTORY include/dcerpc DESTINATION ${INSTALL_INC_DIR})
install(FILES ${DCERPC_IDL_HEADERS} DESTINATION ${INSTALL_INC_DIR}/dcerpc)

configure_file(libdcerpc.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libdcerpc.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libdcerpc.pc
        DESTINATION ${INSTALL_PKGCONFIG_DIR})

if(ENABLE_UTILS)
  add_subdirectory(utils)
endif()
if(ENABLE_EXAMPLES)
  add_subdirectory(examples)
endif()

enable_testing()
add_subdirectory(tests)
