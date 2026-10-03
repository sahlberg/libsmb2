# libdcerpc can be built on its own against an installed libsmb2
# (found with pkg-config), or as a subdirectory of the libsmb2 tree
# where it links the in-tree smb2 target.
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

  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBSMB2 REQUIRED IMPORTED_TARGET libsmb2>=7.0.0)
  set(LIBDCERPC_SMB2 PkgConfig::LIBSMB2)
else()
  set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin")
  set(LIBDCERPC_SMB2 smb2)
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
    dcerpc-srvsvc.c
    dcerpc-dtyp.c
    dcerpc-lsa.c
    dcerpc-wkssvc.c
    dcerpc-winreg.c
    dcerpc-epm.c
    dcerpc-private.h
)

add_library(dcerpc ${DCERPC_LIB_SOURCES})
target_compile_definitions(dcerpc PRIVATE HAVE_CONFIG_H _FILE_OFFSET_BITS=64
                                  "_U_=__attribute__((unused))")
target_include_directories(dcerpc
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
# Our config.h must win over libsmb2's when built in the libsmb2 tree.
target_include_directories(dcerpc BEFORE PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
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

configure_file(libdcerpc.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libdcerpc.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libdcerpc.pc
        DESTINATION ${INSTALL_PKGCONFIG_DIR})

if(ENABLE_UTILS)
  add_subdirectory(utils)
endif()
if(ENABLE_EXAMPLES)
  add_subdirectory(examples)
endif()
