# ESP-IDF first evaluates components in CMake script mode to collect their
# dependencies. Register the component before configuring a standalone build.
if(ESP_PLATFORM)
  include("${CMAKE_CURRENT_LIST_DIR}/lib/sources.cmake")
  list(TRANSFORM SMB2_CORE_SOURCES PREPEND "lib/")
  idf_component_register(SRCS ${SMB2_CORE_SOURCES}
                         INCLUDE_DIRS include include/smb2
                         PRIV_INCLUDE_DIRS lib include/esp
                         PRIV_REQUIRES esp_wifi lwip)
  if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE HAVE_CONFIG_H NEED_READV
                               NEED_WRITEV NEED_GETLOGIN_R "_U_=__attribute__((unused))")
  endif()
  return()
endif()

if(NOT ESP_PLATFORM)
  
  if(CMAKE_SYSTEM_NAME MATCHES NintendoSwitch OR CMAKE_SYSTEM_NAME MATCHES Nintendo3DS OR CMAKE_SYSTEM_NAME MATCHES dreamcast OR CMAKE_SYSTEM_NAME MATCHES NintendoGameCube OR CMAKE_SYSTEM_NAME MATCHES NintendoDS OR CMAKE_SYSTEM_NAME MATCHES NintendoWii OR CMAKE_SYSTEM_NAME MATCHES CafeOS)
    cmake_minimum_required(VERSION 3.13)
  elseif(VITA)
    cmake_minimum_required(VERSION 3.10)
  elseif(PICO_BOARD)
    cmake_minimum_required(VERSION 3.12)
    message(STATUS "Configuring libsmb2 for ${PICO_BOARD}")
  else()
    cmake_minimum_required(VERSION 3.10)
  endif()

  if(NOT IOP AND BUILD_IRX)
    project(smb2man
            LANGUAGES C
            VERSION 2.3.0
    )
    set(VERSION 2.3.0)    
    set(PACKAGE "smb2man")
    set(PACKAGE_BUGREPORT "ronniesahlberg@gmail.com or andregui17@outlook.com")
    set(PACKAGE_NAME "smb2man")
    set(PACKAGE_VERSION "${VERSION}")
    set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
    set(PACKAGE_TARNAME "${PACKAGE}")
    set(PACKAGE_URL "https://github.com/sahlberg/libsmb2")
  elseif(PICO_BOARD)
    project(libsmb2 C CXX ASM)
  else()
    project(libsmb2
            LANGUAGES C
            VERSION 7.0.0
    )  
    set(VERSION 7.0.0)
    set(PACKAGE "libsmb2")
    set(PACKAGE_BUGREPORT "ronniesahlberg@gmail.com")
    set(PACKAGE_NAME "libsmb2")
    set(PACKAGE_VERSION "${VERSION}")
    set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
    set(PACKAGE_TARNAME "${PACKAGE}")
    set(PACKAGE_URL "https://github.com/sahlberg/libsmb2")
  endif()
endif()

  # Names used by CMake for hosted Unix targets with the POSIX utilities.
  if(CMAKE_SYSTEM_NAME MATCHES "^(Linux|GNU|Darwin|.*BSD|DragonFly|SunOS|Solaris|Android)$")
    set(SMB2_HOSTED_UNIX ON)
  endif()

  if(NOT ESP_PLATFORM)
    set(SOVERSION 7 CACHE STRING "" FORCE)
    if(NOT IOP AND NOT BUILD_IRX)
      set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}" CACHE PATH "Installation directory for libraries")
      set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
      set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
      set(INSTALL_CMAKE_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/cmake/libsmb2" CACHE PATH "Installation directory for cmake (.cmake) files")
    endif()
    if(CMAKE_SYSTEM_NAME MATCHES NintendoSwitch OR CMAKE_SYSTEM_NAME MATCHES Nintendo3DS OR PS4 OR PS2 OR VITA OR CMAKE_SYSTEM_NAME MATCHES dreamcast OR CMAKE_SYSTEM_NAME MATCHES NintendoGameCube OR CMAKE_SYSTEM_NAME MATCHES NintendoDS OR CMAKE_SYSTEM_NAME MATCHES NintendoWii OR CMAKE_SYSTEM_NAME MATCHES CafeOS)
      option(BUILD_SHARED_LIBS "Build shared libraries" OFF)  
    else()
      option(BUILD_SHARED_LIBS "Build shared libraries" ON)
    endif()
      option(ENABLE_EXAMPLES "Build example programs" OFF)
      # The utilities need a hosted POSIX system (poll.h, a full libc), so
      # only build them by default there: not on Windows, the consoles or
      # the embedded targets.
      if(SMB2_HOSTED_UNIX AND NOT PS4 AND NOT PICO_BOARD)
        set(ENABLE_UTILS_DEFAULT ON)
      else()
        set(ENABLE_UTILS_DEFAULT OFF)
      endif()
      option(ENABLE_UTILS "Build and install the utilities" ${ENABLE_UTILS_DEFAULT})
      option(ENABLE_LIBKRB5 "Enable libkrb5 support" ON)
      option(ENABLE_GSSAPI "Enable gssapi support" ON)
      list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/Modules)
  endif()

  # Full DCE/RPC is a separate project (libdcerpc/) with its own version
  # and releases. It is Linux and FreeBSD only for now, and can never be
  # built on Windows since its symbols collide with Microsoft RPC.
  if(NOT CMAKE_SYSTEM_NAME MATCHES "^(Linux|FreeBSD)$" OR ESP_PLATFORM OR PICO_BOARD OR IOP OR BUILD_IRX)
    set(ENABLE_LIBDCERPC OFF)
  else()
    option(ENABLE_LIBDCERPC "Build libdcerpc (full DCE/RPC; depends on libsmb2)" ON)
    if(ENABLE_LIBDCERPC)
      message(STATUS "Build libdcerpc (full DCE/RPC interfaces)")
    else()
      message(STATUS "libdcerpc disabled")
    endif()

    # Only libdcerpc's coders and server runtime, without libsmb2: for a
    # project that has libsmb2 as a submodule to get at libdcerpc, such as
    # ksmbd-tools through meson's cmake module.
    option(LIBDCERPC_ONLY "Build only libdcerpc, without the libsmb2 transport" OFF)
    if(LIBDCERPC_ONLY)
      set(WITH_LIBSMB2 OFF CACHE BOOL "" FORCE)
      add_subdirectory(libdcerpc)
      return()
    endif()
  endif()

  set(core_DEPENDS "")
  # The Apple GSS and Kerberos APIs must come from the same SDK.
  # Other platforms use the matching GSSAPI and krb5 libraries found below.
  if(APPLE OR SMB2_HOSTED_UNIX)
    if(ENABLE_LIBKRB5 OR ENABLE_GSSAPI)
      if(APPLE)
        include(CheckIncludeFile)
        check_include_file("GSS/GSS.h" HAVE_GSS_GSS_H)
      endif()
      if(APPLE AND HAVE_GSS_GSS_H)
        check_include_file("krb5/krb5.h" HAVE_LIBKRB5)
        find_library(SMB2_KERBEROS_FRAMEWORK Kerberos)
        if(ENABLE_LIBKRB5 AND HAVE_LIBKRB5 AND SMB2_KERBEROS_FRAMEWORK)
          set(core_DEPENDS "-framework GSS" "-framework Kerberos")
        else()
          message(STATUS "Apple Kerberos backend unavailable or disabled")
          set(ENABLE_LIBKRB5 OFF)
          set(ENABLE_GSSAPI OFF)
        endif()
      else()
        find_package(GSSAPI)
        if(GSSAPI_FOUND)
          set(core_DEPENDS ${GSSAPI_LIBRARIES})
        else()
          # Compiling the kerberos paths in when there is no library to link
          # them against only moves the failure to link time, so build
          # without kerberos instead.
          message(STATUS "gssapi_krb5 not found, building without Kerberos")
          set(ENABLE_LIBKRB5 OFF)
          set(ENABLE_GSSAPI OFF)
        endif()
      endif()
    endif()
  endif()

  # SMB2 over QUIC (the "quic" URL argument) uses the Linux kernel QUIC module for
  # the transport and libquic (on top of gnutls) for the TLS 1.3
  # handshake, so it is Linux only. Built in when libquic is found.
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT (ESP_PLATFORM OR PICO_BOARD OR IOP OR BUILD_IRX))
    option(ENABLE_LIBQUIC "Enable SMB2 over QUIC (needs libquic)" ON)
    if(ENABLE_LIBQUIC)
      find_path(LIBQUIC_INCLUDE_DIR netinet/quic.h)
      find_library(LIBQUIC_LIBRARY quic)
      find_library(GNUTLS_LIBRARY gnutls)
      if(LIBQUIC_INCLUDE_DIR AND LIBQUIC_LIBRARY AND GNUTLS_LIBRARY)
        message(STATUS "Build with SMB2 over QUIC support")
        set(HAVE_LIBQUIC 1)
        list(APPEND core_DEPENDS ${LIBQUIC_LIBRARY} ${GNUTLS_LIBRARY})
      else()
        message(STATUS "libquic not found, building without SMB2 over QUIC")
      endif()
    endif()
  endif()

  # SMB2 over SMB Direct (the "rdma" URL argument) uses librdmacm and
  # libibverbs from rdma-core, Linux only. Built in when they are found.
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT (ESP_PLATFORM OR PICO_BOARD OR IOP OR BUILD_IRX))
    option(ENABLE_RDMA "Enable SMB Direct (needs librdmacm and libibverbs)" ON)
    if(ENABLE_RDMA)
      find_path(RDMACM_INCLUDE_DIR rdma/rdma_cma.h)
      find_path(IBVERBS_INCLUDE_DIR infiniband/verbs.h)
      find_library(RDMACM_LIBRARY rdmacm)
      find_library(IBVERBS_LIBRARY ibverbs)
      if(RDMACM_INCLUDE_DIR AND IBVERBS_INCLUDE_DIR AND RDMACM_LIBRARY AND IBVERBS_LIBRARY)
        message(STATUS "Build with SMB Direct support")
        set(HAVE_LIBRDMACM 1)
        list(APPEND core_DEPENDS ${RDMACM_LIBRARY} ${IBVERBS_LIBRARY})
      else()
        message(STATUS "librdmacm/libibverbs not found, building without SMB Direct")
      endif()
    endif()
  endif()

  option(ENABLE_OPENSSL "Use OpenSSL 3 libcrypto for signing and encryption" OFF)
  if(ENABLE_OPENSSL)
    find_package(OpenSSL 3.0 COMPONENTS Crypto)
    if(NOT OPENSSL_FOUND)
      message(FATAL_ERROR "OpenSSL 3.0 or later libcrypto not found")
    endif()
    message(STATUS "Build with OpenSSL")
    set(HAVE_OPENSSL 1)
    include_directories(${OPENSSL_INCLUDE_DIR})
    list(APPEND core_DEPENDS ${OPENSSL_CRYPTO_LIBRARY})
  endif()

  if(NOT ESP_PLATFORM)
      include(cmake/ConfigureChecks.cmake)
  endif()

  if(PICO_BOARD)
      include_directories(libsmb2 STATIC
            ${PICO_SDK_PATH}/lib/lwip/src/include
            ${PICO_SDK_PATH}/src/rp2_common/pico_lwip/include
            lib
            include
            include/smb2
            include/picow
    )
    else()
      include_directories(${CMAKE_CURRENT_BINARY_DIR}
                        include
                        include/smb2
      )
    endif()
    
    if(MSVC AND BUILD_SHARED_LIBS)
      # If we are building dll with msvc, then generate a def file according to the syms file
      set(SYMS_FILE_PATH "${PROJECT_SOURCE_DIR}/lib/libsmb2.syms")
      set(DEF_FILE_PATH "${PROJECT_BINARY_DIR}/lib/libsmb2.def")
      file(READ ${SYMS_FILE_PATH} EXPORT_SYMBOLS)
      file(WRITE ${DEF_FILE_PATH} "LIBRARY smb2\nEXPORTS\n\n${EXPORT_SYMBOLS}")
      # Pass def file to the linker
      set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /DEF:${DEF_FILE_PATH}")
    endif()

    if(CMAKE_SYSTEM_NAME MATCHES Windows)
      list(APPEND CORE_LIBRARIES ws2_32)
      if(NOT WINCE)
        list(APPEND CORE_LIBRARIES bcrypt)
      endif()
      add_definitions(-DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -DHAVE_LINGER -DNEED_GETLOGIN_R -DNEED_GETPID)
    elseif(CMAKE_SYSTEM_NAME MATCHES NintendoSwitch)
      add_definitions(-DNEED_READV -DNEED_WRITEV -DNEED_GETLOGIN_R)
    elseif(CMAKE_SYSTEM_NAME MATCHES Nintendo3DS)
      add_definitions(-DARM11 -D_3DS -D__3DS__ -DNEED_READV -DNEED_WRITEV -DNEED_GETLOGIN_R)
    elseif(CMAKE_SYSTEM_NAME MATCHES NintendoDS)
      add_definitions(-DNEED_READV -DHAVE_SOCKADDR_STORAGE -DNEED_WRITEV -DNEED_GETLOGIN_R -DNEED_GETADDRINFO -DNEED_FREEADDRINFO -DNEED_POLL)
    elseif(CMAKE_SYSTEM_NAME MATCHES NintendoGameCube)      
      add_definitions(-DNEED_READV -DNEED_WRITEV -DNEED_GETLOGIN_R -DNEED_GETADDRINFO -DNEED_FREEADDRINFO -DNEED_POLL)
    elseif(CMAKE_SYSTEM_NAME MATCHES NintendoWii)
      add_definitions(-DNEED_READV -DNEED_WRITEV -DNEED_GETLOGIN_R -DNEED_GETADDRINFO -DNEED_FREEADDRINFO -DNEED_POLL)
    elseif(CMAKE_SYSTEM_NAME MATCHES CafeOS)
      add_definitions(-DNEED_READV -DNEED_WRITEV -DNEED_GETLOGIN_R)
    elseif(PS4)
      list(APPEND core_DEPENDS SceSysmodule SceRandom)
      add_definitions(-DPS4_PLATFORM)
      set(CMAKE_C_FLAGS "-funwind-tables")
      #-fuse-init-array -emit-llvm broken...
      set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")    
      add_compile_options("${CMAKE_C_FLAGS}")
    elseif(EE)
      add_definitions(-DNEED_BE64TOH -DNEED_POLL -DNEED_WRITEV -DNEED_READV -DNEED_GETLOGIN_R)
      if(EE AND PS2RPC)
        add_definitions(-DPS2RPC)
      endif()      
    elseif(IOP)
      add_definitions(-G 0 -DHAVE_CONFIG_H -DNEED_BE64TOH -DNEED_STRDUP -DNEED_READV -DNEED_WRITEV -DNEED_POLL -DNEED_GETPID -DNEED_GETLOGIN_R -DHAVE_SYS_FCNTL_H)
      if(IOP AND BUILD_IRX)
        add_definitions(-D__ps2sdk_iop__)
        if(DEBUG)
          add_definitions(-DDEBUG)
        endif()
      endif()
      # as ps2sdk's Makefile.iopglobal: the IOP kernel cannot take the
      # several LO relocs to one HI that GCC makes without -mno-explicit-relocs
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fno-builtin -msoft-float -mno-explicit-relocs")
      include_directories(${CMAKE_CURRENT_BINARY_DIR} include/ps2)
    elseif(VITA)
      list(APPEND core_DEPENDS SceLibKernel_stub)
      add_definitions(-DNEED_READV -DNEED_WRITEV -DNEED_GETLOGIN_R)  
    elseif(PICO_BOARD)
      add_definitions(-DNEED_BE64TOH -DNEED_POLL -DNEED_GETLOGIN_R)
    elseif(CMAKE_SYSTEM_NAME MATCHES dreamcast)
      add_definitions(-DNEED_WRITEV -DNEED_READV -DHAVE_CONFIG_H -DNEED_GETLOGIN_R)             
    elseif(CMAKE_SYSTEM_NAME MATCHES "^(SunOS|Solaris)$")
      find_library(SOCKET_LIBRARY socket)
      find_library(NSL_LIBRARY nsl)
      list(APPEND CORE_LIBRARIES ${SOCKET_LIBRARY} ${NSL_LIBRARY})
    elseif(CMAKE_SYSTEM_NAME STREQUAL Haiku)
      # Errors are reported as -errno, but Haiku's error codes are negative
      # already. The error mapper makes errno match the positive constants;
      # its symbols are hidden, so it does not affect users of the library.
      add_definitions(-DB_USE_POSITIVE_POSIX_ERRORS)
      # The socket functions live in libnetwork.so, not in libroot.so
      list(APPEND CORE_LIBRARIES posix_error_mapper network)
    endif()

    # Look for a cryptographically strong source of random bytes for
    # smb2_random_bytes() on hosted targets. Other ports can register a provider.
    if(APPLE OR SMB2_HOSTED_UNIX OR CMAKE_SYSTEM_NAME STREQUAL "Haiku")
      include(CheckSymbolExists)
      check_symbol_exists(arc4random_buf "stdlib.h" HAVE_ARC4RANDOM_BUF)
      check_symbol_exists(getrandom "sys/random.h" HAVE_GETRANDOM)
      if(HAVE_ARC4RANDOM_BUF)
        add_definitions(-DHAVE_ARC4RANDOM_BUF)
      endif()
      if(HAVE_GETRANDOM)
        add_definitions(-DHAVE_SYS_RANDOM_H -DHAVE_GETRANDOM)
      endif()
      # Cross builds can override the target device independently of the host.
      if(NOT DEFINED HAVE_DEV_URANDOM)
        if(CMAKE_CROSSCOMPILING OR EXISTS "/dev/urandom")
          set(HAVE_DEV_URANDOM ON)
        endif()
      endif()
      if(HAVE_DEV_URANDOM)
        add_definitions(-DHAVE_DEV_URANDOM)
      endif()
    endif()


    add_subdirectory(lib)
    if(ENABLE_LIBDCERPC)
      add_subdirectory(libdcerpc)
    endif()

    if(ENABLE_EXAMPLES)
      add_subdirectory(examples)
    endif()

    if(ENABLE_UTILS)
      add_subdirectory(utils)
    endif()

  # The packaging and install rules below need PROJECT_VERSION and the
  # INSTALL_* paths, and neither is set for the pico or the esp-idf build.
  if(NOT PICO_BOARD AND NOT ESP_PLATFORM)
      include(CMakePackageConfigHelpers)
      write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/libsmb2-config-version.cmake
                                    VERSION ${PROJECT_VERSION}
                                    COMPATIBILITY AnyNewerVersion)
    if(NOT IOP AND NOT BUILD_IRX)
      set(SMB2_PC_PRIVATE_LIBS "")
      foreach(dep IN LISTS core_DEPENDS CORE_LIBRARIES)
        if(IS_ABSOLUTE "${dep}")
          get_filename_component(pc_dir "${dep}" DIRECTORY)
          get_filename_component(pc_name "${dep}" NAME)
          string(REGEX REPLACE "^lib|\\.(dll\\.a|a|lib|dylib|so(\\.[0-9.]+)?)$" "" pc_name "${pc_name}")
          set(pc_dep "-l${pc_name}")
          if(NOT pc_dir IN_LIST CMAKE_C_IMPLICIT_LINK_DIRECTORIES)
            if(CMAKE_SYSROOT)
              file(RELATIVE_PATH pc_relative "${CMAKE_SYSROOT}" "${pc_dir}")
              if(NOT pc_relative MATCHES "^\\.\\.")
                set(pc_dir "/${pc_relative}")
              endif()
            endif()
            string(REPLACE " " "\\ " pc_dir "${pc_dir}")
            set(pc_dep "-L${pc_dir} ${pc_dep}")
          endif()
        elseif(dep MATCHES "^-")
          set(pc_dep "${dep}")
        else()
          string(REGEX REPLACE "\\.lib$" "" pc_name "${dep}")
          set(pc_dep "-l${pc_name}")
        endif()
        set(SMB2_PC_PRIVATE_LIBS "${SMB2_PC_PRIVATE_LIBS} ${pc_dep}")
      endforeach()
      string(STRIP "${SMB2_PC_PRIVATE_LIBS}" SMB2_PC_PRIVATE_LIBS)
      set(prefix "${CMAKE_INSTALL_PREFIX}")
      set(exec_prefix "${CMAKE_INSTALL_PREFIX}")
      set(libdir "${INSTALL_LIB_DIR}")
      set(includedir "${INSTALL_INC_DIR}")
      set(VERSION "${PROJECT_VERSION}")
      configure_file(libsmb2.pc.in libsmb2.pc @ONLY)

      install(FILES include/smb2/libsmb2.h
                    include/smb2/libsmb2-raw.h
                    include/smb2/libsmb2-share-enum.h
                    include/smb2/smb2.h
                    include/smb2/smb2-errors.h
                    include/smb2/smb2-ioctl.h
            DESTINATION ${INSTALL_INC_DIR}/smb2)

      install(FILES cmake/FindSMB2.cmake
                  ${CMAKE_CURRENT_BINARY_DIR}/libsmb2-config-version.cmake
            DESTINATION ${INSTALL_CMAKE_DIR})

      install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libsmb2.pc"
            DESTINATION ${INSTALL_PKGCONFIG_DIR})
    endif()
  endif() 

