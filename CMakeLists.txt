if(PICO_BOARD)
    cmake_minimum_required(VERSION 3.12)

    message(STATUS "Configuring libsmb2 for ${PICO_BOARD}")

    project(libsmb2 C CXX ASM)

    add_library(libsmb2 STATIC
            lib/aes.c
            lib/aes128ccm.c
            lib/alloc.c
			lib/compat.c
            lib/dcerpc.c
            lib/dcerpc-lsa.c
            lib/dcerpc-srvsvc.c
            lib/errors.c
			lib/hmac.c
            lib/hmac-md5.c
            lib/init.c
            lib/krb5-wrapper.c
            lib/libsmb2.c
            lib/md4c.c
            lib/md5.c
            lib/ntlmssp.c
            lib/pdu.c
            lib/sha1.c
            lib/sha224-256.c
            lib/sha384-512.c
            lib/smb2-cmd-close.c
            lib/smb2-cmd-create.c
            lib/smb2-cmd-echo.c
            lib/smb2-cmd-error.c
            lib/smb2-cmd-flush.c
            lib/smb2-cmd-ioctl.c
            lib/smb2-cmd-logoff.c
            lib/smb2-cmd-negotiate.c
            lib/smb2-cmd-query-directory.c
            lib/smb2-cmd-query-info.c
            lib/smb2-cmd-read.c
            lib/smb2-cmd-session-setup.c
            lib/smb2-cmd-set-info.c
            lib/smb2-cmd-tree-connect.c
            lib/smb2-cmd-tree-disconnect.c
            lib/smb2-cmd-write.c
            lib/smb2-data-file-info.c
            lib/smb2-data-filesystem-info.c
            lib/smb2-data-security-descriptor.c
            lib/smb2-data-reparse-point.c
            lib/smb2-share-enum.c
            lib/smb3-seal.c
            lib/smb2-signing.c
            lib/socket.c
            lib/sync.c
            lib/timestamps.c
            lib/unicode.c
            lib/usha.c
    )

    include_directories(libsmb2 STATIC
            ${PICO_SDK_PATH}/lib/lwip/src/include
            ${PICO_SDK_PATH}/src/rp2_common/pico_lwip/include
            lib
            include
            include/smb2
            include/picow
    )

	add_definitions(-DNEED_BE64TOH -DNEED_POLL -DNEED_GETLOGIN_R -D_U_=__attribute__((unused)))

 ##### END PICO_BOARD
elseif(ESP_PLATFORM)
  if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    add_definitions(-DHAVE_CONFIG_H)
  endif()
  
  add_definitions(-DNEED_READV -DNEED_WRITEV -DNEED_GETLOGIN_R -DNEED_RANDOM -DNEED_SRANDOM -D_U_=__attribute__((unused)))

  set(COMPONENT_ADD_INCLUDEDIRS
    "lib"
    include
    include/smb2
    include/esp
  )

  set(COMPONENT_SRCS
    lib/aes.c
    lib/aes128ccm.c
    lib/alloc.c
	lib/compat.c
    lib/dcerpc.c
    lib/dcerpc-lsa.c
    lib/dcerpc-srvsvc.c
    lib/errors.c
    lib/init.c
    lib/hmac.c
    lib/hmac-md5.c
    lib/krb5-wrapper.c
    lib/libsmb2.c
    lib/md4c.c
    lib/md5.c
    lib/ntlmssp.c
    lib/pdu.c
    lib/sha1.c
    lib/sha224-256.c
    lib/sha384-512.c
    lib/smb2-cmd-close.c
    lib/smb2-cmd-create.c
    lib/smb2-cmd-echo.c
    lib/smb2-cmd-error.c
    lib/smb2-cmd-flush.c
    lib/smb2-cmd-ioctl.c
    lib/smb2-cmd-logoff.c
    lib/smb2-cmd-negotiate.c
    lib/smb2-cmd-query-directory.c
    lib/smb2-cmd-query-info.c
    lib/smb2-cmd-read.c
    lib/smb2-cmd-session-setup.c
    lib/smb2-cmd-set-info.c
    lib/smb2-cmd-tree-connect.c
    lib/smb2-cmd-tree-disconnect.c
    lib/smb2-cmd-write.c
    lib/smb2-data-file-info.c
    lib/smb2-data-filesystem-info.c
    lib/smb2-data-security-descriptor.c
    lib/smb2-data-reparse-point.c
    lib/smb2-share-enum.c
    lib/smb3-seal.c
    lib/smb2-signing.c
    lib/socket.c
    lib/sync.c
    lib/timestamps.c
    lib/unicode.c
    lib/usha.c
  )

  set(COMPONENT_NAME ".")

  register_component()  
else() 
  if(CMAKE_SYSTEM_NAME MATCHES NintendoSwitch OR CMAKE_SYSTEM_NAME MATCHES Nintendo3DS)
    cmake_minimum_required(VERSION 3.13)
  else()
    cmake_minimum_required(VERSION 3.5)
  endif()

    project(libsmb2
            LANGUAGES C
            VERSION 4.0.0
    )
    set(SOVERSION 1 CACHE STRING "" FORCE)

    set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}" CACHE PATH "Installation directory for libraries")
    set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
    set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
    set(INSTALL_CMAKE_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/cmake/libsmb2" CACHE PATH "Installation directory for cmake (.cmake) files")
  if(CMAKE_SYSTEM_NAME MATCHES NintendoSwitch OR CMAKE_SYSTEM_NAME MATCHES Nintendo3DS OR PS4 OR PS2 OR PS2IPS OR PS2_IOP)
    option(BUILD_SHARED_LIBS "Build shared libraries" OFF)  
  else()
    option(BUILD_SHARED_LIBS "Build shared libraries" ON)
  endif()
    option(ENABLE_EXAMPLES "Build example programs" OFF)
    
    list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/Modules)

    if(IOS)
        find_package(GSSAPI)

        if(GSSAPI_FOUND)
            add_definitions(-DHAVE_LIBKRB5)
        endif()
    endif()

    include(cmake/ConfigureChecks.cmake)

    include_directories(${CMAKE_CURRENT_BINARY_DIR}
                        include
                        include/smb2
    )

    if(IOS)
        set(core_DEPENDS ${GSSAPI_LIBRARIES} CACHE STRING "" FORCE)
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
      list(APPEND CORE_LIBRARIES ws2_32.lib)
      add_definitions(-DWIN32_LEAN_AND_MEAN -D_CRT_NONSTDC_NO_DEPRECATE -D_CRT_SECURE_NO_WARNINGS)
    elseif(CMAKE_SYSTEM_NAME MATCHES NintendoSwitch)
      add_definitions(-DARM11 -DSWITCH -D__SWITCH__ -DNEED_READV -DNEED_WRITEV -DNEED_GETLOGIN_R)
      set(ARCH "-march=armv8-a -mtp=soft -fPIE")
      set(CMAKE_C_FLAGS "-g -Wall -O2 -ffast-math ${ARCH}")
      include_directories(include include/smb2)
      set(CMAKE_C_FLAGS "-Wno-unused-variable")
      set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -fno-rtti -std=gnu++11")
      set(CMAKE_C_LDFLAGS "${CMAKE_C_FLAGS} -specs=switch.specs -g ${ARCH} -Wl,-Map,$(notdir $*.map)")
      add_compile_options("${CMAKE_C_FLAGS} ${CMAKE_LDFLAGS}")
    elseif(CMAKE_SYSTEM_NAME MATCHES Nintendo3DS)
      add_definitions(-DARM11 -D_3DS -D__3DS__ -DNEED_READV -DNEED_WRITEV -DNEED_GETLOGIN_R)
      set(ARCH "-march=armv6k -mfloat-abi=hard -mtune=mpcore -mtp=soft -fPIE")
      set(CMAKE_C_FLAGS "-Wno-unused-variable -g -Wall -O2 -mword-relocations -fomit-frame-pointer -ffast-math ${ARCH}")
      include_directories(include include/smb2)
      set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -fno-rtti -fno-exceptions -std=gnu++11")
      set(CMAKE_C_LDFLAGS "${CMAKE_C_FLAGS} -specs=3dsx.specs -g ${ARCH} -Wl,-Map,$(notdir $*.map)")
      add_compile_options("${CMAKE_C_FLAGS} ${CMAKE_LDFLAGS}") 
    elseif(PS4)
      add_definitions(-DPS4_PLATFORM)
      set(CMAKE_C_FLAGS "-funwind-tables")
      #-fuse-init-array -emit-llvm broken...
      include_directories(include include/smb2 sysroot ${OO_PS4_TOOLCHAIN} system ${OO_PS4_TOOLCHAIN}/include ${OO_PS4_TOOLCHAIN}/include/c++/v1)
      set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")    
      add_compile_options("${CMAKE_C_FLAGS}")
    elseif(PS2 OR PS2IPS)
      add_definitions(-DPS2_EE_PLATFORM -DPS2_PLATFORM -DNEED_BE64TOH -DNEED_POLL -DNEED_WRITEV -DNEED_READV -DNEED_GETLOGIN_R)
      include_directories(include include/ps2 include/smb2)
    elseif(PS2_IOP)
      add_definitions(-DPS2_IOP_PLATFORM -DPS2_PLATFORM -DHAVE_CONFIG_H -DNEED_BE64TOH -DNEED_STRDUP -DNEED_READV -DNEED_WRITEV -DNEED_POLL -DNEED_GETPID -DNEED_RANDOM -DNEED_SRANDOM -DNEED_GETLOGIN_R)
      include_directories(include include/ps2 include/smb2)
      set(CMAKE_C_FLAGS "-Wall -Os -D_start=/**/") 
      add_compile_options("${CMAKE_C_FLAGS}")               
    elseif(CMAKE_SYSTEM_NAME STREQUAL Solaris)
      find_library(SOCKET_LIBRARY socket)
      find_library(NSL_LIBRARY nsl)
      list(APPEND CORE_LIBRARIES ${SOCKET_LIBRARY} ${NSL_LIBRARY})
    endif()

    if(ENABLE_EXAMPLES)
      add_subdirectory(examples)
    endif()

    add_subdirectory(lib)

    include(CMakePackageConfigHelpers)
    write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/libsmb2-config-version.cmake
                                    VERSION ${PROJECT_VERSION}
                                    COMPATIBILITY AnyNewerVersion)

    configure_file(cmake/libsmb2.pc.cmake
                  ${CMAKE_CURRENT_BINARY_DIR}/libsmb2.pc @ONLY)

    install(DIRECTORY include/smb2
            DESTINATION ${INSTALL_INC_DIR})

    install(FILES cmake/FindSMB2.cmake
                  ${CMAKE_CURRENT_BINARY_DIR}/libsmb2-config-version.cmake
            DESTINATION ${INSTALL_CMAKE_DIR})

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsmb2.pc
            DESTINATION ${INSTALL_PKGCONFIG_DIR})
endif() 

