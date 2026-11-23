include("${CMAKE_CURRENT_LIST_DIR}/sources.cmake")

if(NOT ESP_PLATFORM AND NOT (IOP AND BUILD_IRX))
  list(APPEND SMB2_CORE_SOURCES aes_apple.c)
endif()

if(IOP AND BUILD_IRX)
  set(SOURCES
            ps2/entropy.c
            ps2/smb2_fio.c
            ps2/smb2man.c
            ps2/imports.c
            ${SMB2_CORE_SOURCES})

  BUILD_IOP_IMPORTS(${CMAKE_CURRENT_SOURCE_DIR}/ps2/imports.c ${CMAKE_CURRENT_SOURCE_DIR}/ps2/imports.lst)
  # as ps2sdk's IOP_IETABLE_CFLAGS: each import table's header is an unused
  # static, which GCC drops or moves away from its stubs otherwise
  set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/ps2/imports.c
          PROPERTIES COMPILE_FLAGS -fno-toplevel-reorder)

else()
  set(SOURCES ${SMB2_CORE_SOURCES})
endif()

if(NOT ESP_PLATFORM)
set(INCLUDE_PATH ../include)
set(SMB2_INCLUDE "${INCLUDE_PATH}/smb2")
set(HEADERS
    ${SMB2_INCLUDE}/libsmb2-share-enum.h
    ${SMB2_INCLUDE}/libsmb2-raw.h
    ${SMB2_INCLUDE}/libsmb2.h
    ${SMB2_INCLUDE}/smb2-errors.h
    ${SMB2_INCLUDE}/smb2.h)

# Private headers (compat.h etc.) live in this directory.
set(_SMB2_PRIVATE_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR})

if(EE AND PS2RPC)
add_library(smb2_rpc ${SOURCES} ${HEADERS})
target_link_libraries(smb2_rpc PUBLIC ${core_DEPENDS} ${CORE_LIBRARIES})
target_include_directories(smb2_rpc PUBLIC ${INCLUDE_PATH}
                                   PRIVATE ${_SMB2_PRIVATE_INCLUDES})
set_target_properties(smb2_rpc PROPERTIES
                           VERSION ${PROJECT_VERSION}
                           SOVERSION ${SOVERSION})
elseif(IOP AND BUILD_IRX)
# An IRX is a relocatable object, stripped and then converted by iopfixup,
# as ps2sdk's Makefile.iopglobal builds one: linked as an executable it is
# not a module the IOP can load. No --rb: it turns jal into bal, which
# reaches only 128 KB, and smb2man's .text is larger than that.
add_executable(smb2man.elf ${SOURCES})
target_link_libraries(smb2man.elf
        PRIVATE
        gcc)
target_include_directories(smb2man.elf PRIVATE ${_SMB2_PRIVATE_INCLUDES})
set_target_properties(smb2man.elf PROPERTIES LINK_FLAGS "-nostdlib -dc -r")
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/smb2man.irx
        COMMAND mipsel-none-elf-strip --strip-unneeded --remove-section=.pdr
                --remove-section=.comment --remove-section=.mdebug.abi32
                --remove-section=.gnu.attributes
                -o smb2man-stripped.elf $<TARGET_FILE:smb2man.elf>
        COMMAND iopfixup --irx1 --allow-zero-text -o smb2man.irx smb2man-stripped.elf
        COMMAND md5sum smb2man.irx
        DEPENDS smb2man.elf
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
add_custom_target(smb2man_irx ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/smb2man.irx)
elseif(PICO_BOARD)
add_library(libsmb2 STATIC ${SOURCES})
target_include_directories(libsmb2 PRIVATE ${_SMB2_PRIVATE_INCLUDES})
else()
add_library(smb2 ${SOURCES} ${HEADERS})
target_link_libraries(smb2 PUBLIC ${core_DEPENDS} ${CORE_LIBRARIES})
target_include_directories(smb2 PUBLIC ${INCLUDE_PATH}
                               PRIVATE ${_SMB2_PRIVATE_INCLUDES})
set_target_properties(smb2 PROPERTIES
                           VERSION ${PROJECT_VERSION}
                           SOVERSION ${SOVERSION})
endif()
endif()

if(CMAKE_SYSTEM_NAME MATCHES dreamcast)
target_sources(smb2 PRIVATE dreamcast/vfs.c)
install(FILES dreamcast/vfs.h DESTINATION ${INSTALL_INC_DIR}/smb2/ RENAME smb2-kos.h)
endif()

if(NOT MSVC)
  add_definitions("-D_U_=__attribute__((unused))")
else()
  add_definitions("-D_U_=")
  if(CMAKE_SYSTEM_NAME STREQUAL WindowsStore)
    add_definitions("-D_MSC_UWP")
  endif()
endif()

# Neither the pico nor the esp-idf build installs anything, and neither of
# them even creates a target called smb2, so this must be skipped for both.
if(NOT PICO_BOARD AND NOT ESP_PLATFORM)
if(EE AND PS2RPC)
install(TARGETS smb2_rpc EXPORT smb2_rpc
                     RUNTIME DESTINATION bin
                     ARCHIVE DESTINATION lib${LIB_SUFFIX}
                     LIBRARY DESTINATION lib${LIB_SUFFIX})
elseif(IOP AND BUILD_IRX)
install(FILES ps2/ps2smb2.h
DESTINATION ${PS2SDK}/common/include)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/smb2man.irx
        DESTINATION ${PS2SDK}/ports_iop/irx)
else()
install(TARGETS smb2 EXPORT smb2
                     RUNTIME DESTINATION bin
                     ARCHIVE DESTINATION lib${LIB_SUFFIX}
                     LIBRARY DESTINATION lib${LIB_SUFFIX})
endif()
endif()
