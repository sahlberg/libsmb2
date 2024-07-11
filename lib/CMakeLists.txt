set(SOURCES aes.c
            aes128ccm.c
            alloc.c
			compat.c
            dcerpc.c
            dcerpc-lsa.c
            dcerpc-srvsvc.c
            errors.c
            hmac.c
            hmac-md5.c			
            init.c
            krb5-wrapper.c
            libsmb2.c
            md4c.c
            md5.c
            ntlmssp.c
            pdu.c
	    sha1.c
	    sha224-256.c
	    sha384-512.c
            smb2-cmd-close.c
            smb2-cmd-create.c
            smb2-cmd-echo.c
            smb2-cmd-error.c
            smb2-cmd-flush.c
            smb2-cmd-ioctl.c
            smb2-cmd-logoff.c
            smb2-cmd-negotiate.c
            smb2-cmd-query-directory.c
            smb2-cmd-query-info.c
            smb2-cmd-read.c
            smb2-cmd-session-setup.c
            smb2-cmd-set-info.c
            smb2-cmd-tree-connect.c
            smb2-cmd-tree-disconnect.c
            smb2-cmd-write.c
            smb2-data-file-info.c
            smb2-data-filesystem-info.c
            smb2-data-security-descriptor.c
            smb2-data-reparse-point.c
	    smb2-share-enum.c
	    smb3-seal.c
	    smb2-signing.c
            socket.c
            sync.c
            timestamps.c
            unicode.c
	    usha.c)

set(INCLUDE_PATH ../include)
set(SMB2_INCLUDE "${INCLUDE_PATH}/smb2")
set(HEADERS
    ${SMB2_INCLUDE}/libsmb2-dcerpc-lsa.h
    ${SMB2_INCLUDE}/libsmb2-dcerpc-srvsvc.h
    ${SMB2_INCLUDE}/libsmb2-dcerpc.h
    ${SMB2_INCLUDE}/libsmb2-raw.h
    ${SMB2_INCLUDE}/libsmb2.h
    ${SMB2_INCLUDE}/smb2-errors.h
    ${SMB2_INCLUDE}/smb2.h)

if(EE AND PS2RPC)
add_library(smb2_rpc ${SOURCES} ${HEADERS})
target_link_libraries(smb2_rpc PUBLIC ${core_DEPENDS} ${CORE_LIBRARIES})
target_include_directories(smb2_rpc PUBLIC ${INCLUDE_PATH})
set_target_properties(smb2_rpc PROPERTIES
                           VERSION ${PROJECT_VERSION}
                           SOVERSION ${SOVERSION})                                              
else()
add_library(smb2 ${SOURCES} ${HEADERS})
target_link_libraries(smb2 PUBLIC ${core_DEPENDS} ${CORE_LIBRARIES})
target_include_directories(smb2 PUBLIC ${INCLUDE_PATH})
set_target_properties(smb2 PROPERTIES
                           VERSION ${PROJECT_VERSION}
                           SOVERSION ${SOVERSION})
endif()

if(NOT MSVC)
  add_definitions("-D_U_=__attribute__((unused))")
else()
  add_definitions("-D_U_=")
  if(CMAKE_SYSTEM_NAME STREQUAL WindowsStore)
    add_definitions("-D_MSC_UWP")
  endif()
endif()

if(EE AND PS2RPC)
install(TARGETS smb2_rpc EXPORT smb2_rpc
                     RUNTIME DESTINATION bin
                     ARCHIVE DESTINATION lib${LIB_SUFFIX}
                     LIBRARY DESTINATION lib${LIB_SUFFIX})              
else()
install(TARGETS smb2 EXPORT smb2
                     RUNTIME DESTINATION bin
                     ARCHIVE DESTINATION lib${LIB_SUFFIX}
                     LIBRARY DESTINATION lib${LIB_SUFFIX})
endif()