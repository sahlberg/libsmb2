set(SOURCES smb2_fio.c 
            smb2man.c 
            imports.c
            ../aes.c
            ../aes128ccm.c
            ../alloc.c
			../compat.c
            ../dcerpc.c
            ../dcerpc-lsa.c
            ../dcerpc-srvsvc.c
            ../errors.c
            ../hmac.c
            ../hmac-md5.c			
            ../init.c
            ../krb5-wrapper.c
            ../libsmb2.c
            ../md4c.c
            ../md5.c
            ../ntlmssp.c
            ../pdu.c
	    ../sha1.c
	    ../sha224-256.c
	    ../sha384-512.c
            ../smb2-cmd-close.c
            ../smb2-cmd-create.c
            ../smb2-cmd-echo.c
            ../smb2-cmd-error.c
            ../smb2-cmd-flush.c
            ../smb2-cmd-ioctl.c
            ../smb2-cmd-logoff.c
            ../smb2-cmd-negotiate.c
            ../smb2-cmd-query-directory.c
            ../smb2-cmd-query-info.c
            ../smb2-cmd-read.c
            ../smb2-cmd-session-setup.c
            ../smb2-cmd-set-info.c
            ../smb2-cmd-tree-connect.c
            ../smb2-cmd-tree-disconnect.c
            ../smb2-cmd-write.c
            ../smb2-data-file-info.c
            ../smb2-data-filesystem-info.c
            ../smb2-data-security-descriptor.c
            ../smb2-data-reparse-point.c
	    ../smb2-share-enum.c
	    ../smb3-seal.c
	    ../smb2-signing.c
            ../socket.c
            ../sync.c
            ../timestamps.c
            ../unicode.c
	    ../usha.c)

BUILD_IOP_IMPORTS(imports.c ${CMAKE_CURRENT_SOURCE_DIR}/imports.lst)

include_directories(./)

if(DEBUG)
    add_definitions(-DDEBUG)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fno-builtin")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s")

add_definitions("-D_U_=__attribute__((unused))")

add_executable(smb2man.irx ${SOURCES})

target_link_libraries(smb2man.irx
	PRIVATE
	gcc)

add_custom_command(TARGET smb2man.irx POST_BUILD COMMAND md5sum ARGS smb2man.irx)                         

install(TARGETS smb2man.irx EXPORT smb2man.irx
RUNTIME DESTINATION bin
ARCHIVE DESTINATION smb2man.irx
LIBRARY DESTINATION smb2man.irx)

install(FILES ps2smb2.h
DESTINATION ${PS2SDK}/common/include)
