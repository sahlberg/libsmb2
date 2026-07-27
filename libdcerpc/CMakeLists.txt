set(DCERPC_LIB_SOURCES
    dcerpc.c
    dcerpc-srvsvc.c
    dcerpc-dtyp.c
    dcerpc-lsa.c
    dcerpc-wkssvc.c
    dcerpc-winreg.c
)

set(INCLUDE_PATH ../include)
set(SMB2_INCLUDE "${INCLUDE_PATH}/smb2")
set(DCERPC_HEADERS
    ${SMB2_INCLUDE}/libsmb2-dcerpc-dtyp.h
    ${SMB2_INCLUDE}/libsmb2-dcerpc-lsa.h
    ${SMB2_INCLUDE}/libsmb2-dcerpc-srvsvc.h
    ${SMB2_INCLUDE}/libsmb2-dcerpc-wkssvc.h
    ${SMB2_INCLUDE}/libsmb2-dcerpc-winreg.h
    ${SMB2_INCLUDE}/libsmb2-dcerpc.h
)

if(NOT ESP_PLATFORM AND NOT PICO_BOARD AND NOT (IOP AND BUILD_IRX))
  if(ENABLE_LIBDCERPC)
    add_library(dcerpc ${DCERPC_LIB_SOURCES} ${DCERPC_HEADERS})
    target_compile_definitions(dcerpc PRIVATE HAVE_DCERPC_FULL=1)
    if(NOT MSVC)
      target_compile_definitions(dcerpc PRIVATE "_U_=__attribute__((unused))")
    else()
      target_compile_definitions(dcerpc PRIVATE "_U_=")
    endif()
    target_link_libraries(dcerpc PUBLIC smb2 ${core_DEPENDS} ${CORE_LIBRARIES})
    target_include_directories(dcerpc PUBLIC ${INCLUDE_PATH}
                                     PRIVATE ../lib)
    set_target_properties(dcerpc PROPERTIES
                               VERSION ${PROJECT_VERSION}
                               SOVERSION 1
                               OUTPUT_NAME dcerpc)

    install(TARGETS dcerpc EXPORT dcerpc
                         RUNTIME DESTINATION bin
                         ARCHIVE DESTINATION lib${LIB_SUFFIX}
                         LIBRARY DESTINATION lib${LIB_SUFFIX})
  endif()
endif()
