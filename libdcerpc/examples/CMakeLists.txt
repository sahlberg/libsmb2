set(SOURCES epm-srvsvc
            smb2-lsa-lookupsids
            smb2-share-info
            smb2-winreg-enum)

foreach(TARGET ${SOURCES})
  add_executable(${TARGET} ${TARGET}.c)
  target_compile_options(${TARGET} PRIVATE -Wall -Werror)
  target_compile_definitions(${TARGET} PRIVATE "_U_=__attribute__((unused))")
  target_link_libraries(${TARGET} dcerpc)
endforeach()
