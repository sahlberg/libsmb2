set(SOURCES smb2-cp
            smb2-ls)

foreach(TARGET ${SOURCES})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} smb2 ${CORE_LIBRARIES})
  add_dependencies(${TARGET} smb2)
  install(TARGETS ${TARGET} RUNTIME DESTINATION bin)
endforeach()

if(NOT MSVC)
  add_definitions(-Werror "-D_U_=__attribute__((unused))")
else()
  add_definitions("-D_U_=")
endif()
