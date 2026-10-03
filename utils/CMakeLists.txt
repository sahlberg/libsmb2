set(SOURCES smb2-cp
            smb2-ls)

set(DCERPC_SOURCES dcerpc
            epm-enum)

foreach(TARGET ${SOURCES})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} smb2 ${CORE_LIBRARIES})
  add_dependencies(${TARGET} smb2)
  install(TARGETS ${TARGET} RUNTIME DESTINATION bin)
endforeach()

if(ENABLE_LIBDCERPC AND TARGET dcerpc)
  find_package(Curses)
  if(CURSES_FOUND)
    list(APPEND DCERPC_SOURCES winreg-tui)
  endif()

  foreach(SRC ${DCERPC_SOURCES})
    # The target name "dcerpc" belongs to the library; the binary keeps it.
    if(SRC STREQUAL "dcerpc")
      set(TARGET dcerpc-tool)
    else()
      set(TARGET ${SRC})
    endif()
    add_executable(${TARGET} ${SRC}.c)
    set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME ${SRC})
    target_link_libraries(${TARGET} dcerpc smb2 ${CORE_LIBRARIES})
    add_dependencies(${TARGET} dcerpc smb2)
    install(TARGETS ${TARGET} RUNTIME DESTINATION bin)
  endforeach()

  target_link_libraries(dcerpc-tool ${CMAKE_DL_LIBS})

  if(CURSES_FOUND)
    target_link_libraries(winreg-tui ${CURSES_LIBRARIES})
    target_include_directories(winreg-tui PRIVATE ${CURSES_INCLUDE_DIRS})
  endif()
endif()

if(NOT MSVC)
  add_definitions(-Werror "-D_U_=__attribute__((unused))")
else()
  add_definitions("-D_U_=")
endif()
