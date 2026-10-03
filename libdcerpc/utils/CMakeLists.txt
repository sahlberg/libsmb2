set(SOURCES dcerpc
            epm-enum)

find_package(Curses)
if(CURSES_FOUND)
  list(APPEND SOURCES winreg-tui)
endif()

foreach(SRC ${SOURCES})
  # The target name "dcerpc" belongs to the library; the binary keeps it.
  if(SRC STREQUAL "dcerpc")
    set(TARGET dcerpc-tool)
  else()
    set(TARGET ${SRC})
  endif()
  add_executable(${TARGET} ${SRC}.c)
  set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME ${SRC})
  target_compile_options(${TARGET} PRIVATE -Wall -Werror)
  target_compile_definitions(${TARGET} PRIVATE "_U_=__attribute__((unused))")
  target_link_libraries(${TARGET} dcerpc)
  install(TARGETS ${TARGET} RUNTIME DESTINATION ${INSTALL_BIN_DIR})
endforeach()

target_link_libraries(dcerpc-tool ${CMAKE_DL_LIBS})

if(CURSES_FOUND)
  target_link_libraries(winreg-tui ${CURSES_LIBRARIES})
  target_include_directories(winreg-tui PRIVATE ${CURSES_INCLUDE_DIRS})
endif()
