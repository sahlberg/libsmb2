list(APPEND CORE_LIBRARIES ${POPT_LIBRARY})

set(SOURCES smb2-cat-async
            smb2-cat-sync
            smb2-ftruncate-sync
            smb2-ls-async
            smb2-put-async
            smb2-put-sync
            smb2-raw-stat-async
            smb2-raw-getsd-async
            smb2-readlink
            smb2-server-side-copy-sync
            smb2-lsa-lookupsids
            smb2-lseek-sync
            smb2-share-enum
            smb2-share-info
            smb2-stat-sync
            smb2-truncate-sync
            smb2-CMD-FIND
            smb2-server-sync
            smb2-notify
            smb2-set-security-info
            smb2-link-sync)

foreach(TARGET ${SOURCES})
  add_executable(${TARGET} ${TARGET}.c)
  target_link_libraries(${TARGET} smb2 ${CORE_LIBRARIES})
  add_dependencies(${TARGET} smb2)
  if(WIN32 AND BUILD_SHARED_LIBS)
    add_custom_command(TARGET ${TARGET} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              $<TARGET_FILE:smb2> $<TARGET_FILE_DIR:${TARGET}>)
  endif()
endforeach()

if(NOT MSVC)
  add_definitions(-Werror "-D_U_=__attribute__((unused))")
else()
  add_definitions("-D_U_=")
endif()
