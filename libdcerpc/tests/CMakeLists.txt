# Coder transcoding tests; run with ctest in the libdcerpc build directory.
# Each test program holds the known-good NDR and YAML for one interface;
# coder-test.c runs them.
set(TESTS wkssvc-coder-test srvsvc-coder-test winreg-coder-test
    lsa-coder-test samr-coder-test dssetup-coder-test netlogon-coder-test epm-coder-test)

foreach(TEST ${TESTS})
  add_executable(${TEST} ${TEST}.c coder-test.c)
  target_link_libraries(${TEST} dcerpc)
  add_test(NAME ${TEST} COMMAND ${TEST})
endforeach()

# The server runtime (dcerpc/server.h), without a transport
add_executable(server-test server-test.c)
target_link_libraries(server-test dcerpc)
add_test(NAME server-test COMMAND server-test)

add_executable(schannel-test schannel-test.c)
target_link_libraries(schannel-test dcerpc)
add_test(NAME schannel-test COMMAND schannel-test)

# schannel-rpc-test plays the server over a fake transport: it provides
# the smb2_cmd_*_async() calls, so it needs the libsmb2 transport, and
# its definitions must win over libsmb2's in a static build too.
if(WITH_LIBSMB2)
  add_executable(schannel-rpc-test schannel-rpc-test.c)
  target_compile_definitions(schannel-rpc-test PRIVATE
                             "_U_=__attribute__((unused))")
  target_link_libraries(schannel-rpc-test dcerpc
                        -Wl,--allow-multiple-definition)
  add_test(NAME schannel-rpc-test COMMAND schannel-rpc-test)
endif()

# codertest.idl is a test-only interface for NDR layouts the real
# interfaces do not exercise. Its coders use only the public libdcerpc API
# (idlcomp without --libdcerpc) and are built into the test program.
set(CODERTEST_GEN ${CMAKE_CURRENT_BINARY_DIR})
add_custom_command(
  OUTPUT ${CODERTEST_GEN}/codertest_coder.c ${CODERTEST_GEN}/codertest_coder.h
  COMMAND ${PYTHON3} ${CMAKE_CURRENT_SOURCE_DIR}/../idlcomp.py
          ${CMAKE_CURRENT_SOURCE_DIR}/codertest.idl
          -o ${CODERTEST_GEN}/codertest_coder.c.tmp
          --header ${CODERTEST_GEN}/codertest_coder.h
          --server-header ${CODERTEST_GEN}/codertest_server.h
  COMMAND ${CMAKE_COMMAND} -E rename ${CODERTEST_GEN}/codertest_coder.c.tmp
          ${CODERTEST_GEN}/codertest_coder.c
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/codertest.idl
          ${CMAKE_CURRENT_SOURCE_DIR}/../idlcomp.py
  COMMENT "Generating codertest coders from codertest.idl"
  VERBATIM)
add_executable(codertest-coder-test codertest-coder-test.c coder-test.c
               ${CODERTEST_GEN}/codertest_coder.c)
target_include_directories(codertest-coder-test PRIVATE ${CODERTEST_GEN})
target_link_libraries(codertest-coder-test dcerpc)
add_test(NAME codertest-coder-test COMMAND codertest-coder-test)
