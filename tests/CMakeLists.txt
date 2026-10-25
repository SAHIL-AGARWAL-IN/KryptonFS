foreach(name config ipc protocol)
    add_executable(test_${name} test_${name}.c)
    target_link_libraries(test_${name} PRIVATE kfs::common)
    kfs_apply_defaults(test_${name})
    add_test(NAME ${name} COMMAND test_${name})
endforeach()

add_executable(test_crypto test_crypto.c)
target_link_libraries(test_crypto PRIVATE kfs::crypto)
kfs_apply_defaults(test_crypto)
add_test(NAME crypto COMMAND test_crypto)

set(KFS_TEST_TMPDIR ${CMAKE_CURRENT_BINARY_DIR}/tmp)
file(MAKE_DIRECTORY ${KFS_TEST_TMPDIR})
add_executable(test_keystore test_keystore.c)
target_link_libraries(test_keystore PRIVATE kfs::crypto)
target_compile_definitions(test_keystore PRIVATE KFS_TEST_TMPDIR="${KFS_TEST_TMPDIR}")
kfs_apply_defaults(test_keystore)
add_test(NAME keystore COMMAND test_keystore)

add_executable(test_scanner test_scanner.c)
target_link_libraries(test_scanner PRIVATE kfs::scanner)
kfs_apply_defaults(test_scanner)
add_test(NAME scanner COMMAND test_scanner)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_sandbox test_sandbox.c)
    target_link_libraries(test_sandbox PRIVATE kfs::sandbox)
    kfs_apply_defaults(test_sandbox)
    add_test(NAME sandbox COMMAND test_sandbox)
endif()

# The shipped example configuration must always load and validate.
target_compile_definitions(test_config PRIVATE
    KFS_EXAMPLE_CONFIG="${PROJECT_SOURCE_DIR}/config/kryptonfs.conf.example")
