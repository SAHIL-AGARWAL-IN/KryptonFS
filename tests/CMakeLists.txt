foreach(name config ipc protocol)
    add_executable(test_${name} test_${name}.c)
    target_link_libraries(test_${name} PRIVATE kfs::common)
    kfs_apply_defaults(test_${name})
    add_test(NAME ${name} COMMAND test_${name})
endforeach()

# The shipped example configuration must always load and validate.
target_compile_definitions(test_config PRIVATE
    KFS_EXAMPLE_CONFIG="${PROJECT_SOURCE_DIR}/config/kryptonfs.conf.example")
