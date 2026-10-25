add_executable(kfs-keygen kfs-keygen.c)
target_link_libraries(kfs-keygen PRIVATE kfs::crypto)
kfs_apply_defaults(kfs-keygen)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(kfs-mkvol kfs-mkvol.c)
    target_link_libraries(kfs-mkvol PRIVATE kfs::fs)
    kfs_apply_defaults(kfs-mkvol)
endif()
