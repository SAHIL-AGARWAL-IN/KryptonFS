add_executable(kfs-keygen kfs-keygen.c)
target_link_libraries(kfs-keygen PRIVATE kfs::crypto)
kfs_apply_defaults(kfs-keygen)
