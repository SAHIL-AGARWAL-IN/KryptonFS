add_executable(kfs-noded kfs_noded.c)
target_link_libraries(kfs-noded PRIVATE kfs::net kfs::fs)
kfs_apply_defaults(kfs-noded)
