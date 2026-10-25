add_executable(kryptonfs krypton_fuse.c)
target_link_libraries(kryptonfs PRIVATE kfs::fs kfs::sandbox PkgConfig::FUSE3)
kfs_apply_defaults(kryptonfs)
