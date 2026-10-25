add_library(kfs_common STATIC
    krypton_common.c
    krypton_config.c
    krypton_ipc.c
    krypton_protocol.c)
add_library(kfs::common ALIAS kfs_common)

target_include_directories(kfs_common PUBLIC ${PROJECT_SOURCE_DIR}/include)
kfs_apply_defaults(kfs_common)
