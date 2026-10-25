add_library(kfs_fs STATIC
    backend_local.c
    krypton_blockio.c
    krypton_cache.c
    krypton_fs.c
    krypton_meta.c
    krypton_volume.c)
add_library(kfs::fs ALIAS kfs_fs)

target_link_libraries(kfs_fs PUBLIC kfs::crypto kfs::scanner Threads::Threads)
kfs_apply_defaults(kfs_fs)
