add_library(kfs_sandbox STATIC
    sandbox_worker.c)
add_library(kfs::sandbox ALIAS kfs_sandbox)

target_link_libraries(kfs_sandbox PUBLIC kfs::crypto kfs::scanner Threads::Threads)
kfs_apply_defaults(kfs_sandbox)
