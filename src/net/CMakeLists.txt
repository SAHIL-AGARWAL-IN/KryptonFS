add_library(kfs_net STATIC
    backend_net.c
    cluster.c
    heartbeat.c
    pool.c
    rpc_conn.c
    rpc_handshake.c)
add_library(kfs::net ALIAS kfs_net)

target_link_libraries(kfs_net PUBLIC kfs::crypto Threads::Threads)
kfs_apply_defaults(kfs_net)
