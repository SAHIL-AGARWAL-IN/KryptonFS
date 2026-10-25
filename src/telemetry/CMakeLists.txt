add_library(kfs_telemetry STATIC
    telemetry_server.c)
add_library(kfs::telemetry ALIAS kfs_telemetry)

target_link_libraries(kfs_telemetry PUBLIC kfs::fs kfs::net kfs::sandbox)
kfs_apply_defaults(kfs_telemetry)
