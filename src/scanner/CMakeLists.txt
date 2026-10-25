add_library(kfs_scanner STATIC
    malware_scanner.c)
add_library(kfs::scanner ALIAS kfs_scanner)

target_link_libraries(kfs_scanner PUBLIC kfs::common)
kfs_apply_defaults(kfs_scanner)
