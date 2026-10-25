add_library(kfs_crypto STATIC
    krypton_crypto.c
    krypton_keystore.c)
add_library(kfs::crypto ALIAS kfs_crypto)

target_link_libraries(kfs_crypto PUBLIC kfs::common OpenSSL::Crypto)
kfs_apply_defaults(kfs_crypto)
