/*
 * krypton_config.h - Runtime configuration for the FUSE client
 * (kryptonfs) and the storage node daemon (kfs-noded).
 *
 * One INI-style file serves both roles; each daemon validates what its
 * role needs with kfs_config_validate(). config/kryptonfs.conf.example
 * documents every key.
 *
 *   [section]
 *   key = value        # full-line comments start with '#' or ';'
 *
 * Sizes accept K/M/G suffixes (powers of 1024). Booleans accept
 * true/false, yes/no, on/off and 1/0. Strings may be double-quoted.
 * [cluster] peer may repeat; every other key keeps its last value.
 *
 * Parameters fixed at volume creation (block size, KDF salt and
 * iterations) live in the volume header on the cluster, not here.
 */
#ifndef KRYPTON_CONFIG_H
#define KRYPTON_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "krypton_common.h"

#define KFS_MAX_PEERS 64
#define KFS_NAME_MAX  64

typedef enum kfs_role {
    KFS_ROLE_CLIENT, /* kryptonfs: FUSE mount + sandbox workers */
    KFS_ROLE_NODE    /* kfs-noded: storage node */
} kfs_role;

typedef enum kfs_scan_action {
    KFS_SCAN_REJECT, /* fail the write with EACCES */
    KFS_SCAN_LOG     /* allow the write, raise an audit event */
} kfs_scan_action;

typedef struct kfs_peer {
    uint32_t node_id;
    char     host[KFS_HOST_MAX];
    uint16_t rpc_port;
    uint16_t hb_port;
} kfs_peer;

/* [volume] - client */
typedef struct kfs_volume_config {
    char name[KFS_NAME_MAX];
    char mountpoint[KFS_PATH_MAX];
} kfs_volume_config;

/* [crypto] - both roles */
typedef struct kfs_crypto_config {
    char node_key[KFS_PATH_MAX];     /* this host's RSA-2048 private key (PEM) */
    char trusted_keys[KFS_PATH_MAX]; /* directory of pinned <node_id>.pub.pem */
    char cluster_key[KFS_PATH_MAX];  /* 32-byte heartbeat HMAC key */
} kfs_crypto_config;

/* [sandbox] - client */
typedef struct kfs_sandbox_config {
    uint32_t scan_workers;
    uint32_t crypto_workers;
    uint32_t ipc_slots;               /* shared-memory slots = blocks in flight */
    char     chroot_dir[KFS_PATH_MAX];
    uint32_t uid;                     /* identity workers drop to; never 0 */
    uint32_t gid;
} kfs_sandbox_config;

/* [cache] - client */
typedef struct kfs_cache_config {
    uint64_t size_bytes;   /* mmap page cache of plaintext blocks */
    uint32_t writeback_ms; /* dirty block flush interval */
    bool     lock_memory;  /* mlock() the cache so plaintext never swaps */
} kfs_cache_config;

/* [cluster] - both roles */
typedef struct kfs_cluster_config {
    kfs_peer peers[KFS_MAX_PEERS];
    uint32_t peer_count;
    uint32_t replication;           /* copies of each block */
    uint32_t heartbeat_interval_ms;
    uint32_t heartbeat_timeout_ms;  /* silence after which a node is DOWN */
    uint32_t rpc_timeout_ms;
} kfs_cluster_config;

/* [node] - storage node */
typedef struct kfs_node_config {
    uint32_t node_id;
    char     bind_addr[KFS_HOST_MAX];
    uint16_t rpc_port;
    uint16_t hb_port;
    char     data_dir[KFS_PATH_MAX];
    uint32_t io_threads;
    uint32_t max_connections;
} kfs_node_config;

/* [scanner] - client */
typedef struct kfs_scanner_config {
    bool            enabled;
    bool            block_elf;                /* refuse files starting with an ELF header */
    char            signatures[KFS_PATH_MAX]; /* extra signature DB; empty = built-ins */
    kfs_scan_action action;
} kfs_scanner_config;

/* [telemetry] - both roles */
typedef struct kfs_telemetry_config {
    bool     enabled;
    char     socket_path[KFS_PATH_MAX]; /* Unix socket the dashboard connects to */
    uint32_t interval_ms;
} kfs_telemetry_config;

typedef struct kfs_config {
    kfs_volume_config    volume;
    kfs_crypto_config    crypto;
    kfs_sandbox_config   sandbox;
    kfs_cache_config     cache;
    kfs_cluster_config   cluster;
    kfs_node_config      node;
    kfs_scanner_config   scanner;
    kfs_telemetry_config telemetry;
} kfs_config;

void kfs_config_defaults(kfs_config *cfg);

/*
 * Apply settings from text on top of the current contents of cfg (start
 * from kfs_config_defaults). Enforces syntax and per-key bounds; on
 * failure writes "line N: ..." to err, returns KFS_E_CONFIG and leaves cfg
 * partially updated.
 */
kfs_status kfs_config_parse(kfs_config *cfg, const char *text, size_t len,
                            char *err, size_t errlen);

/* kfs_config_parse() on a file of at most 1 MiB. */
kfs_status kfs_config_load(kfs_config *cfg, const char *path,
                           char *err, size_t errlen);

/* Cross-key consistency and the settings the given role requires. */
kfs_status kfs_config_validate(const kfs_config *cfg, kfs_role role,
                               char *err, size_t errlen);

#endif /* KRYPTON_CONFIG_H */
