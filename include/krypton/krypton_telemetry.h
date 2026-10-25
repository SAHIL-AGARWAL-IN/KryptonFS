/*
 * krypton_telemetry.h - Live metrics and audit events for the dashboard
 * (Linux).
 *
 * The daemon serves newline-delimited JSON on a Unix socket. The socket
 * is created mode 0600 (owner only): the tree message carries decrypted
 * file names. Every interval each connected client receives:
 *
 *   {"type":"snapshot", "ts_ms":..., "interval_ms":...,
 *    "volume":  {"name","mountpoint","backend","block_size"},
 *    "io":      {"read_ops","write_ops","read_bytes","write_bytes",
 *                "read_lat_us","write_lat_us","read_lat_max_us",
 *                "write_lat_max_us","errors"},        (this interval only)
 *    "cache":   {"frames","used","dirty","hits","misses","evictions"},
 *    "usage":   {"files","dirs","data_blocks"},
 *    "nodes":   [{"id","state","rtt_us","disk_total","disk_used",
 *                 "last_seen_ms"}],                   (cluster backend only)
 *    "sandbox": {"failed", "workers":[{"pid","kind","alive"}]},
 *    "keys":    {"cipher","kdf","kdf_iterations","volume_key",
 *                "identity_id"},
 *    "events":  [{"seq","ts_ms","level","kind","msg"}]} (new since last)
 *
 * and every tree_every-th interval (and on connect):
 *
 *   {"type":"tree", "entries":[{"path","dir","size","depth"}],
 *    "truncated":bool}
 *
 * A client that falls behind (its socket buffer fills) is disconnected
 * rather than allowed to stall the daemon. New clients first get the most
 * recent events as {"type":"events", "events":[...]}.
 *
 * All entry points accept a NULL telemetry handle and do nothing, so
 * callers need no "is telemetry enabled" checks.
 */
#ifndef KRYPTON_TELEMETRY_H
#define KRYPTON_TELEMETRY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "krypton_cluster.h"
#include "krypton_common.h"
#include "krypton_fs.h"
#include "krypton_sandbox.h"

typedef enum kfs_event_level {
    KFS_EV_INFO,
    KFS_EV_WARN,
    KFS_EV_ALERT
} kfs_event_level;

typedef struct kfs_telemetry_sources {
    kfs_fs      *fs;
    kfs_sandbox *sandbox;        /* NULL if none */
    kfs_health  *health;         /* NULL for the local backend */
    const char  *volume_name;
    const char  *mountpoint;
    const char  *backend;        /* "cluster" or "local" */
    uint32_t     block_size;
    uint32_t     kdf_iterations;
    uint32_t     crypto_workers;
    uint32_t     identity_id;    /* 0 when not in a cluster */
} kfs_telemetry_sources;

typedef struct kfs_telemetry kfs_telemetry;

/* Strings in src are copied. The socket's parent directory is created
 * mode 0700 if missing; a stale socket file is replaced. */
kfs_status kfs_telemetry_start(const char *socket_path, uint32_t interval_ms,
                               const kfs_telemetry_sources *src, kfs_telemetry **out);
void kfs_telemetry_stop(kfs_telemetry *t);

/* One completed read or write, for IOPS, throughput and latency. */
void kfs_telemetry_io(kfs_telemetry *t, bool write, size_t bytes, int64_t latency_ns, bool ok);

void kfs_telemetry_event(kfs_telemetry *t, kfs_event_level level, const char *kind,
                         const char *fmt, ...) KFS_PRINTF_FMT(4, 5);

#endif /* KRYPTON_TELEMETRY_H */
