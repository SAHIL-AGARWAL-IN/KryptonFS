/*
 * krypton_cluster.h - Block placement, peer health and UDP heartbeats
 * (Linux).
 *
 * Placement uses rendezvous (highest-random-weight) hashing: every host
 * ranks all configured peers by hash(node_id, block_id) and the top
 * `replication` peers hold the block, in that order. All clients and
 * nodes compute the same answer from the shared peer list, nothing needs
 * coordinating, and adding a node moves only the blocks it now wins.
 * The replica set ignores health, so a down node keeps its role and
 * catches up later; health only decides who is asked first.
 *
 * Heartbeats (wire format in krypton_protocol.h, IPv4):
 *   nodes   send BEAT to every other peer each interval and answer PING
 *           with PONG
 *   clients send PING to every peer each interval; the PONG echoes the
 *           client's timestamp, giving RTT on the client's own clock
 * Every datagram is verified with the cluster key and must carry a
 * sequence number above the last one accepted from that node. A peer not
 * heard from within heartbeat_timeout_ms is marked DOWN.
 */
#ifndef KRYPTON_CLUSTER_H
#define KRYPTON_CLUSTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "krypton_common.h"
#include "krypton_config.h"
#include "krypton_crypto.h"
#include "krypton_protocol.h"

/* Writes the indexes (into cl->peers) of the block's top `want` peers,
 * best first; returns how many were written (at most peer_count). */
size_t kfs_placement(const kfs_cluster_config *cl, uint64_t block_id,
                     uint32_t *out, size_t want);

typedef struct kfs_peer_health {
    uint32_t       node_id;
    kfs_node_state state;
    int64_t        last_seen_ns; /* CLOCK_MONOTONIC; 0 = never */
    int64_t        rtt_ns;       /* clients only; 0 = unknown */
    uint64_t       disk_total;
    uint64_t       disk_used;
} kfs_peer_health;

typedef struct kfs_health kfs_health;

kfs_health *kfs_health_new(const kfs_cluster_config *cl);
void kfs_health_free(kfs_health *h);

/* Accepts a verified heartbeat from a known peer. KFS_E_NOT_FOUND for an
 * unknown node, KFS_E_AUTH for a replayed (non-increasing) sequence. */
kfs_status kfs_health_observe(kfs_health *h, const kfs_heartbeat *hb, int64_t now_ns);
void kfs_health_set_rtt(kfs_health *h, uint32_t node_id, int64_t rtt_ns);

/* Marks peers silent for longer than the timeout DOWN. */
void kfs_health_expire(kfs_health *h, int64_t now_ns);

/* False only for peers known to be DOWN or DRAINING: unknown peers are
 * worth trying. */
bool kfs_health_usable(kfs_health *h, uint32_t node_id);

/* Copies up to cap entries (in peer-list order); returns the count. */
size_t kfs_health_snapshot(kfs_health *h, kfs_peer_health *out, size_t cap);

typedef struct kfs_heartbeat_svc kfs_heartbeat_svc;

typedef struct kfs_heartbeat_opts {
    kfs_role                  role;
    const kfs_cluster_config *cluster;
    const uint8_t            *cluster_key;  /* KFS_KEY_SIZE bytes */
    uint32_t                  self_id;
    const char               *bind_addr;    /* nodes; clients bind 0.0.0.0 */
    uint16_t                  port;         /* nodes: hb_port; clients: 0 */
    const char               *data_dir;     /* nodes: reported disk usage */
} kfs_heartbeat_opts;

/* Copies the key; the cluster config must outlive the service. */
kfs_status kfs_heartbeat_start(const kfs_heartbeat_opts *opts, kfs_health *health,
                               kfs_heartbeat_svc **out);
void kfs_heartbeat_stop(kfs_heartbeat_svc *svc);

int64_t kfs_mono_ns(void);

#endif /* KRYPTON_CLUSTER_H */
