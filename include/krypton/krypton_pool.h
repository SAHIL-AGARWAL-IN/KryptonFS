/*
 * krypton_pool.h - One authenticated connection per cluster peer.
 *
 * Each peer's public key is pinned when the pool is created (a missing
 * key fails creation, surfacing misconfiguration early). Connections are
 * dialled and handshaken on first use. A transport failure closes the
 * connection and the call is retried once on a fresh one, which also
 * covers servers that close idle connections; every block RPC is
 * idempotent, so a retry is always safe. Calls to the same peer are
 * serialized; calls to different peers run in parallel.
 */
#ifndef KRYPTON_POOL_H
#define KRYPTON_POOL_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "krypton_config.h"
#include "krypton_keystore.h"
#include "krypton_rpc.h"

typedef struct kfs_peer_link {
    pthread_mutex_t lock;
    kfs_conn        conn;
    kfs_identity   *key; /* pinned public key; NULL for ourselves */
} kfs_peer_link;

typedef struct kfs_pool {
    const kfs_cluster_config *cluster;
    const kfs_identity       *self;
    uint32_t                  self_id;
    uint32_t                  timeout_ms;
    kfs_peer_link             links[KFS_MAX_PEERS];
} kfs_pool;

kfs_status kfs_pool_init(kfs_pool *p, const kfs_cluster_config *cluster,
                         const kfs_identity *self, uint32_t self_id,
                         const char *trusted_dir, char *err, size_t errlen);
void kfs_pool_destroy(kfs_pool *p);

/*
 * One round trip to cluster->peers[peer]. On KFS_OK, *remote is the
 * peer's status and the reply body (after the status) is copied to out.
 * KFS_E_UNAVAILABLE if the peer cannot be reached or authenticated,
 * KFS_E_PROTO if the body exceeds cap.
 */
kfs_status kfs_pool_call(kfs_pool *p, uint32_t peer, uint16_t opcode, uint64_t block_id,
                         const kfs_buf *parts, size_t nparts, kfs_status *remote,
                         uint8_t *out, size_t cap, size_t *out_len);

#endif /* KRYPTON_POOL_H */
