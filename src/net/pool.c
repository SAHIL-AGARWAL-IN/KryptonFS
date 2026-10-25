/*
 * pool.c - Lazily dialled, pinned, per-peer RPC connections.
 */
#include "krypton/krypton_pool.h"

#include <stdio.h>
#include <string.h>

kfs_status kfs_pool_init(kfs_pool *p, const kfs_cluster_config *cluster,
                         const kfs_identity *self, uint32_t self_id,
                         const char *trusted_dir, char *err, size_t errlen)
{
    memset(p, 0, sizeof(*p));
    p->cluster = cluster;
    p->self = self;
    p->self_id = self_id;
    p->timeout_ms = cluster->rpc_timeout_ms;
    for (uint32_t i = 0; i < cluster->peer_count; i++) {
        kfs_peer_link *l = &p->links[i];

        pthread_mutex_init(&l->lock, NULL);
        l->conn.fd = -1;
        if (cluster->peers[i].node_id == self_id)
            continue;
        if (kfs_identity_load_peer(trusted_dir, cluster->peers[i].node_id, &l->key,
                                   err, errlen) != KFS_OK) {
            kfs_pool_destroy(p);
            return KFS_E_CONFIG;
        }
    }
    return KFS_OK;
}

void kfs_pool_destroy(kfs_pool *p)
{
    for (uint32_t i = 0; p->cluster != NULL && i < p->cluster->peer_count; i++) {
        kfs_peer_link *l = &p->links[i];

        if (l->conn.fd >= 0)
            kfs_conn_close(&l->conn);
        kfs_identity_free(l->key);
        l->key = NULL;
        pthread_mutex_destroy(&l->lock);
    }
}

static kfs_status dial(kfs_pool *p, uint32_t peer, kfs_peer_link *l)
{
    const kfs_peer *dst = &p->cluster->peers[peer];
    kfs_status st;
    int fd;

    st = kfs_tcp_connect(dst->host, dst->rpc_port, p->timeout_ms, &fd);
    if (st == KFS_OK)
        st = kfs_conn_init(&l->conn, fd, p->timeout_ms);
    if (st == KFS_OK) {
        st = kfs_conn_handshake_client(&l->conn, p->self, p->self_id, l->key, dst->node_id);
        if (st != KFS_OK)
            kfs_conn_close(&l->conn);
    }
    return st;
}

kfs_status kfs_pool_call(kfs_pool *p, uint32_t peer, uint16_t opcode, uint64_t block_id,
                         const kfs_buf *parts, size_t nparts, kfs_status *remote,
                         uint8_t *out, size_t cap, size_t *out_len)
{
    kfs_peer_link *l;
    kfs_status st = KFS_E_UNAVAILABLE;

    if (peer >= p->cluster->peer_count || p->links[peer].key == NULL)
        return KFS_E_INVAL;
    l = &p->links[peer];
    pthread_mutex_lock(&l->lock);
    for (int attempt = 0; attempt < 2; attempt++) {
        const uint8_t *body;
        size_t body_len;

        if (!kfs_conn_ready(&l->conn) && dial(p, peer, l) != KFS_OK) {
            st = KFS_E_UNAVAILABLE;
            break; /* unreachable or failed authentication: no retry */
        }
        st = kfs_conn_call(&l->conn, opcode, block_id, parts, nparts, remote, &body, &body_len);
        if (st == KFS_OK) {
            if (body_len > cap) {
                st = KFS_E_PROTO;
            } else {
                memcpy(out, body, body_len);
                *out_len = body_len;
            }
            break;
        }
        kfs_conn_close(&l->conn); /* desynchronized: redial */
        st = KFS_E_UNAVAILABLE;
    }
    pthread_mutex_unlock(&l->lock);
    return st;
}
