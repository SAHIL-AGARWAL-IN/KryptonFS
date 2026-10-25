/*
 * backend_net.c - kfs_backend over the replicated storage cluster.
 *
 * A block's replica set is its top `replication` peers by rendezvous
 * placement. Writes go to the first usable replica, which stores the
 * block and forwards it to the rest; reads ask replicas one at a time
 * (the block I/O layer decides whether a copy is fresh enough). Healthy
 * replicas are tried before ones known to be down.
 */
#include "krypton/krypton_backend.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "krypton/krypton_cluster.h"
#include "krypton/krypton_keystore.h"
#include "krypton/krypton_net_backend.h"
#include "krypton/krypton_pool.h"

typedef struct net_backend {
    kfs_backend        base; /* first: kfs_backend * converts to net_backend * */
    kfs_cluster_config cluster;
    kfs_identity      *self;
    kfs_health        *health;
    kfs_heartbeat_svc *heartbeat;
    kfs_pool           pool;
    bool               pool_ready;
} net_backend;

static net_backend *net_of(kfs_backend *b)
{
    return (net_backend *)(void *)b;
}

/* The block's replicas, usable ones first, otherwise in placement order. */
static size_t replica_order(net_backend *nb, uint64_t id, uint32_t *out)
{
    uint32_t placed[KFS_MAX_PEERS];
    size_t n = kfs_placement(&nb->cluster, id, placed, nb->cluster.replication), k = 0;

    for (size_t pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < n; i++) {
            bool usable = kfs_health_usable(nb->health, nb->cluster.peers[placed[i]].node_id);

            if (usable == (pass == 0))
                out[k++] = placed[i];
        }
    }
    return k;
}

static kfs_status net_put(kfs_backend *b, uint64_t id, const uint8_t *buf, size_t len)
{
    net_backend *nb = net_of(b);
    uint32_t order[KFS_MAX_PEERS];
    size_t n = replica_order(nb, id, order);
    kfs_buf part = { buf, len };

    for (size_t i = 0; i < n; i++) {
        uint8_t body[4];
        size_t body_len = 0;
        kfs_status remote = KFS_E_IO;
        kfs_status st = kfs_pool_call(&nb->pool, order[i], KFS_OP_BLOCK_WRITE, id, &part, 1,
                                      &remote, body, sizeof(body), &body_len);

        if (st == KFS_OK && remote == KFS_OK)
            return KFS_OK; /* the receiving node replicates onwards */
    }
    return KFS_E_UNAVAILABLE;
}

static kfs_status net_get(kfs_backend *b, uint64_t id, uint32_t replica,
                          uint8_t *buf, size_t cap, size_t *len)
{
    net_backend *nb = net_of(b);
    uint32_t order[KFS_MAX_PEERS];
    size_t n = replica_order(nb, id, order);
    kfs_status remote = KFS_E_IO, st;

    if (replica >= n)
        return KFS_E_UNAVAILABLE;
    st = kfs_pool_call(&nb->pool, order[replica], KFS_OP_BLOCK_READ, id, NULL, 0,
                       &remote, buf, cap, len);
    if (st != KFS_OK)
        return st == KFS_E_PROTO ? KFS_E_PROTO : KFS_E_UNAVAILABLE;
    if (remote == KFS_E_NOT_FOUND)
        return KFS_E_NOT_FOUND;
    return remote == KFS_OK ? KFS_OK : KFS_E_UNAVAILABLE;
}

static kfs_status net_del(kfs_backend *b, uint64_t id)
{
    net_backend *nb = net_of(b);
    uint32_t order[KFS_MAX_PEERS];
    size_t n = replica_order(nb, id, order);

    for (size_t i = 0; i < n; i++) {
        uint8_t body[4];
        size_t body_len = 0;
        kfs_status remote = KFS_E_IO;

        if (kfs_pool_call(&nb->pool, order[i], KFS_OP_BLOCK_DELETE, id, NULL, 0, &remote,
                          body, sizeof(body), &body_len) == KFS_OK && remote == KFS_OK)
            return KFS_OK;
    }
    return KFS_E_UNAVAILABLE;
}

static void net_close(kfs_backend *b)
{
    net_backend *nb = net_of(b);

    kfs_heartbeat_stop(nb->heartbeat);
    if (nb->pool_ready)
        kfs_pool_destroy(&nb->pool);
    kfs_health_free(nb->health);
    kfs_identity_free(nb->self);
    free(nb);
}

static const kfs_backend_ops NET_OPS = { net_put, net_get, net_del, net_close };

kfs_status kfs_backend_open_cluster(const kfs_config *cfg, kfs_backend **out,
                                    char *err, size_t errlen)
{
    net_backend *nb = calloc(1, sizeof(*nb));
    uint8_t cluster_key[KFS_KEY_SIZE];
    kfs_heartbeat_opts ho;
    kfs_status st;

    if (nb == NULL)
        return KFS_E_NOMEM;
    nb->base.ops = &NET_OPS;
    nb->cluster = cfg->cluster;
    nb->base.replicas = cfg->cluster.replication;

    st = kfs_identity_load_private(cfg->crypto.node_key, &nb->self, err, errlen);
    if (st == KFS_OK)
        st = kfs_secret_read(cfg->crypto.cluster_key, cluster_key, sizeof(cluster_key),
                             err, errlen);
    if (st == KFS_OK) {
        st = kfs_pool_init(&nb->pool, &nb->cluster, nb->self, cfg->node.node_id,
                           cfg->crypto.trusted_keys, err, errlen);
        nb->pool_ready = st == KFS_OK;
    }
    if (st == KFS_OK) {
        nb->health = kfs_health_new(&nb->cluster);
        st = nb->health != NULL ? KFS_OK : KFS_E_NOMEM;
    }
    if (st == KFS_OK) {
        memset(&ho, 0, sizeof(ho));
        ho.role = KFS_ROLE_CLIENT;
        ho.cluster = &nb->cluster;
        ho.cluster_key = cluster_key;
        ho.self_id = cfg->node.node_id;
        st = kfs_heartbeat_start(&ho, nb->health, &nb->heartbeat);
        if (st != KFS_OK && err != NULL)
            snprintf(err, errlen, "cannot open a heartbeat socket");
    }
    kfs_wipe(cluster_key, sizeof(cluster_key));
    if (st != KFS_OK) {
        net_close(&nb->base);
        return st;
    }
    *out = &nb->base;
    return KFS_OK;
}

kfs_health *kfs_backend_cluster_health(kfs_backend *b)
{
    return b->ops == &NET_OPS ? net_of(b)->health : NULL;
}
