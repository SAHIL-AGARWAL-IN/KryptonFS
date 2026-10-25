/*
 * cluster.c - Rendezvous placement and the peer health table.
 */
#define _POSIX_C_SOURCE 200809L

#include "krypton/krypton_cluster.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct kfs_health {
    pthread_mutex_t     lock;
    kfs_peer_health     peers[KFS_MAX_PEERS];
    uint64_t            last_seq[KFS_MAX_PEERS];
    size_t              count;
    int64_t             started_ns;
    int64_t             timeout_ns;
};

int64_t kfs_mono_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static uint64_t mix64(uint64_t x)
{
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

size_t kfs_placement(const kfs_cluster_config *cl, uint64_t block_id,
                     uint32_t *out, size_t want)
{
    uint64_t score[KFS_MAX_PEERS];
    uint32_t order[KFS_MAX_PEERS];
    size_t n = cl->peer_count;

    for (uint32_t i = 0; i < n; i++) {
        score[i] = mix64(block_id ^ mix64(cl->peers[i].node_id));
        order[i] = i;
    }
    /* Partial selection sort: only the top `want` matter. */
    if (want > n)
        want = n;
    for (size_t i = 0; i < want; i++) {
        size_t best = i;

        for (size_t j = i + 1; j < n; j++) {
            if (score[order[j]] > score[order[best]] ||
                (score[order[j]] == score[order[best]] &&
                 cl->peers[order[j]].node_id < cl->peers[order[best]].node_id))
                best = j;
        }
        {
            uint32_t t = order[i];

            order[i] = order[best];
            order[best] = t;
        }
        out[i] = order[i];
    }
    return want;
}

kfs_health *kfs_health_new(const kfs_cluster_config *cl)
{
    kfs_health *h = calloc(1, sizeof(*h));

    if (h == NULL)
        return NULL;
    pthread_mutex_init(&h->lock, NULL);
    h->count = cl->peer_count;
    for (size_t i = 0; i < h->count; i++) {
        h->peers[i].node_id = cl->peers[i].node_id;
        h->peers[i].state = KFS_NODE_UNKNOWN;
    }
    h->started_ns = kfs_mono_ns();
    h->timeout_ns = (int64_t)cl->heartbeat_timeout_ms * 1000000;
    return h;
}

void kfs_health_free(kfs_health *h)
{
    if (h == NULL)
        return;
    pthread_mutex_destroy(&h->lock);
    free(h);
}

static kfs_peer_health *find(kfs_health *h, uint32_t node_id, size_t *idx)
{
    for (size_t i = 0; i < h->count; i++) {
        if (h->peers[i].node_id == node_id) {
            if (idx != NULL)
                *idx = i;
            return &h->peers[i];
        }
    }
    return NULL;
}

kfs_status kfs_health_observe(kfs_health *h, const kfs_heartbeat *hb, int64_t now_ns)
{
    kfs_peer_health *p;
    size_t idx = 0;
    kfs_status st = KFS_OK;

    pthread_mutex_lock(&h->lock);
    p = find(h, hb->node_id, &idx);
    if (p == NULL) {
        st = KFS_E_NOT_FOUND;
    } else if (p->last_seen_ns != 0 && hb->seq <= h->last_seq[idx]) {
        st = KFS_E_AUTH; /* replayed or reordered datagram */
    } else {
        h->last_seq[idx] = hb->seq;
        p->state = (kfs_node_state)hb->state;
        p->last_seen_ns = now_ns;
        p->disk_total = hb->disk_total;
        p->disk_used = hb->disk_used;
    }
    pthread_mutex_unlock(&h->lock);
    return st;
}

void kfs_health_set_rtt(kfs_health *h, uint32_t node_id, int64_t rtt_ns)
{
    kfs_peer_health *p;

    pthread_mutex_lock(&h->lock);
    p = find(h, node_id, NULL);
    if (p != NULL)
        p->rtt_ns = rtt_ns;
    pthread_mutex_unlock(&h->lock);
}

void kfs_health_expire(kfs_health *h, int64_t now_ns)
{
    pthread_mutex_lock(&h->lock);
    for (size_t i = 0; i < h->count; i++) {
        int64_t since = h->peers[i].last_seen_ns != 0 ? h->peers[i].last_seen_ns : h->started_ns;

        if (now_ns - since > h->timeout_ns)
            h->peers[i].state = KFS_NODE_DOWN;
    }
    pthread_mutex_unlock(&h->lock);
}

bool kfs_health_usable(kfs_health *h, uint32_t node_id)
{
    kfs_peer_health *p;
    bool usable = true;

    pthread_mutex_lock(&h->lock);
    p = find(h, node_id, NULL);
    if (p != NULL)
        usable = p->state != KFS_NODE_DOWN && p->state != KFS_NODE_DRAINING;
    pthread_mutex_unlock(&h->lock);
    return usable;
}

size_t kfs_health_snapshot(kfs_health *h, kfs_peer_health *out, size_t cap)
{
    size_t n;

    pthread_mutex_lock(&h->lock);
    n = h->count < cap ? h->count : cap;
    memcpy(out, h->peers, n * sizeof(*out));
    pthread_mutex_unlock(&h->lock);
    return n;
}
