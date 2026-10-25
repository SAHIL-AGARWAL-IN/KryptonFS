/*
 * kfs-noded - KryptonFS storage node.
 *
 *   kfs-noded [-c CONFIG]
 *
 * Stores and serves block envelopes for the cluster. A node never holds
 * volume keys: it sees only ciphertext envelopes and their generation.
 *
 * Threads:
 *   accept     queues authenticated-to-be connections, up to
 *              max_connections waiting or active
 *   io x N     io_threads workers; each handshakes one connection, then
 *              serves its requests until it closes or idles out
 *   heartbeat  UDP beats to peers, answers client pings
 *   main       waits for SIGINT / SIGTERM and shuts everything down
 *
 * Replication: a BLOCK_WRITE or BLOCK_DELETE from a client is applied
 * locally and then forwarded to the block's other replicas (REPLICATE /
 * BLOCK_DELETE from a peer is applied locally only, so nothing loops).
 * REPLICATE is accepted only from authenticated cluster peers.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <syslog.h>
#include <unistd.h>

#include "krypton/krypton_backend.h"
#include "krypton/krypton_cluster.h"
#include "krypton/krypton_config.h"
#include "krypton/krypton_keystore.h"
#include "krypton/krypton_pool.h"
#include "krypton/krypton_rpc.h"

typedef struct node {
    kfs_config         cfg;
    kfs_identity      *self;
    kfs_backend       *store;
    kfs_health        *health;
    kfs_heartbeat_svc *heartbeat;
    kfs_pool           pool;
    int                listen_fd;
    atomic_bool        stopping;

    pthread_mutex_t    qlock;
    pthread_cond_t     qcond;
    int               *queue;      /* accepted fds awaiting a worker */
    size_t             qhead, qlen, qcap;
    atomic_uint        active;     /* connections being served */
    int               *serving;    /* fd each worker serves, -1 if idle */
    pthread_t         *workers;
    struct worker_arg *args;
    pthread_t          acceptor;
} node;

typedef struct worker_arg {
    node  *n;
    size_t index;
} worker_arg;

static bool is_peer(const node *n, uint32_t id)
{
    for (uint32_t i = 0; i < n->cfg.cluster.peer_count; i++) {
        if (n->cfg.cluster.peers[i].node_id == id)
            return true;
    }
    return false;
}

/* Forwards a write (as REPLICATE) or a delete to the block's other
 * replicas; returns how many acknowledged. */
static uint32_t forward(node *n, uint16_t opcode, uint64_t id, const uint8_t *obj, size_t len)
{
    uint32_t placed[KFS_MAX_PEERS], acked = 0;
    size_t k = kfs_placement(&n->cfg.cluster, id, placed, n->cfg.cluster.replication);
    kfs_buf part = { obj, len };

    for (size_t i = 0; i < k; i++) {
        const kfs_peer *p = &n->cfg.cluster.peers[placed[i]];
        uint8_t body[16];
        size_t body_len = 0;
        kfs_status remote = KFS_E_IO;

        if (p->node_id == n->cfg.node.node_id || !kfs_health_usable(n->health, p->node_id))
            continue;
        if (kfs_pool_call(&n->pool, placed[i], opcode, id, len > 0 ? &part : NULL,
                          len > 0 ? 1 : 0, &remote, body, sizeof(body), &body_len) == KFS_OK &&
            remote == KFS_OK)
            acked++;
        else
            syslog(LOG_WARNING, "replica %u missed %s of block %016llx", p->node_id,
                   opcode == KFS_OP_REPLICATE ? "a write" : "a delete", (unsigned long long)id);
    }
    return acked;
}

/* Writes are refused past the same threshold at which heartbeats start
 * advertising DEGRADED, so the data directory never fills completely. */
static bool disk_full(const node *n)
{
    struct statvfs sv;

    if (statvfs(n->cfg.node.data_dir, &sv) != 0 || sv.f_blocks == 0)
        return false;
    return (sv.f_blocks - sv.f_bavail) * 100 / sv.f_blocks >= 95;
}

static kfs_status handle(node *n, kfs_conn *c, uint8_t *obj, const kfs_frame_hdr *h,
                         const uint8_t *p)
{
    bool from_peer = is_peer(n, c->peer_id);
    uint8_t out[12];
    kfs_buf body;
    size_t len = 0;
    kfs_status st;

    switch (h->opcode) {
    case KFS_OP_BLOCK_READ:
        st = kfs_backend_get(n->store, h->block_id, obj, KFS_OBJECT_MAX, &len);
        body = (kfs_buf){ obj, len };
        return kfs_conn_reply(c, h->opcode, h->block_id, st, &body, st == KFS_OK ? 1 : 0);

    case KFS_OP_BLOCK_WRITE:
    case KFS_OP_REPLICATE:
        if (h->opcode == KFS_OP_REPLICATE && !from_peer)
            return kfs_conn_reply(c, h->opcode, h->block_id, KFS_E_AUTH, NULL, 0);
        if (h->payload_len > KFS_OBJECT_MAX)
            return kfs_conn_reply(c, h->opcode, h->block_id, KFS_E_PROTO, NULL, 0);
        if (disk_full(n))
            return kfs_conn_reply(c, h->opcode, h->block_id, KFS_E_UNAVAILABLE, NULL, 0);
        st = kfs_backend_put(n->store, h->block_id, p, h->payload_len);
        if (h->opcode == KFS_OP_REPLICATE || st != KFS_OK)
            return kfs_conn_reply(c, h->opcode, h->block_id, st, NULL, 0);
        kfs_store_be32(out, 1 + (from_peer ? 0 : forward(n, KFS_OP_REPLICATE, h->block_id,
                                                          p, h->payload_len)));
        body = (kfs_buf){ out, 4 };
        return kfs_conn_reply(c, h->opcode, h->block_id, KFS_OK, &body, 1);

    case KFS_OP_BLOCK_DELETE:
        st = kfs_backend_del(n->store, h->block_id);
        if (st == KFS_OK && !from_peer)
            forward(n, KFS_OP_BLOCK_DELETE, h->block_id, NULL, 0);
        return kfs_conn_reply(c, h->opcode, h->block_id, st, NULL, 0);

    case KFS_OP_BLOCK_STAT:
        st = kfs_backend_get(n->store, h->block_id, obj, KFS_OBJECT_MAX, &len);
        kfs_store_be32(out, (uint32_t)len);
        kfs_store_be64(out + 4, st == KFS_OK && len >= KFS_ENVELOPE_HDR_SIZE
                                    ? kfs_load_be64(obj + KFS_ENVELOPE_OFF_GENERATION) : 0);
        body = (kfs_buf){ out, 12 };
        return kfs_conn_reply(c, h->opcode, h->block_id, st, &body, st == KFS_OK ? 1 : 0);

    default:
        return kfs_conn_reply(c, (uint16_t)(h->opcode & ~KFS_OP_REPLY), h->block_id,
                              KFS_E_INVAL, NULL, 0);
    }
}

static void serve(node *n, int fd, uint8_t *obj)
{
    kfs_conn c;

    if (kfs_conn_init(&c, fd, n->cfg.cluster.rpc_timeout_ms) != KFS_OK)
        return;
    if (kfs_conn_handshake_server(&c, n->self, n->cfg.node.node_id,
                                  n->cfg.crypto.trusted_keys) != KFS_OK) {
        kfs_conn_close(&c); /* unknown or unauthenticated peer: hang up */
        return;
    }
    while (!atomic_load(&n->stopping)) {
        kfs_frame_hdr h;
        const uint8_t *p;

        /* Idle connections time out; clients redial transparently. */
        if (kfs_conn_recv(&c, &h, &p) != KFS_OK || handle(n, &c, obj, &h, p) != KFS_OK)
            break;
    }
    kfs_conn_close(&c);
}

static void *io_worker(void *arg)
{
    node *n = ((worker_arg *)arg)->n;
    size_t me = ((worker_arg *)arg)->index;
    uint8_t *obj = malloc(KFS_OBJECT_MAX);

    pthread_mutex_lock(&n->qlock);
    while (obj != NULL) {
        int fd;

        while (n->qlen == 0 && !atomic_load(&n->stopping))
            pthread_cond_wait(&n->qcond, &n->qlock);
        if (atomic_load(&n->stopping))
            break;
        fd = n->queue[n->qhead];
        n->qhead = (n->qhead + 1) % n->qcap;
        n->qlen--;
        n->serving[me] = fd;
        pthread_mutex_unlock(&n->qlock);

        serve(n, fd, obj);

        pthread_mutex_lock(&n->qlock);
        n->serving[me] = -1;
        atomic_fetch_sub(&n->active, 1);
    }
    pthread_mutex_unlock(&n->qlock);
    free(obj);
    return NULL;
}

static void *acceptor(void *arg)
{
    node *n = arg;

    while (!atomic_load(&n->stopping)) {
        int fd = accept4(n->listen_fd, NULL, NULL, SOCK_CLOEXEC);

        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            break; /* listener shut down */
        }
        if (atomic_load(&n->active) >= n->cfg.node.max_connections) {
            close(fd); /* at capacity: refuse rather than queue unboundedly */
            continue;
        }
        atomic_fetch_add(&n->active, 1);
        pthread_mutex_lock(&n->qlock);
        n->queue[(n->qhead + n->qlen) % n->qcap] = fd;
        n->qlen++;
        pthread_cond_signal(&n->qcond);
        pthread_mutex_unlock(&n->qlock);
    }
    return NULL;
}

static int start(node *n)
{
    uint8_t cluster_key[KFS_KEY_SIZE];
    kfs_heartbeat_opts ho;
    char err[512];
    kfs_status st;

    if (kfs_identity_load_private(n->cfg.crypto.node_key, &n->self, err, sizeof(err)) != KFS_OK ||
        kfs_secret_read(n->cfg.crypto.cluster_key, cluster_key, sizeof(cluster_key),
                        err, sizeof(err)) != KFS_OK ||
        kfs_pool_init(&n->pool, &n->cfg.cluster, n->self, n->cfg.node.node_id,
                      n->cfg.crypto.trusted_keys, err, sizeof(err)) != KFS_OK) {
        fprintf(stderr, "kfs-noded: %s\n", err);
        return -1;
    }
    if (mkdir(n->cfg.node.data_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "kfs-noded: %s: %s\n", n->cfg.node.data_dir, strerror(errno));
        return -1;
    }
    if (kfs_backend_open_local(n->cfg.node.data_dir, &n->store) != KFS_OK) {
        fprintf(stderr, "kfs-noded: cannot open %s\n", n->cfg.node.data_dir);
        return -1;
    }

    n->health = kfs_health_new(&n->cfg.cluster);
    memset(&ho, 0, sizeof(ho));
    ho.role = KFS_ROLE_NODE;
    ho.cluster = &n->cfg.cluster;
    ho.cluster_key = cluster_key;
    ho.self_id = n->cfg.node.node_id;
    ho.bind_addr = n->cfg.node.bind_addr;
    ho.port = n->cfg.node.hb_port;
    ho.data_dir = n->cfg.node.data_dir;
    st = n->health != NULL ? kfs_heartbeat_start(&ho, n->health, &n->heartbeat) : KFS_E_NOMEM;
    kfs_wipe(cluster_key, sizeof(cluster_key));
    if (st != KFS_OK) {
        fprintf(stderr, "kfs-noded: cannot bind heartbeat port %u\n", n->cfg.node.hb_port);
        return -1;
    }
    if (kfs_tcp_listen(n->cfg.node.bind_addr, n->cfg.node.rpc_port, 128, &n->listen_fd) != KFS_OK) {
        fprintf(stderr, "kfs-noded: cannot listen on %s:%u\n", n->cfg.node.bind_addr,
                n->cfg.node.rpc_port);
        return -1;
    }

    n->qcap = n->cfg.node.max_connections;
    n->queue = calloc(n->qcap, sizeof(*n->queue));
    n->serving = malloc(n->cfg.node.io_threads * sizeof(*n->serving));
    n->workers = calloc(n->cfg.node.io_threads, sizeof(*n->workers));
    n->args = calloc(n->cfg.node.io_threads, sizeof(*n->args));
    if (n->queue == NULL || n->serving == NULL || n->workers == NULL || n->args == NULL)
        return -1;
    for (uint32_t i = 0; i < n->cfg.node.io_threads; i++)
        n->serving[i] = -1;
    for (uint32_t i = 0; i < n->cfg.node.io_threads; i++) {
        n->args[i] = (worker_arg){ n, i };
        if (pthread_create(&n->workers[i], NULL, io_worker, &n->args[i]) != 0)
            return -1;
    }
    if (pthread_create(&n->acceptor, NULL, acceptor, n) != 0)
        return -1;

    syslog(LOG_INFO, "node %u serving %s on %s:%u (heartbeat %u), %u io threads",
           n->cfg.node.node_id, n->cfg.node.data_dir, n->cfg.node.bind_addr,
           n->cfg.node.rpc_port, n->cfg.node.hb_port, n->cfg.node.io_threads);
    return 0;
}

static void stop(node *n, bool started)
{
    atomic_store(&n->stopping, true);
    if (started) {
        shutdown(n->listen_fd, SHUT_RDWR);
        pthread_join(n->acceptor, NULL);
        pthread_mutex_lock(&n->qlock);
        for (uint32_t i = 0; i < n->cfg.node.io_threads; i++) {
            if (n->serving[i] >= 0)
                shutdown(n->serving[i], SHUT_RDWR); /* unblock its recv */
        }
        pthread_cond_broadcast(&n->qcond);
        pthread_mutex_unlock(&n->qlock);
        for (uint32_t i = 0; i < n->cfg.node.io_threads; i++)
            pthread_join(n->workers[i], NULL);
        while (n->qlen > 0) {
            close(n->queue[n->qhead]);
            n->qhead = (n->qhead + 1) % n->qcap;
            n->qlen--;
        }
    }
    if (n->listen_fd >= 0)
        close(n->listen_fd);
    kfs_heartbeat_stop(n->heartbeat);
    kfs_health_free(n->health);
    kfs_pool_destroy(&n->pool);
    kfs_backend_close(n->store);
    kfs_identity_free(n->self);
    free(n->queue);
    free(n->serving);
    free(n->workers);
    free(n->args);
}

int main(int argc, char **argv)
{
    static node n;
    const char *config = "/etc/kryptonfs/kryptonfs.conf";
    char err[512];
    sigset_t sigs;
    int sig = 0, c, rc;

    while ((c = getopt(argc, argv, "c:h")) != -1) {
        if (c != 'c') {
            fprintf(stderr, "usage: kfs-noded [-c CONFIG]\n");
            return c == 'h' ? 0 : 2;
        }
        config = optarg;
    }

    openlog("kfs-noded", LOG_PID | LOG_PERROR, LOG_DAEMON);
    kfs_config_defaults(&n.cfg);
    if (kfs_config_load(&n.cfg, config, err, sizeof(err)) != KFS_OK ||
        kfs_config_validate(&n.cfg, KFS_ROLE_NODE, err, sizeof(err)) != KFS_OK) {
        fprintf(stderr, "kfs-noded: %s\n", err);
        return 1;
    }

    /* Every thread inherits this mask; only sigwait() below sees them. */
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);
    signal(SIGPIPE, SIG_IGN);

    n.listen_fd = -1;
    pthread_mutex_init(&n.qlock, NULL);
    pthread_cond_init(&n.qcond, NULL);
    atomic_init(&n.stopping, false);
    atomic_init(&n.active, 0);

    rc = start(&n);
    if (rc == 0) {
        sigwait(&sigs, &sig);
        syslog(LOG_INFO, "signal %d: shutting down", sig);
    }
    stop(&n, rc == 0);
    closelog();
    return rc == 0 ? 0 : 1;
}
