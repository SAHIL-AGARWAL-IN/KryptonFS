/*
 * heartbeat.c - Authenticated UDP liveness and latency probing.
 */
#define _GNU_SOURCE /* SOCK_CLOEXEC */

#include "krypton/krypton_cluster.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#define DISK_DEGRADED_PCT 95 /* nodes this full refuse writes */

struct kfs_heartbeat_svc {
    kfs_heartbeat_opts  opts;
    uint8_t             key[KFS_KEY_SIZE];
    char                bind_addr[KFS_HOST_MAX];
    char                data_dir[KFS_PATH_MAX];
    kfs_health         *health;
    int                 fd;
    int                 wake[2];   /* pipe: stop requests interrupt poll() */
    struct sockaddr_in  addrs[KFS_MAX_PEERS];
    bool                resolved[KFS_MAX_PEERS];
    uint64_t            seq;
    pthread_t           thread;
    atomic_bool         stop;
};

static bool resolve_v4(const char *host, uint16_t port, struct sockaddr_in *out)
{
    struct addrinfo hints, *res = NULL;
    char port_str[8];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL)
        return false;
    memcpy(out, res->ai_addr, sizeof(*out));
    freeaddrinfo(res);
    return true;
}

static void disk_usage(const kfs_heartbeat_svc *s, uint64_t *total, uint64_t *used)
{
    struct statvfs sv;

    *total = *used = 0;
    if (s->data_dir[0] != '\0' && statvfs(s->data_dir, &sv) == 0) {
        *total = (uint64_t)sv.f_blocks * sv.f_frsize;
        *used = *total - (uint64_t)sv.f_bavail * sv.f_frsize;
    }
}

static void send_hb(kfs_heartbeat_svc *s, uint8_t type, uint64_t timestamp,
                    const struct sockaddr_in *to)
{
    uint8_t wire[KFS_HB_SIZE];
    kfs_heartbeat hb;

    memset(&hb, 0, sizeof(hb));
    hb.type = type;
    hb.state = KFS_NODE_UP;
    hb.node_id = s->opts.self_id;
    hb.seq = ++s->seq;
    hb.timestamp_ns = timestamp;
    disk_usage(s, &hb.disk_total, &hb.disk_used);
    if (hb.disk_total != 0 && hb.disk_used * 100 / hb.disk_total >= DISK_DEGRADED_PCT)
        hb.state = KFS_NODE_DEGRADED;
    kfs_heartbeat_encode(&hb, wire);
    if (kfs_heartbeat_sign(s->key, wire) == KFS_OK)
        sendto(s->fd, wire, sizeof(wire), MSG_NOSIGNAL, (const struct sockaddr *)to, sizeof(*to));
}

static void broadcast(kfs_heartbeat_svc *s)
{
    const kfs_cluster_config *cl = s->opts.cluster;
    uint8_t type = s->opts.role == KFS_ROLE_NODE ? KFS_HB_BEAT : KFS_HB_PING;

    for (uint32_t i = 0; i < cl->peer_count; i++) {
        if (cl->peers[i].node_id == s->opts.self_id)
            continue;
        if (!s->resolved[i])
            s->resolved[i] = resolve_v4(cl->peers[i].host, cl->peers[i].hb_port, &s->addrs[i]);
        if (s->resolved[i])
            send_hb(s, type, (uint64_t)kfs_mono_ns(), &s->addrs[i]);
    }
}

static void receive(kfs_heartbeat_svc *s)
{
    uint8_t wire[KFS_HB_SIZE + 1];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    kfs_heartbeat hb;
    ssize_t n = recvfrom(s->fd, wire, sizeof(wire), MSG_DONTWAIT,
                         (struct sockaddr *)&from, &from_len);
    int64_t now = kfs_mono_ns();

    if (n != KFS_HB_SIZE || kfs_heartbeat_verify(s->key, wire) != KFS_OK ||
        kfs_heartbeat_decode(wire, &hb) != KFS_OK || hb.node_id == s->opts.self_id)
        return; /* forged, malformed or reflected back at us */

    switch (hb.type) {
    case KFS_HB_PING:
        /* Any cluster member may probe a node; echo its timestamp. */
        if (s->opts.role == KFS_ROLE_NODE)
            send_hb(s, KFS_HB_PONG, hb.timestamp_ns, &from);
        break;
    case KFS_HB_PONG:
        if (s->opts.role == KFS_ROLE_CLIENT &&
            kfs_health_observe(s->health, &hb, now) == KFS_OK &&
            (int64_t)hb.timestamp_ns <= now)
            kfs_health_set_rtt(s->health, hb.node_id, now - (int64_t)hb.timestamp_ns);
        break;
    case KFS_HB_BEAT:
        kfs_health_observe(s->health, &hb, now);
        break;
    default:
        break;
    }
}

static void *run(void *arg)
{
    kfs_heartbeat_svc *s = arg;
    int64_t interval = (int64_t)s->opts.cluster->heartbeat_interval_ms * 1000000;
    int64_t next = kfs_mono_ns();

    while (!atomic_load(&s->stop)) {
        struct pollfd pfd[2] = { { s->fd, POLLIN, 0 }, { s->wake[0], POLLIN, 0 } };
        int64_t now = kfs_mono_ns();

        if (now >= next) {
            broadcast(s);
            kfs_health_expire(s->health, now);
            next = now + interval;
        }
        if (poll(pfd, 2, (int)((next - now) / 1000000) + 1) > 0 && (pfd[0].revents & POLLIN))
            receive(s);
    }
    return NULL;
}

kfs_status kfs_heartbeat_start(const kfs_heartbeat_opts *opts, kfs_health *health,
                               kfs_heartbeat_svc **out)
{
    kfs_heartbeat_svc *s = calloc(1, sizeof(*s));
    struct sockaddr_in addr;
    struct timespec ts;

    if (s == NULL)
        return KFS_E_NOMEM;
    s->opts = *opts;
    s->health = health;
    s->fd = s->wake[0] = s->wake[1] = -1;
    memcpy(s->key, opts->cluster_key, KFS_KEY_SIZE);
    snprintf(s->bind_addr, sizeof(s->bind_addr), "%s",
             opts->bind_addr != NULL ? opts->bind_addr : "0.0.0.0");
    snprintf(s->data_dir, sizeof(s->data_dir), "%s", opts->data_dir != NULL ? opts->data_dir : "");
    s->opts.bind_addr = s->bind_addr;
    s->opts.data_dir = s->data_dir;
    atomic_init(&s->stop, false);

    /* Seed from the realtime clock so a restarted sender never repeats a
     * sequence number its peers have already accepted. */
    clock_gettime(CLOCK_REALTIME, &ts);
    s->seq = (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;

    s->fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s->fd < 0 || pipe(s->wake) != 0 || !resolve_v4(s->bind_addr, opts->port, &addr) ||
        bind(s->fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
        goto fail;
    if (pthread_create(&s->thread, NULL, run, s) != 0)
        goto fail;
    *out = s;
    return KFS_OK;
fail:
    if (s->fd >= 0)
        close(s->fd);
    if (s->wake[0] >= 0) {
        close(s->wake[0]);
        close(s->wake[1]);
    }
    kfs_wipe(s->key, sizeof(s->key));
    free(s);
    return KFS_E_IO;
}

void kfs_heartbeat_stop(kfs_heartbeat_svc *s)
{
    if (s == NULL)
        return;
    atomic_store(&s->stop, true);
    if (write(s->wake[1], "x", 1) < 0) {
        /* poll() still wakes within one interval */
    }
    pthread_join(s->thread, NULL);
    close(s->fd);
    close(s->wake[0]);
    close(s->wake[1]);
    kfs_wipe(s->key, sizeof(s->key));
    free(s);
}
