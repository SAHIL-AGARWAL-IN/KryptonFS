/*
 * telemetry_server.c - JSON-lines telemetry over a Unix socket.
 */
#define _GNU_SOURCE /* accept4, SOCK_NONBLOCK */

#include "krypton/krypton_telemetry.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS   16
#define EVENT_RING    256
#define EVENT_MSG_MAX 240
#define BACKFILL      50
#define TREE_MAX      2000
#define TREE_EVERY    4   /* send the tree every 4th snapshot */
#define MAX_WORKERS   128

typedef struct event {
    uint64_t        seq;
    int64_t         ts_ms;
    kfs_event_level level;
    char            kind[16];
    char            msg[EVENT_MSG_MAX];
} event;

struct kfs_telemetry {
    kfs_telemetry_sources src;
    char             volume_name[KFS_NAME_MAX];
    char             mountpoint[KFS_PATH_MAX];
    char             backend[16];
    char             path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    uint32_t         interval_ms;
    int              listen_fd;
    int              wake[2];
    int              clients[MAX_CLIENTS];
    size_t           nclients;
    pthread_t        thread;
    atomic_bool      stop;

    /* I/O in the current interval; index 0 = read, 1 = write. */
    atomic_uint_fast64_t ops[2];
    atomic_uint_fast64_t bytes[2];
    atomic_uint_fast64_t lat_ns[2];
    atomic_uint_fast64_t lat_max_ns[2];
    atomic_uint_fast64_t errors;

    pthread_mutex_t  ev_lock;
    event            ring[EVENT_RING];
    uint64_t         next_seq; /* seq of the next event; first is 1 */
    uint64_t         sent_seq; /* last seq included in a snapshot */

    kfs_node_state   last_state[KFS_MAX_PEERS];
    bool             sandbox_failed_seen;
    unsigned         tick;
};

/* ---------------------------------------------------------------------
 * JSON building
 * ------------------------------------------------------------------- */

typedef struct jbuf {
    char  *s;
    size_t len;
    size_t cap;
    bool   failed;
} jbuf;

static void jb_raw(jbuf *b, const char *p, size_t n)
{
    if (b->failed)
        return;
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap != 0 ? b->cap : 4096;
        char *s;

        while (cap < b->len + n + 1)
            cap *= 2;
        s = realloc(b->s, cap);
        if (s == NULL) {
            b->failed = true;
            return;
        }
        b->s = s;
        b->cap = cap;
    }
    memcpy(b->s + b->len, p, n);
    b->len += n;
    b->s[b->len] = '\0';
}

/* Appends a string literal; its length comes from sizeof, never by hand. */
#define jb_lit(b, lit) jb_raw((b), (lit), sizeof(lit) - 1)

static void jb_fmt(jbuf *b, const char *fmt, ...) KFS_PRINTF_FMT(2, 3);

static void jb_fmt(jbuf *b, const char *fmt, ...)
{
    char tmp[512];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0)
        jb_raw(b, tmp, (size_t)n < sizeof(tmp) ? (size_t)n : sizeof(tmp) - 1);
}

/* Length of a valid UTF-8 sequence at p, or 0 if invalid. */
static size_t utf8_len(const unsigned char *p)
{
    if (p[0] < 0x80)
        return 1;
    if ((p[0] & 0xE0) == 0xC0 && p[0] >= 0xC2 && (p[1] & 0xC0) == 0x80)
        return 2;
    if ((p[0] & 0xF0) == 0xE0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 &&
        !(p[0] == 0xE0 && p[1] < 0xA0) && !(p[0] == 0xED && p[1] >= 0xA0))
        return 3;
    if ((p[0] & 0xF8) == 0xF0 && p[0] <= 0xF4 && (p[1] & 0xC0) == 0x80 &&
        (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80 &&
        !(p[0] == 0xF0 && p[1] < 0x90) && !(p[0] == 0xF4 && p[1] >= 0x90))
        return 4;
    return 0;
}

/* A JSON string. File names are arbitrary bytes; invalid UTF-8 becomes
 * U+FFFD so the output always parses. */
static void jb_str(jbuf *b, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    jb_lit(b, "\"");
    while (*p != '\0') {
        size_t n = utf8_len(p);

        if (*p == '"' || *p == '\\') {
            char esc[2] = { '\\', (char)*p };

            jb_raw(b, esc, 2);
            p++;
        } else if (*p < 0x20) {
            jb_fmt(b, "\\u%04x", *p);
            p++;
        } else if (n == 0) {
            jb_lit(b, "\\ufffd");
            p++;
        } else {
            jb_raw(b, (const char *)p, n);
            p += n;
        }
    }
    jb_lit(b, "\"");
}

/* ---------------------------------------------------------------------
 * Recording
 * ------------------------------------------------------------------- */

static int64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void kfs_telemetry_io(kfs_telemetry *t, bool write, size_t bytes, int64_t latency_ns, bool ok)
{
    int i = write ? 1 : 0;
    uint64_t lat = latency_ns > 0 ? (uint64_t)latency_ns : 0;
    uint_fast64_t max;

    if (t == NULL)
        return;
    if (!ok) {
        atomic_fetch_add(&t->errors, 1);
        return;
    }
    atomic_fetch_add(&t->ops[i], 1);
    atomic_fetch_add(&t->bytes[i], bytes);
    atomic_fetch_add(&t->lat_ns[i], lat);
    max = atomic_load(&t->lat_max_ns[i]);
    while (lat > max && !atomic_compare_exchange_weak(&t->lat_max_ns[i], &max, lat))
        ;
}

static void event_v(kfs_telemetry *t, kfs_event_level level, const char *kind,
                    const char *fmt, va_list ap)
{
    event *e;

    pthread_mutex_lock(&t->ev_lock);
    e = &t->ring[t->next_seq % EVENT_RING];
    e->seq = t->next_seq++;
    e->ts_ms = now_ms();
    e->level = level;
    snprintf(e->kind, sizeof(e->kind), "%s", kind);
    vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
    pthread_mutex_unlock(&t->ev_lock);
}

void kfs_telemetry_event(kfs_telemetry *t, kfs_event_level level, const char *kind,
                         const char *fmt, ...)
{
    va_list ap;

    if (t == NULL)
        return;
    va_start(ap, fmt);
    event_v(t, level, kind, fmt, ap);
    va_end(ap);
}

static void internal_event(kfs_telemetry *t, kfs_event_level level, const char *kind,
                           const char *fmt, ...) KFS_PRINTF_FMT(4, 5);

static void internal_event(kfs_telemetry *t, kfs_event_level level, const char *kind,
                           const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    event_v(t, level, kind, fmt, ap);
    va_end(ap);
}

/* ---------------------------------------------------------------------
 * Messages
 * ------------------------------------------------------------------- */

static const char *LEVELS[] = { "info", "warn", "alert" };
static const char *STATES[] = { "unknown", "up", "degraded", "draining", "down" };

static void events_json(kfs_telemetry *t, jbuf *b, uint64_t after)
{
    bool first = true;

    pthread_mutex_lock(&t->ev_lock);
    if (t->next_seq > EVENT_RING && after < t->next_seq - EVENT_RING)
        after = t->next_seq - EVENT_RING; /* older ones were overwritten */
    jb_lit(b, "[");
    for (uint64_t s = after + 1; s < t->next_seq; s++) {
        const event *e = &t->ring[s % EVENT_RING];

        jb_fmt(b, "%s{\"seq\":%llu,\"ts_ms\":%lld,\"level\":\"%s\",\"kind\":", first ? "" : ",",
               (unsigned long long)e->seq, (long long)e->ts_ms, LEVELS[e->level]);
        jb_str(b, e->kind);
        jb_lit(b, ",\"msg\":");
        jb_str(b, e->msg);
        jb_lit(b, "}");
        first = false;
    }
    jb_lit(b, "]");
    pthread_mutex_unlock(&t->ev_lock);
}

/* Compares health and sandbox state with the last snapshot and records
 * transitions as events, before the snapshot is built. */
static void note_transitions(kfs_telemetry *t)
{
    if (t->src.health != NULL) {
        kfs_peer_health peers[KFS_MAX_PEERS];
        size_t n = kfs_health_snapshot(t->src.health, peers, KFS_MAX_PEERS);

        for (size_t i = 0; i < n; i++) {
            kfs_node_state s = peers[i].state;

            if (s != t->last_state[i] && s != KFS_NODE_UNKNOWN)
                internal_event(t, s == KFS_NODE_DOWN ? KFS_EV_WARN : KFS_EV_INFO, "cluster",
                               "node %u is %s", peers[i].node_id, STATES[s]);
            t->last_state[i] = s;
        }
    }
    if (t->src.sandbox != NULL && !t->sandbox_failed_seen && kfs_sandbox_failed(t->src.sandbox)) {
        t->sandbox_failed_seen = true;
        internal_event(t, KFS_EV_ALERT, "sandbox",
                       "a sandbox worker died: failing closed, all I/O now returns EIO");
    }
}

static void snapshot_json(kfs_telemetry *t, jbuf *b)
{
    kfs_fs_usage u;
    uint64_t ops[2], bytes[2], lat[2], lat_max[2], errors;

    for (int i = 0; i < 2; i++) {
        ops[i] = atomic_exchange(&t->ops[i], 0);
        bytes[i] = atomic_exchange(&t->bytes[i], 0);
        lat[i] = atomic_exchange(&t->lat_ns[i], 0);
        lat_max[i] = atomic_exchange(&t->lat_max_ns[i], 0);
    }
    errors = atomic_exchange(&t->errors, 0);
    kfs_fs_usage_get(t->src.fs, &u);

    jb_fmt(b, "{\"type\":\"snapshot\",\"ts_ms\":%lld,\"interval_ms\":%u,\"volume\":{\"name\":",
           (long long)now_ms(), t->interval_ms);
    jb_str(b, t->volume_name);
    jb_lit(b, ",\"mountpoint\":");
    jb_str(b, t->mountpoint);
    jb_lit(b, ",\"backend\":");
    jb_str(b, t->backend);
    jb_fmt(b, ",\"block_size\":%u}", t->src.block_size);

    jb_fmt(b, ",\"io\":{\"read_ops\":%llu,\"write_ops\":%llu,\"read_bytes\":%llu,"
              "\"write_bytes\":%llu,",
           (unsigned long long)ops[0], (unsigned long long)ops[1],
           (unsigned long long)bytes[0], (unsigned long long)bytes[1]);
    jb_fmt(b, "\"read_lat_us\":%llu,\"write_lat_us\":%llu,\"read_lat_max_us\":%llu,"
              "\"write_lat_max_us\":%llu,\"errors\":%llu}",
           (unsigned long long)(ops[0] ? lat[0] / ops[0] / 1000 : 0),
           (unsigned long long)(ops[1] ? lat[1] / ops[1] / 1000 : 0),
           (unsigned long long)(lat_max[0] / 1000), (unsigned long long)(lat_max[1] / 1000),
           (unsigned long long)errors);

    jb_fmt(b, ",\"cache\":{\"frames\":%u,\"used\":%u,\"dirty\":%u,\"hits\":%llu,"
              "\"misses\":%llu,\"evictions\":%llu}",
           u.cache.frames, u.cache.used, u.cache.dirty, (unsigned long long)u.cache.hits,
           (unsigned long long)u.cache.misses, (unsigned long long)u.cache.evictions);
    jb_fmt(b, ",\"usage\":{\"files\":%llu,\"dirs\":%llu,\"data_blocks\":%llu}",
           (unsigned long long)u.files, (unsigned long long)u.dirs,
           (unsigned long long)u.data_blocks);

    jb_lit(b, ",\"nodes\":[");
    if (t->src.health != NULL) {
        kfs_peer_health peers[KFS_MAX_PEERS];
        size_t n = kfs_health_snapshot(t->src.health, peers, KFS_MAX_PEERS);
        int64_t mono = kfs_mono_ns();

        for (size_t i = 0; i < n; i++) {
            const kfs_peer_health *p = &peers[i];

            jb_fmt(b, "%s{\"id\":%u,\"state\":\"%s\",\"rtt_us\":%lld,\"disk_total\":%llu,"
                      "\"disk_used\":%llu,\"last_seen_ms\":%lld}",
                   i == 0 ? "" : ",", p->node_id, STATES[p->state],
                   (long long)(p->rtt_ns / 1000), (unsigned long long)p->disk_total,
                   (unsigned long long)p->disk_used,
                   (long long)(p->last_seen_ns != 0 ? (mono - p->last_seen_ns) / 1000000 : -1));
        }
    }
    jb_lit(b, "]");

    jb_lit(b, ",\"sandbox\":{");
    if (t->src.sandbox != NULL) {
        kfs_worker_info w[MAX_WORKERS];
        size_t n = kfs_sandbox_workers(t->src.sandbox, w, MAX_WORKERS);

        jb_fmt(b, "\"failed\":%s,\"workers\":[", kfs_sandbox_failed(t->src.sandbox) ? "true" : "false");
        for (size_t i = 0; i < n; i++)
            jb_fmt(b, "%s{\"pid\":%d,\"kind\":\"%s\",\"alive\":%s}", i == 0 ? "" : ",",
                   (int)w[i].pid, w[i].kind == KFS_WORKER_SCAN ? "scan" : "crypto",
                   w[i].alive ? "true" : "false");
        jb_lit(b, "]");
    } else {
        jb_lit(b, "\"failed\":false,\"workers\":[]");
    }
    jb_lit(b, "}");

    jb_fmt(b, ",\"keys\":{\"cipher\":\"AES-256-CTR + HMAC-SHA256\",\"kdf\":\"PBKDF2-HMAC-SHA256\","
              "\"kdf_iterations\":%u,\"volume_key\":",
           t->src.kdf_iterations);
    if (t->src.sandbox != NULL && kfs_sandbox_failed(t->src.sandbox))
        jb_str(b, "unavailable: sandbox failed closed");
    else if (t->src.sandbox != NULL)
        jb_fmt(b, "\"held by %u jailed crypto workers; wiped from the daemon\"",
               t->src.crypto_workers);
    else
        jb_str(b, "held in-process");
    jb_fmt(b, ",\"identity_id\":%u}", t->src.identity_id);

    jb_lit(b, ",\"events\":");
    events_json(t, b, t->sent_seq);
    pthread_mutex_lock(&t->ev_lock);
    t->sent_seq = t->next_seq - 1;
    pthread_mutex_unlock(&t->ev_lock);
    jb_lit(b, "}\n");
}

typedef struct tree_ctx {
    jbuf *b;
    bool  first;
} tree_ctx;

static void tree_entry(void *ctx, const char *path, unsigned depth, const kfs_stat *st)
{
    tree_ctx *c = ctx;

    if (c->first)
        jb_lit(c->b, "{\"path\":");
    else
        jb_lit(c->b, ",{\"path\":");
    jb_str(c->b, path);
    jb_fmt(c->b, ",\"dir\":%s,\"size\":%llu,\"depth\":%u}",
           S_ISDIR(st->mode) ? "true" : "false", (unsigned long long)st->size, depth);
    c->first = false;
}

static void tree_json(kfs_telemetry *t, jbuf *b)
{
    tree_ctx c = { b, true };
    bool complete;

    jb_lit(b, "{\"type\":\"tree\",\"entries\":[");
    complete = kfs_fs_walk(t->src.fs, TREE_MAX, tree_entry, &c);
    jb_fmt(b, "],\"truncated\":%s}\n", complete ? "false" : "true");
}

/* ---------------------------------------------------------------------
 * Server
 * ------------------------------------------------------------------- */

static void drop_client(kfs_telemetry *t, size_t i)
{
    close(t->clients[i]);
    t->clients[i] = t->clients[--t->nclients];
}

/* A partial write would corrupt the line stream, so a client that cannot
 * take a whole message right now is disconnected. */
static bool send_line(int fd, const jbuf *b)
{
    size_t off = 0;

    while (off < b->len) {
        ssize_t n = send(fd, b->s + off, b->len - off, MSG_NOSIGNAL | MSG_DONTWAIT);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        off += (size_t)n;
    }
    return true;
}

static void broadcast(kfs_telemetry *t, const jbuf *b)
{
    if (b->failed)
        return;
    for (size_t i = 0; i < t->nclients;) {
        if (send_line(t->clients[i], b))
            i++;
        else
            drop_client(t, i);
    }
}

static void welcome(kfs_telemetry *t, int fd)
{
    jbuf b = { NULL, 0, 0, false };
    uint64_t after;

    pthread_mutex_lock(&t->ev_lock);
    after = t->next_seq > BACKFILL + 1 ? t->next_seq - 1 - BACKFILL : 0;
    pthread_mutex_unlock(&t->ev_lock);
    jb_lit(&b, "{\"type\":\"events\",\"events\":");
    events_json(t, &b, after);
    jb_lit(&b, "}\n");
    tree_json(t, &b);
    if (b.failed || !send_line(fd, &b)) {
        close(fd);
    } else if (t->nclients == MAX_CLIENTS) {
        close(fd);
    } else {
        t->clients[t->nclients++] = fd;
    }
    free(b.s);
}

static void *run(void *arg)
{
    kfs_telemetry *t = arg;
    int64_t interval = (int64_t)t->interval_ms * 1000000, next = kfs_mono_ns() + interval;

    while (!atomic_load(&t->stop)) {
        struct pollfd pfd[2] = { { t->listen_fd, POLLIN, 0 }, { t->wake[0], POLLIN, 0 } };
        int64_t now = kfs_mono_ns();
        int wait_ms = now < next ? (int)((next - now) / 1000000) + 1 : 0;

        if (poll(pfd, 2, wait_ms) > 0 && (pfd[0].revents & POLLIN)) {
            int fd = accept4(t->listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);

            if (fd >= 0)
                welcome(t, fd);
        }
        if (kfs_mono_ns() >= next) {
            jbuf b = { NULL, 0, 0, false };

            note_transitions(t);
            snapshot_json(t, &b);
            if (++t->tick % TREE_EVERY == 0)
                tree_json(t, &b);
            broadcast(t, &b);
            free(b.s);
            next += interval;
            if (next < kfs_mono_ns())
                next = kfs_mono_ns() + interval; /* fell behind: don't burst */
        }
    }
    return NULL;
}

static kfs_status listen_unix(kfs_telemetry *t)
{
    struct sockaddr_un addr;
    struct stat st;
    char dir[sizeof(t->path)];
    mode_t old;
    int rc;

    snprintf(dir, sizeof(dir), "%s", t->path);
    if (mkdir(dirname(dir), 0700) != 0 && errno != EEXIST)
        return KFS_E_IO;
    /* Replace a stale socket, but never delete anything else. */
    if (lstat(t->path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode))
            return KFS_E_IO;
        unlink(t->path);
    }

    t->listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (t->listen_fd < 0)
        return KFS_E_IO;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, t->path, strlen(t->path) + 1);
    old = umask(077); /* the socket is born owner-only */
    rc = bind(t->listen_fd, (const struct sockaddr *)&addr, sizeof(addr));
    umask(old);
    if (rc != 0 || chmod(t->path, 0600) != 0 || listen(t->listen_fd, 8) != 0)
        return KFS_E_IO;
    return KFS_OK;
}

kfs_status kfs_telemetry_start(const char *socket_path, uint32_t interval_ms,
                               const kfs_telemetry_sources *src, kfs_telemetry **out)
{
    kfs_telemetry *t;

    if (strlen(socket_path) >= sizeof(t->path) || interval_ms == 0 || src->fs == NULL)
        return KFS_E_INVAL;
    t = calloc(1, sizeof(*t));
    if (t == NULL)
        return KFS_E_NOMEM;
    t->src = *src;
    snprintf(t->volume_name, sizeof(t->volume_name), "%s", src->volume_name ? src->volume_name : "");
    snprintf(t->mountpoint, sizeof(t->mountpoint), "%s", src->mountpoint ? src->mountpoint : "");
    snprintf(t->backend, sizeof(t->backend), "%s", src->backend ? src->backend : "");
    snprintf(t->path, sizeof(t->path), "%s", socket_path);
    t->interval_ms = interval_ms;
    t->listen_fd = t->wake[0] = t->wake[1] = -1;
    t->next_seq = 1;
    pthread_mutex_init(&t->ev_lock, NULL);
    atomic_init(&t->stop, false);
    for (int i = 0; i < 2; i++) {
        atomic_init(&t->ops[i], 0);
        atomic_init(&t->bytes[i], 0);
        atomic_init(&t->lat_ns[i], 0);
        atomic_init(&t->lat_max_ns[i], 0);
    }
    atomic_init(&t->errors, 0);

    if (listen_unix(t) != KFS_OK || pipe2(t->wake, O_CLOEXEC) != 0 ||
        pthread_create(&t->thread, NULL, run, t) != 0) {
        if (t->listen_fd >= 0) {
            close(t->listen_fd);
            unlink(t->path);
        }
        if (t->wake[0] >= 0) {
            close(t->wake[0]);
            close(t->wake[1]);
        }
        pthread_mutex_destroy(&t->ev_lock);
        free(t);
        return KFS_E_IO;
    }
    *out = t;
    return KFS_OK;
}

void kfs_telemetry_stop(kfs_telemetry *t)
{
    if (t == NULL)
        return;
    atomic_store(&t->stop, true);
    if (write(t->wake[1], "x", 1) < 0) {
        /* poll() still wakes at the next tick */
    }
    pthread_join(t->thread, NULL);
    while (t->nclients > 0)
        drop_client(t, 0);
    close(t->listen_fd);
    unlink(t->path);
    close(t->wake[0]);
    close(t->wake[1]);
    pthread_mutex_destroy(&t->ev_lock);
    free(t);
}
