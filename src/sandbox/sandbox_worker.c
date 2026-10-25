/*
 * sandbox_worker.c - Worker pools, jail setup and the request/reply
 * channel between the FUSE daemon and its sandboxed workers.
 */
#define _GNU_SOURCE /* setresuid, setresgid, setgroups */

#include "krypton/krypton_sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "krypton/krypton_ipc.h"

#define MAX_WORKERS 128
#define READY_FD    3 /* the one descriptor a child keeps while jailing */

struct kfs_sandbox {
    kfs_sandbox_opts opts;
    kfs_shm_layout   layout; /* private copy: see krypton_ipc.h */
    void            *arena;
    int              req_q;
    int              rep_q;

    pthread_mutex_t  workers_lock;
    kfs_worker_info  workers[MAX_WORKERS];
    size_t           nworkers;
    bool             crypto_started;

    pthread_mutex_t  slot_lock;
    pthread_cond_t   slot_cond;
    uint32_t        *free_slots;
    uint32_t         nfree;

    _Atomic uint64_t *inflight; /* req_id waiting on each slot, 0 when idle */
    _Atomic uint64_t  next_req;
    atomic_bool       failed;
    atomic_bool       stopping;

    pthread_t         supervisor;
    bool              supervisor_started;
};

static int send_msg(int q, const kfs_ipc_msg *m)
{
    while (msgsnd(q, m, KFS_IPC_MSG_BODY_SIZE, 0) != 0) {
        if (errno != EINTR)
            return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * Worker side (runs in the forked child only)
 * ------------------------------------------------------------------- */

static void close_fds_from(unsigned first)
{
#ifdef SYS_close_range
    if (syscall(SYS_close_range, first, ~0u, 0u) == 0)
        return;
#endif
    {
        long max = sysconf(_SC_OPEN_MAX);

        for (long fd = first; fd < (max > 0 ? max : 1024); fd++)
            close((int)fd);
    }
}

static bool enter_jail(const kfs_sandbox_opts *o, pid_t parent)
{
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent)
        return false;
    if (prctl(PR_SET_DUMPABLE, 0) != 0) /* no core dumps, no ptrace attach */
        return false;
    if (o->drop_privileges) {
        if (chroot(o->chroot_dir) != 0 || chdir("/") != 0)
            return false;
        if (setgroups(0, NULL) != 0 ||
            setresgid(o->gid, o->gid, o->gid) != 0 ||
            setresuid(o->uid, o->uid, o->uid) != 0)
            return false;
        if (setuid(0) == 0 || seteuid(0) == 0) /* the drop must be irreversible */
            return false;
    }
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
}

static void reply(kfs_sandbox *sb, kfs_ipc_msg *m, kfs_status st)
{
    m->mtype = kfs_ipc_reply_mtype(m->slot);
    m->status = (uint32_t)st;
    if (send_msg(sb->rep_q, m) != 0)
        _exit(1);
}

static void scan_one(kfs_sandbox *sb, kfs_ipc_msg *m)
{
    kfs_scan_hit hit = { 0, 0 };
    kfs_status st;

    if (m->op != KFS_IPC_SCAN) {
        reply(sb, m, KFS_E_INVAL);
        return;
    }
    st = kfs_scanner_scan(sb->opts.scanner,
                          kfs_shm_slot_data(&sb->layout, sb->arena, m->slot), m->len,
                          (m->flags & KFS_IPC_F_FILE_START) ? 0 : 1,
                          sb->opts.block_elf, &hit);
    m->scan_sig = hit.sig_id;
    m->scan_offset = hit.offset;
    reply(sb, m, st);
}

static void crypto_one(kfs_sandbox *sb, const kfs_block_keys *keys, kfs_ipc_msg *m)
{
    uint8_t *data = kfs_shm_slot_data(&sb->layout, sb->arena, m->slot);
    kfs_envelope_hdr *shared = kfs_shm_slot_meta(sb->arena, m->slot);
    kfs_envelope_hdr env = *shared; /* snapshot: shared memory may change under us */
    kfs_status st;

    switch (m->op) {
    case KFS_IPC_SEAL:
        st = kfs_block_seal(keys, m->block_id, env.generation, data, m->len, &env);
        if (st == KFS_OK)
            *shared = env;
        break;
    case KFS_IPC_OPEN:
        st = kfs_block_open(keys, m->block_id, &env, data, m->len);
        break;
    default:
        st = KFS_E_INVAL;
        break;
    }
    reply(sb, m, st);
}

static _Noreturn void worker_main(kfs_sandbox *sb, kfs_worker_kind kind,
                                  const kfs_block_keys *keys, pid_t parent,
                                  int ready_fd)
{
    long mtype = kind == KFS_WORKER_SCAN ? KFS_IPC_MTYPE_SCAN : KFS_IPC_MTYPE_CRYPTO;
    kfs_block_keys local;

    memset(&local, 0, sizeof(local));
    if (keys != NULL) {
        local = *keys;
        mlock(&local, sizeof(local)); /* best effort: keep keys out of swap */
    }

    if (ready_fd != READY_FD && dup2(ready_fd, READY_FD) != READY_FD)
        _exit(1);
    close_fds_from(READY_FD + 1);
    if (!enter_jail(&sb->opts, parent))
        _exit(1);
    if (write(READY_FD, "1", 1) != 1)
        _exit(1);
    close(READY_FD);

    for (;;) {
        kfs_ipc_msg m;
        ssize_t n = msgrcv(sb->req_q, &m, KFS_IPC_MSG_BODY_SIZE, mtype, 0);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            kfs_wipe(&local, sizeof(local));
            _exit(errno == EIDRM ? 0 : 1); /* EIDRM: queue removed at shutdown */
        }
        if ((size_t)n != KFS_IPC_MSG_BODY_SIZE ||
            kfs_ipc_msg_check(&sb->layout, &m) != KFS_OK)
            continue;
        if (m.op == KFS_IPC_SHUTDOWN) {
            kfs_wipe(&local, sizeof(local));
            _exit(0);
        }
        if (kind == KFS_WORKER_SCAN)
            scan_one(sb, &m);
        else
            crypto_one(sb, &local, &m);
    }
}

/* ---------------------------------------------------------------------
 * Parent side
 * ------------------------------------------------------------------- */

static kfs_status spawn(kfs_sandbox *sb, kfs_worker_kind kind,
                        const kfs_block_keys *keys)
{
    pid_t parent = getpid(), pid;
    int ready[2];
    char c;
    ssize_t n;

    if (sb->nworkers == MAX_WORKERS)
        return KFS_E_INVAL;
    if (pipe2(ready, O_CLOEXEC) != 0)
        return KFS_E_IO;

    pid = fork();
    if (pid < 0) {
        close(ready[0]);
        close(ready[1]);
        return KFS_E_IO;
    }
    if (pid == 0) {
        close(ready[0]);
        worker_main(sb, kind, keys, parent, ready[1]);
    }

    /* The child writes one byte once jailed; EOF means it failed and exited. */
    close(ready[1]);
    do {
        n = read(ready[0], &c, 1);
    } while (n < 0 && errno == EINTR);
    close(ready[0]);

    pthread_mutex_lock(&sb->workers_lock);
    sb->workers[sb->nworkers++] = (kfs_worker_info){ pid, kind, n == 1 };
    pthread_mutex_unlock(&sb->workers_lock);

    if (n != 1) {
        waitpid(pid, NULL, 0);
        return KFS_E_IO;
    }
    return KFS_OK;
}

static void fail_closed(kfs_sandbox *sb)
{
    if (atomic_exchange(&sb->failed, true))
        return;

    /* Wake every thread waiting for a reply ... */
    for (uint32_t i = 0; i < sb->layout.slot_count; i++) {
        uint64_t id = atomic_load(&sb->inflight[i]);

        if (id != 0) {
            kfs_ipc_msg m;

            memset(&m, 0, sizeof(m));
            m.mtype = kfs_ipc_reply_mtype(i);
            m.slot = i;
            m.req_id = id;
            m.status = KFS_E_UNAVAILABLE;
            send_msg(sb->rep_q, &m);
        }
    }
    /* ... and every thread waiting for a slot. */
    pthread_mutex_lock(&sb->slot_lock);
    pthread_cond_broadcast(&sb->slot_cond);
    pthread_mutex_unlock(&sb->slot_lock);
}

static void *supervise(void *arg)
{
    kfs_sandbox *sb = arg;

    for (;;) {
        pid_t pid = waitpid(-1, NULL, 0);

        if (pid < 0) {
            if (errno == EINTR)
                continue;
            break; /* ECHILD: every worker has been reaped */
        }
        pthread_mutex_lock(&sb->workers_lock);
        for (size_t i = 0; i < sb->nworkers; i++) {
            if (sb->workers[i].pid == pid)
                sb->workers[i].alive = false;
        }
        pthread_mutex_unlock(&sb->workers_lock);
        if (!atomic_load(&sb->stopping))
            fail_closed(sb);
    }
    return NULL;
}

static int make_queue(const kfs_sandbox_opts *o)
{
    int q = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    struct msqid_ds ds;

    if (q < 0 || !o->drop_privileges)
        return q;
    /* Workers lose root, so grant their group access. The parent stays
     * the owner, which needs no CAP_IPC_OWNER (absent in containers). */
    if (msgctl(q, IPC_STAT, &ds) != 0)
        goto fail;
    ds.msg_perm.gid = o->gid;
    ds.msg_perm.mode = 0660;
    if (msgctl(q, IPC_SET, &ds) != 0)
        goto fail;
    return q;
fail:
    msgctl(q, IPC_RMID, NULL);
    return -1;
}

kfs_status kfs_sandbox_create(const kfs_sandbox_opts *opts, kfs_sandbox **out)
{
    kfs_sandbox *sb;
    long page = sysconf(_SC_PAGESIZE);
    kfs_status st;

    *out = NULL;
    if (opts->scan_workers == 0 || opts->crypto_workers == 0 ||
        (size_t)opts->scan_workers + opts->crypto_workers > MAX_WORKERS ||
        page <= 0 ||
        (opts->drop_privileges &&
         (opts->chroot_dir == NULL || opts->chroot_dir[0] != '/' ||
          opts->uid == 0 || opts->gid == 0)))
        return KFS_E_INVAL;

    sb = calloc(1, sizeof(*sb));
    if (sb == NULL)
        return KFS_E_NOMEM;
    sb->opts = *opts;
    sb->arena = MAP_FAILED;
    sb->req_q = sb->rep_q = -1;
    pthread_mutex_init(&sb->workers_lock, NULL);
    pthread_mutex_init(&sb->slot_lock, NULL);
    pthread_cond_init(&sb->slot_cond, NULL);
    atomic_init(&sb->next_req, 0);
    atomic_init(&sb->failed, false);
    atomic_init(&sb->stopping, false);

    st = kfs_shm_layout_init(&sb->layout, opts->slots, opts->block_size, (size_t)page);
    if (st != KFS_OK)
        goto fail;

    sb->arena = mmap(NULL, sb->layout.total_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    sb->free_slots = calloc(opts->slots, sizeof(*sb->free_slots));
    sb->inflight = calloc(opts->slots, sizeof(*sb->inflight));
    if (sb->arena == MAP_FAILED || sb->free_slots == NULL || sb->inflight == NULL) {
        st = KFS_E_NOMEM;
        goto fail;
    }
    /* The arena carries plaintext: keep it out of swap and core dumps. */
    mlock(sb->arena, sb->layout.total_size);
    madvise(sb->arena, sb->layout.total_size, MADV_DONTDUMP);

    for (uint32_t i = 0; i < opts->slots; i++) {
        atomic_init(&sb->inflight[i], 0);
        sb->free_slots[i] = opts->slots - 1 - i;
    }
    sb->nfree = opts->slots;

    sb->req_q = make_queue(opts);
    sb->rep_q = make_queue(opts);
    if (sb->req_q < 0 || sb->rep_q < 0) {
        st = KFS_E_IO;
        goto fail;
    }

    /* Scan workers fork before any key exists in this process. */
    for (uint32_t i = 0; i < opts->scan_workers; i++) {
        st = spawn(sb, KFS_WORKER_SCAN, NULL);
        if (st != KFS_OK)
            goto fail;
    }
    *out = sb;
    return KFS_OK;
fail:
    kfs_sandbox_destroy(sb);
    return st;
}

kfs_status kfs_sandbox_start_crypto(kfs_sandbox *sb, const kfs_block_keys *keys)
{
    uint8_t probe[16];
    kfs_envelope_hdr env;
    kfs_status st;

    if (sb->crypto_started)
        return KFS_E_INVAL;
    sb->crypto_started = true;

    /* Initialize OpenSSL (providers, DRBG) while files are reachable, and
     * check the keys work, before any worker enters its chroot. */
    memset(probe, 0, sizeof(probe));
    st = kfs_block_seal(keys, 0, 0, probe, sizeof(probe), &env);
    if (st == KFS_OK)
        st = kfs_block_open(keys, 0, &env, probe, sizeof(probe));
    if (st != KFS_OK)
        return st;

    for (uint32_t i = 0; i < sb->opts.crypto_workers; i++) {
        st = spawn(sb, KFS_WORKER_CRYPTO, keys);
        if (st != KFS_OK)
            return st;
    }
    if (pthread_create(&sb->supervisor, NULL, supervise, sb) != 0)
        return KFS_E_NOMEM;
    sb->supervisor_started = true;
    return KFS_OK;
}

void kfs_sandbox_destroy(kfs_sandbox *sb)
{
    if (sb == NULL)
        return;
    atomic_store(&sb->stopping, true);

    /* Removing the queues ends every msgrcv with EIDRM; SIGKILL covers a
     * worker that is busy or wedged. Workers keep no state worth saving. */
    if (sb->req_q >= 0)
        msgctl(sb->req_q, IPC_RMID, NULL);
    if (sb->rep_q >= 0)
        msgctl(sb->rep_q, IPC_RMID, NULL);

    pthread_mutex_lock(&sb->workers_lock);
    for (size_t i = 0; i < sb->nworkers; i++) {
        if (sb->workers[i].alive)
            kill(sb->workers[i].pid, SIGKILL);
    }
    pthread_mutex_unlock(&sb->workers_lock);

    if (sb->supervisor_started) {
        pthread_join(sb->supervisor, NULL);
    } else {
        for (size_t i = 0; i < sb->nworkers; i++) {
            if (sb->workers[i].alive)
                waitpid(sb->workers[i].pid, NULL, 0);
        }
    }

    if (sb->arena != MAP_FAILED) {
        kfs_wipe(sb->arena, sb->layout.total_size);
        munmap(sb->arena, sb->layout.total_size);
    }
    free(sb->free_slots);
    free(sb->inflight);
    pthread_cond_destroy(&sb->slot_cond);
    pthread_mutex_destroy(&sb->slot_lock);
    pthread_mutex_destroy(&sb->workers_lock);
    free(sb);
}

kfs_status kfs_sandbox_acquire(kfs_sandbox *sb, uint32_t *slot)
{
    pthread_mutex_lock(&sb->slot_lock);
    while (sb->nfree == 0 && !atomic_load(&sb->failed))
        pthread_cond_wait(&sb->slot_cond, &sb->slot_lock);
    if (atomic_load(&sb->failed)) {
        pthread_mutex_unlock(&sb->slot_lock);
        return KFS_E_UNAVAILABLE;
    }
    *slot = sb->free_slots[--sb->nfree];
    pthread_mutex_unlock(&sb->slot_lock);
    return KFS_OK;
}

void kfs_sandbox_release(kfs_sandbox *sb, uint32_t slot)
{
    pthread_mutex_lock(&sb->slot_lock);
    sb->free_slots[sb->nfree++] = slot;
    pthread_cond_signal(&sb->slot_cond);
    pthread_mutex_unlock(&sb->slot_lock);
}

uint8_t *kfs_sandbox_data(kfs_sandbox *sb, uint32_t slot)
{
    return kfs_shm_slot_data(&sb->layout, sb->arena, slot);
}

kfs_envelope_hdr *kfs_sandbox_meta(kfs_sandbox *sb, uint32_t slot)
{
    return kfs_shm_slot_meta(sb->arena, slot);
}

/* Sends *m to a pool and waits for the reply to this exact request,
 * which replaces *m. */
static kfs_status call(kfs_sandbox *sb, long pool, kfs_ipc_msg *m)
{
    uint32_t slot = m->slot;
    uint64_t id = atomic_fetch_add(&sb->next_req, 1) + 1;
    kfs_ipc_msg r;

    if (slot >= sb->layout.slot_count || m->len > sb->layout.block_size)
        return KFS_E_INVAL;

    m->mtype = pool;
    m->req_id = id;
    /* Publish the wait before checking for failure: either we see the
     * failure here, or fail_closed() sees our id and wakes us. */
    atomic_store(&sb->inflight[slot], id);
    if (atomic_load(&sb->failed)) {
        atomic_store(&sb->inflight[slot], 0);
        return KFS_E_UNAVAILABLE;
    }
    if (send_msg(sb->req_q, m) != 0) {
        atomic_store(&sb->inflight[slot], 0);
        return KFS_E_IO;
    }
    for (;;) {
        ssize_t n = msgrcv(sb->rep_q, &r, KFS_IPC_MSG_BODY_SIZE,
                           kfs_ipc_reply_mtype(slot), 0);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            atomic_store(&sb->inflight[slot], 0);
            return KFS_E_IO;
        }
        /* Anything else is a stale reply from an earlier, abandoned wait. */
        if ((size_t)n == KFS_IPC_MSG_BODY_SIZE && r.req_id == id && r.slot == slot)
            break;
    }
    atomic_store(&sb->inflight[slot], 0);
    *m = r;
    return r.status <= KFS_E_CONFIG ? (kfs_status)r.status : KFS_E_PROTO;
}

kfs_status kfs_sandbox_scan(kfs_sandbox *sb, uint32_t slot, uint32_t len,
                            bool file_start, kfs_scan_hit *hit)
{
    kfs_ipc_msg m;
    kfs_status st;

    if (sb->opts.scanner == NULL)
        return KFS_OK;
    memset(&m, 0, sizeof(m));
    m.op = KFS_IPC_SCAN;
    m.slot = slot;
    m.len = len;
    m.flags = file_start ? KFS_IPC_F_FILE_START : 0;
    st = call(sb, KFS_IPC_MTYPE_SCAN, &m);
    if (st == KFS_E_MALWARE) {
        hit->sig_id = m.scan_sig;
        hit->offset = m.scan_offset;
    }
    return st;
}

kfs_status kfs_sandbox_seal(kfs_sandbox *sb, uint32_t slot, uint64_t block_id,
                            uint64_t generation, uint32_t len)
{
    kfs_ipc_msg m;

    if (slot >= sb->layout.slot_count)
        return KFS_E_INVAL;
    kfs_sandbox_meta(sb, slot)->generation = generation;
    memset(&m, 0, sizeof(m));
    m.op = KFS_IPC_SEAL;
    m.slot = slot;
    m.block_id = block_id;
    m.len = len;
    return call(sb, KFS_IPC_MTYPE_CRYPTO, &m);
}

kfs_status kfs_sandbox_open(kfs_sandbox *sb, uint32_t slot, uint64_t block_id,
                            uint32_t len)
{
    kfs_ipc_msg m;

    memset(&m, 0, sizeof(m));
    m.op = KFS_IPC_OPEN;
    m.slot = slot;
    m.block_id = block_id;
    m.len = len;
    return call(sb, KFS_IPC_MTYPE_CRYPTO, &m);
}

size_t kfs_sandbox_workers(kfs_sandbox *sb, kfs_worker_info *out, size_t cap)
{
    size_t n;

    pthread_mutex_lock(&sb->workers_lock);
    n = sb->nworkers < cap ? sb->nworkers : cap;
    memcpy(out, sb->workers, n * sizeof(*out));
    pthread_mutex_unlock(&sb->workers_lock);
    return n;
}

bool kfs_sandbox_failed(const kfs_sandbox *sb)
{
    return atomic_load(&sb->failed);
}
