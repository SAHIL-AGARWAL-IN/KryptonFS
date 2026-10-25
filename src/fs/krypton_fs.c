/*
 * krypton_fs.c - File and directory operations over meta + cache + blockio.
 */
#define _XOPEN_SOURCE 700 /* S_IFDIR / S_IFREG / S_IFMT */

#include "krypton/krypton_fs.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>

#include "krypton/krypton_meta.h"
#include "krypton/krypton_volume.h"

struct kfs_fs {
    pthread_mutex_t lock;
    kfs_fs_opts     opts;
    kfs_blockio    *io;
    kfs_meta        meta;
    kfs_cache      *cache;
    uint8_t        *scratch; /* candidate block for scanning, mlocked */

    pthread_t       wb_thread;
    bool            wb_running;
    bool            stopping;
    pthread_cond_t  wb_cond;
};

static int64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int to_errno(kfs_status st)
{
    switch (st) {
    case KFS_OK:        return 0;
    case KFS_E_INVAL:   return -EINVAL;
    case KFS_E_NOMEM:   return -ENOMEM;
    case KFS_E_MALWARE: return -EACCES;
    default:            return -EIO; /* storage, tag or sandbox failures */
    }
}

static uint64_t max_file_size(const kfs_fs *fs)
{
    return (uint64_t)KFS_MAX_FILE_BLOCKS * fs->opts.block_size;
}

/* Cache eviction / flush callback: seal a dirty block to storage under a
 * fresh generation and record it in the inode. */
static kfs_status writeback(void *ctx, uint64_t ino, uint32_t index, const uint8_t *data)
{
    kfs_fs *fs = ctx;
    kfs_inode *n = kfs_meta_get(&fs->meta, ino);
    uint64_t gen;
    kfs_status st;

    if (n == NULL)
        return KFS_OK; /* deleted since it was dirtied */
    gen = kfs_meta_next_gen(&fs->meta, n, index);
    st = kfs_blockio_write(fs->io, kfs_bid(ino, index, gen), gen, data, fs->opts.block_size);
    if (st == KFS_OK)
        st = kfs_meta_set_gen(&fs->meta, n, index, gen);
    return st;
}

/* The cached frame for a block, loading it on a miss. A block whose
 * storage generation differs from the metadata's is a rollback. */
static kfs_status get_block(kfs_fs *fs, kfs_inode *n, uint32_t index, uint8_t **out)
{
    uint8_t *frame = kfs_cache_find(fs->cache, n->ino, index);
    uint64_t want, got = 0;
    kfs_status st;

    if (frame != NULL) {
        *out = frame;
        return KFS_OK;
    }
    st = kfs_cache_alloc(fs->cache, n->ino, index, writeback, fs, &frame);
    if (st != KFS_OK)
        return st;

    want = kfs_meta_block_gen(n, index);
    if (want == 0) {
        memset(frame, 0, fs->opts.block_size); /* hole */
    } else {
        st = kfs_blockio_read(fs->io, kfs_bid(n->ino, index, want), frame,
                              fs->opts.block_size, want, &got);
        if (st != KFS_OK) {
            kfs_cache_drop(fs->cache, n->ino, index);
            return st;
        }
    }
    *out = frame;
    return KFS_OK;
}

static kfs_status sync_locked(kfs_fs *fs)
{
    kfs_status st = kfs_cache_flush(fs->cache, writeback, fs);

    if (st == KFS_OK && fs->meta.dirty)
        st = kfs_meta_commit(&fs->meta, fs->io);
    return st;
}

static void *writeback_loop(void *arg)
{
    kfs_fs *fs = arg;

    pthread_mutex_lock(&fs->lock);
    while (!fs->stopping) {
        struct timespec deadline;

        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += fs->opts.writeback_ms / 1000;
        deadline.tv_nsec += (long)(fs->opts.writeback_ms % 1000) * 1000000;
        if (deadline.tv_nsec >= 1000000000) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000;
        }
        pthread_cond_timedwait(&fs->wb_cond, &fs->lock, &deadline);
        if (!fs->stopping)
            sync_locked(fs); /* errors resurface on the next explicit sync */
    }
    pthread_mutex_unlock(&fs->lock);
    return NULL;
}

kfs_status kfs_fs_open(kfs_blockio *io, const kfs_fs_opts *opts, kfs_fs **out)
{
    kfs_fs *fs = calloc(1, sizeof(*fs));
    kfs_status st;

    if (fs == NULL)
        return KFS_E_NOMEM;
    fs->opts = *opts;
    fs->io = io;
    pthread_mutex_init(&fs->lock, NULL);
    pthread_cond_init(&fs->wb_cond, NULL);

    fs->scratch = calloc(1, opts->block_size);
    if (fs->scratch == NULL) {
        st = KFS_E_NOMEM;
        goto fail;
    }
    mlock(fs->scratch, opts->block_size);

    st = kfs_cache_new(opts->cache_bytes, opts->block_size, opts->lock_memory, &fs->cache);
    if (st != KFS_OK)
        goto fail;

    st = kfs_meta_load(&fs->meta, io, opts->block_size);
    if (st == KFS_E_NOT_FOUND && opts->format_if_empty) {
        st = kfs_meta_init(&fs->meta, opts->block_size, 0755,
                           opts->root_uid, opts->root_gid, now_ns());
        if (st == KFS_OK)
            st = kfs_meta_commit(&fs->meta, io);
    }
    if (st != KFS_OK)
        goto fail;

    if (opts->writeback_ms > 0) {
        if (pthread_create(&fs->wb_thread, NULL, writeback_loop, fs) != 0) {
            st = KFS_E_NOMEM;
            goto fail;
        }
        fs->wb_running = true;
    }
    *out = fs;
    return KFS_OK;
fail:
    kfs_meta_destroy(&fs->meta);
    kfs_cache_free(fs->cache);
    free(fs->scratch);
    pthread_cond_destroy(&fs->wb_cond);
    pthread_mutex_destroy(&fs->lock);
    free(fs);
    return st;
}

int kfs_fs_close(kfs_fs *fs)
{
    kfs_status st;

    if (fs->wb_running) {
        pthread_mutex_lock(&fs->lock);
        fs->stopping = true;
        pthread_cond_signal(&fs->wb_cond);
        pthread_mutex_unlock(&fs->lock);
        pthread_join(fs->wb_thread, NULL);
    }
    pthread_mutex_lock(&fs->lock);
    st = sync_locked(fs);
    pthread_mutex_unlock(&fs->lock);

    kfs_meta_destroy(&fs->meta);
    kfs_cache_free(fs->cache);
    kfs_wipe(fs->scratch, fs->opts.block_size);
    munlock(fs->scratch, fs->opts.block_size);
    free(fs->scratch);
    pthread_cond_destroy(&fs->wb_cond);
    pthread_mutex_destroy(&fs->lock);
    free(fs);
    return to_errno(st);
}

static void fill_stat(const kfs_fs *fs, const kfs_inode *n, kfs_stat *st)
{
    st->ino = n->ino;
    st->mode = n->mode;
    st->uid = n->uid;
    st->gid = n->gid;
    st->size = n->size;
    st->blocks512 = (n->size + 511) / 512;
    st->mtime_ns = n->mtime_ns;
    st->ctime_ns = n->ctime_ns;
    st->nlink = 1;
    if (S_ISDIR(n->mode)) {
        st->nlink = 2;
        for (uint32_t i = 0; i < n->nchildren; i++) {
            const kfs_inode *c = kfs_meta_get(&fs->meta, n->children[i]);

            if (c != NULL && S_ISDIR(c->mode))
                st->nlink++;
        }
    }
}

int kfs_fs_getattr(kfs_fs *fs, const char *path, kfs_stat *st)
{
    kfs_inode *n;
    int rc;

    pthread_mutex_lock(&fs->lock);
    rc = kfs_meta_resolve(&fs->meta, path, &n);
    if (rc == 0)
        fill_stat(fs, n, st);
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

int kfs_fs_readdir(kfs_fs *fs, const char *path, kfs_dirent_fn fn, void *ctx)
{
    kfs_inode *dir;
    int rc;

    pthread_mutex_lock(&fs->lock);
    rc = kfs_meta_resolve(&fs->meta, path, &dir);
    if (rc == 0 && !S_ISDIR(dir->mode))
        rc = -ENOTDIR;
    for (uint32_t i = 0; rc == 0 && i < dir->nchildren; i++) {
        const kfs_inode *c = kfs_meta_get(&fs->meta, dir->children[i]);
        kfs_stat st;

        if (c == NULL)
            continue;
        fill_stat(fs, c, &st);
        if (fn(ctx, c->name, &st) != 0)
            break;
    }
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

static int make_node(kfs_fs *fs, const char *path, uint32_t mode, uint32_t uid, uint32_t gid)
{
    char leaf[KFS_NAME_LEN_MAX + 1];
    kfs_inode *dir, *n;
    int rc;

    pthread_mutex_lock(&fs->lock);
    rc = kfs_meta_resolve_parent(&fs->meta, path, &dir, leaf);
    if (rc == 0 && kfs_meta_child(&fs->meta, dir, leaf) != NULL)
        rc = -EEXIST;
    if (rc == 0 && !kfs_meta_name_ok(leaf))
        rc = -EINVAL;
    if (rc == 0)
        rc = to_errno(kfs_meta_create(&fs->meta, dir, leaf, mode, uid, gid, now_ns(), &n));
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

int kfs_fs_mkdir(kfs_fs *fs, const char *path, uint32_t mode, uint32_t uid, uint32_t gid)
{
    return make_node(fs, path, S_IFDIR | (mode & 07777), uid, gid);
}

int kfs_fs_create(kfs_fs *fs, const char *path, uint32_t mode, uint32_t uid, uint32_t gid)
{
    return make_node(fs, path, S_IFREG | (mode & 07777), uid, gid);
}

static void remove_node(kfs_fs *fs, kfs_inode *n)
{
    kfs_inode *parent = kfs_meta_get(&fs->meta, n->parent);

    if (parent != NULL)
        parent->mtime_ns = parent->ctime_ns = now_ns();
    kfs_cache_invalidate(fs->cache, n->ino, 0);
    kfs_meta_remove(&fs->meta, n);
}

int kfs_fs_unlink(kfs_fs *fs, const char *path)
{
    kfs_inode *n;
    int rc;

    pthread_mutex_lock(&fs->lock);
    rc = kfs_meta_resolve(&fs->meta, path, &n);
    if (rc == 0 && S_ISDIR(n->mode))
        rc = -EISDIR;
    if (rc == 0)
        remove_node(fs, n);
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

int kfs_fs_rmdir(kfs_fs *fs, const char *path)
{
    kfs_inode *n;
    int rc;

    pthread_mutex_lock(&fs->lock);
    rc = kfs_meta_resolve(&fs->meta, path, &n);
    if (rc == 0 && !S_ISDIR(n->mode))
        rc = -ENOTDIR;
    else if (rc == 0 && n->ino == KFS_ROOT_INO)
        rc = -EBUSY;
    else if (rc == 0 && n->nchildren > 0)
        rc = -ENOTEMPTY;
    if (rc == 0)
        remove_node(fs, n);
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

/* True if dir is node or lies beneath it. */
static bool is_within(const kfs_fs *fs, const kfs_inode *dir, const kfs_inode *node)
{
    while (dir != NULL) {
        if (dir == node)
            return true;
        if (dir->ino == KFS_ROOT_INO)
            return false;
        dir = kfs_meta_get(&fs->meta, dir->parent);
    }
    return false;
}

int kfs_fs_rename(kfs_fs *fs, const char *from, const char *to, unsigned flags)
{
    char leaf[KFS_NAME_LEN_MAX + 1];
    kfs_inode *src, *dst_dir, *existing, *old_parent;
    int64_t now = now_ns();
    int rc;

    if ((flags & ~KFS_RENAME_NOREPLACE) != 0)
        return -EINVAL; /* RENAME_EXCHANGE / WHITEOUT are not supported */

    pthread_mutex_lock(&fs->lock);
    rc = kfs_meta_resolve(&fs->meta, from, &src);
    if (rc == 0)
        rc = kfs_meta_resolve_parent(&fs->meta, to, &dst_dir, leaf);
    if (rc == 0 && src->ino == KFS_ROOT_INO)
        rc = -EBUSY;
    if (rc == 0 && !kfs_meta_name_ok(leaf))
        rc = -EINVAL;
    if (rc == 0 && S_ISDIR(src->mode) && is_within(fs, dst_dir, src))
        rc = -EINVAL; /* a directory cannot move beneath itself */
    if (rc != 0)
        goto out;

    existing = kfs_meta_child(&fs->meta, dst_dir, leaf);
    if (existing == src)
        goto out;
    if (existing != NULL) {
        if (flags & KFS_RENAME_NOREPLACE)
            rc = -EEXIST;
        else if (S_ISDIR(src->mode) && !S_ISDIR(existing->mode))
            rc = -ENOTDIR;
        else if (!S_ISDIR(src->mode) && S_ISDIR(existing->mode))
            rc = -EISDIR;
        else if (S_ISDIR(existing->mode) && existing->nchildren > 0)
            rc = -ENOTEMPTY;
        if (rc != 0)
            goto out;
        remove_node(fs, existing);
    }

    old_parent = kfs_meta_get(&fs->meta, src->parent);
    rc = to_errno(kfs_meta_move(&fs->meta, src, dst_dir, leaf));
    if (rc == 0) {
        src->ctime_ns = now;
        dst_dir->mtime_ns = dst_dir->ctime_ns = now;
        if (old_parent != NULL)
            old_parent->mtime_ns = old_parent->ctime_ns = now;
    }
out:
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

static int resolve_file(kfs_fs *fs, const char *path, kfs_inode **n)
{
    int rc = kfs_meta_resolve(&fs->meta, path, n);

    if (rc == 0 && S_ISDIR((*n)->mode))
        rc = -EISDIR;
    return rc;
}

int kfs_fs_read(kfs_fs *fs, const char *path, uint8_t *buf, size_t size, uint64_t off)
{
    uint32_t bs = fs->opts.block_size;
    size_t done = 0;
    kfs_inode *n;
    int rc;

    if (size > INT_MAX)
        size = INT_MAX;
    pthread_mutex_lock(&fs->lock);
    rc = resolve_file(fs, path, &n);
    if (rc != 0 || off >= n->size)
        goto out;
    if (size > n->size - off)
        size = (size_t)(n->size - off);

    while (done < size) {
        uint64_t pos = off + done;
        uint32_t index = (uint32_t)(pos / bs), in = (uint32_t)(pos % bs);
        size_t chunk = bs - in < size - done ? bs - in : size - done;
        uint8_t *frame;
        kfs_status st = get_block(fs, n, index, &frame);

        if (st != KFS_OK) {
            rc = to_errno(st);
            goto out;
        }
        memcpy(buf + done, frame + in, chunk);
        done += chunk;
    }
out:
    pthread_mutex_unlock(&fs->lock);
    return rc != 0 ? rc : (int)done;
}

int kfs_fs_write(kfs_fs *fs, const char *path, const uint8_t *buf, size_t size, uint64_t off)
{
    uint32_t bs = fs->opts.block_size;
    size_t done = 0;
    kfs_inode *n;
    int rc;

    if (size > INT_MAX)
        size = INT_MAX;
    pthread_mutex_lock(&fs->lock);
    rc = resolve_file(fs, path, &n);
    if (rc == 0 && (off > max_file_size(fs) || size > max_file_size(fs) - off))
        rc = -EFBIG;

    while (rc == 0 && done < size) {
        uint64_t pos = off + done;
        uint32_t index = (uint32_t)(pos / bs), in = (uint32_t)(pos % bs);
        size_t chunk = bs - in < size - done ? bs - in : size - done;
        uint8_t *frame;
        kfs_status st = get_block(fs, n, index, &frame);

        if (st != KFS_OK) {
            rc = to_errno(st);
            break;
        }
        /* Stage the new block contents, scan them, and only then commit
         * them to the cache. */
        memcpy(fs->scratch, frame, bs);
        memcpy(fs->scratch + in, buf + done, chunk);
        if (fs->opts.scan != NULL) {
            kfs_scan_hit hit = { 0, 0 };

            st = fs->opts.scan(fs->opts.scan_ctx, fs->scratch, bs, index == 0, &hit);
            if (st == KFS_E_MALWARE) {
                bool block = fs->opts.scan_action == KFS_SCAN_REJECT;

                if (fs->opts.audit != NULL)
                    fs->opts.audit(fs->opts.audit_ctx, path, &hit, block);
                if (block) {
                    rc = -EACCES;
                    break;
                }
            } else if (st != KFS_OK) {
                rc = to_errno(st);
                break;
            }
        }
        memcpy(frame, fs->scratch, bs);
        kfs_cache_mark_dirty(fs->cache, n->ino, index);
        done += chunk;
        if (pos + chunk > n->size)
            n->size = pos + chunk;
    }
    if (done > 0) {
        n->mtime_ns = n->ctime_ns = now_ns();
        fs->meta.dirty = true;
    }
    kfs_wipe(fs->scratch, bs);
    pthread_mutex_unlock(&fs->lock);
    /* A short write reports the bytes that landed; the error resurfaces
     * if the caller retries the remainder. */
    return done > 0 ? (int)done : rc;
}

int kfs_fs_truncate(kfs_fs *fs, const char *path, uint64_t size)
{
    uint32_t bs = fs->opts.block_size;
    kfs_inode *n;
    int rc;

    pthread_mutex_lock(&fs->lock);
    rc = resolve_file(fs, path, &n);
    if (rc == 0 && size > max_file_size(fs))
        rc = -EFBIG;
    if (rc == 0 && size < n->size) {
        uint32_t keep = (uint32_t)((size + bs - 1) / bs);

        kfs_cache_invalidate(fs->cache, n->ino, keep);
        kfs_meta_drop_blocks(&fs->meta, n, keep);
        /* Zero the tail of the last block so growing the file later never
         * resurrects the cut-off bytes. */
        if (size % bs != 0) {
            uint8_t *frame;
            kfs_status st = get_block(fs, n, (uint32_t)(size / bs), &frame);

            if (st != KFS_OK) {
                rc = to_errno(st);
            } else {
                memset(frame + size % bs, 0, bs - size % bs);
                kfs_cache_mark_dirty(fs->cache, n->ino, (uint32_t)(size / bs));
            }
        }
    }
    if (rc == 0) {
        n->size = size;
        n->mtime_ns = n->ctime_ns = now_ns();
        fs->meta.dirty = true;
    }
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

int kfs_fs_chmod(kfs_fs *fs, const char *path, uint32_t mode)
{
    kfs_inode *n;
    int rc;

    pthread_mutex_lock(&fs->lock);
    rc = kfs_meta_resolve(&fs->meta, path, &n);
    if (rc == 0) {
        n->mode = (n->mode & (uint32_t)S_IFMT) | (mode & 07777);
        n->ctime_ns = now_ns();
        fs->meta.dirty = true;
    }
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

int kfs_fs_chown(kfs_fs *fs, const char *path, uint32_t uid, uint32_t gid)
{
    kfs_inode *n;
    int rc;

    pthread_mutex_lock(&fs->lock);
    rc = kfs_meta_resolve(&fs->meta, path, &n);
    if (rc == 0) {
        if (uid != KFS_ID_UNCHANGED)
            n->uid = uid;
        if (gid != KFS_ID_UNCHANGED)
            n->gid = gid;
        n->ctime_ns = now_ns();
        fs->meta.dirty = true;
    }
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

int kfs_fs_utimens(kfs_fs *fs, const char *path, int64_t mtime_ns)
{
    kfs_inode *n;
    int rc;

    pthread_mutex_lock(&fs->lock);
    rc = kfs_meta_resolve(&fs->meta, path, &n);
    if (rc == 0) {
        n->mtime_ns = mtime_ns;
        n->ctime_ns = now_ns();
        fs->meta.dirty = true;
    }
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

int kfs_fs_sync(kfs_fs *fs)
{
    kfs_status st;

    pthread_mutex_lock(&fs->lock);
    st = sync_locked(fs);
    pthread_mutex_unlock(&fs->lock);
    return to_errno(st);
}

typedef struct walk_state {
    kfs_fs     *fs;
    kfs_walk_fn fn;
    void       *ctx;
    size_t      left;
    char        path[4096];
} walk_state;

static bool walk_node(walk_state *w, const kfs_inode *n, size_t path_len, unsigned depth)
{
    kfs_stat st;

    if (w->left == 0)
        return false;
    w->left--;
    fill_stat(w->fs, n, &st);
    w->fn(w->ctx, w->path, depth, &st);
    if (!S_ISDIR(n->mode))
        return true;
    for (uint32_t i = 0; i < n->nchildren; i++) {
        const kfs_inode *c = kfs_meta_get(&w->fs->meta, n->children[i]);
        size_t name_len, len = path_len;

        if (c == NULL)
            continue;
        name_len = strlen(c->name);
        if (len + 1 + name_len >= sizeof(w->path))
            continue; /* too deep to show */
        if (len > 1)
            w->path[len++] = '/';
        memcpy(w->path + len, c->name, name_len + 1);
        if (!walk_node(w, c, len + name_len, depth + 1))
            return false;
        w->path[path_len] = '\0';
    }
    return true;
}

bool kfs_fs_walk(kfs_fs *fs, size_t max_entries, kfs_walk_fn fn, void *ctx)
{
    walk_state *w = malloc(sizeof(*w));
    const kfs_inode *root;
    bool complete = false;

    if (w == NULL)
        return false;
    w->fs = fs;
    w->fn = fn;
    w->ctx = ctx;
    w->left = max_entries;
    strcpy(w->path, "/");
    pthread_mutex_lock(&fs->lock);
    root = kfs_meta_get(&fs->meta, KFS_ROOT_INO);
    if (root != NULL)
        complete = walk_node(w, root, 1, 0);
    pthread_mutex_unlock(&fs->lock);
    free(w);
    return complete;
}

void kfs_fs_usage_get(kfs_fs *fs, kfs_fs_usage *out)
{
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&fs->lock);
    for (uint64_t i = 0; i < fs->meta.table_cap; i++) {
        const kfs_inode *n = fs->meta.table[i];

        if (n == NULL)
            continue;
        if (S_ISDIR(n->mode))
            out->dirs++;
        else
            out->files++;
        for (uint32_t g = 0; g < n->ngens; g++)
            out->data_blocks += n->gens[g] != 0;
    }
    kfs_cache_get_stats(fs->cache, &out->cache);
    pthread_mutex_unlock(&fs->lock);
}
