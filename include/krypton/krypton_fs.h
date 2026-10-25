/*
 * krypton_fs.h - Filesystem semantics over encrypted block storage.
 *
 * Path-based operations shaped like the FUSE high-level API, but with no
 * FUSE dependency, so they can be tested without mounting. Integer
 * results are 0 / a byte count on success or a negative errno.
 *
 * Writes are staged into a candidate copy of each block and scanned
 * before the cache accepts them, so a write rejected by the malware
 * scanner fails with -EACCES and leaves the file unchanged. Dirty blocks
 * reach storage on eviction, every writeback_ms, and on kfs_fs_sync().
 *
 * One mutex serializes all operations.
 */
#ifndef KRYPTON_FS_H
#define KRYPTON_FS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "krypton_blockio.h"
#include "krypton_cache.h"
#include "krypton_common.h"
#include "krypton_config.h"
#include "krypton_scanner.h"

typedef struct kfs_fs kfs_fs;

/* KFS_OK when clean, KFS_E_MALWARE with *hit on a match. */
typedef kfs_status (*kfs_scan_fn)(void *ctx, const uint8_t *block, size_t len,
                                  bool file_start, kfs_scan_hit *hit);

/* Called for every scanner match; blocked tells whether the write failed. */
typedef void (*kfs_audit_fn)(void *ctx, const char *path,
                             const kfs_scan_hit *hit, bool blocked);

typedef struct kfs_fs_opts {
    uint32_t        block_size;
    uint64_t        cache_bytes;
    bool            lock_memory;
    uint32_t        writeback_ms;  /* 0: no background writeback */
    kfs_scan_fn     scan;          /* NULL: scanning disabled */
    void           *scan_ctx;
    kfs_scan_action scan_action;
    kfs_audit_fn    audit;         /* optional */
    void           *audit_ctx;
    bool            format_if_empty; /* only kfs-mkvol formats a volume */
    uint32_t        root_uid;      /* owner of a new volume's root */
    uint32_t        root_gid;
} kfs_fs_opts;

typedef struct kfs_stat {
    uint64_t ino;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint64_t blocks512;
    int64_t  mtime_ns;
    int64_t  ctime_ns;
} kfs_stat;

/* Return nonzero to stop the listing. */
typedef int (*kfs_dirent_fn)(void *ctx, const char *name, const kfs_stat *st);

#define KFS_RENAME_NOREPLACE 1u
#define KFS_ID_UNCHANGED     UINT32_MAX

/* Loads committed metadata. If there is none: with format_if_empty,
 * formats an empty volume; otherwise KFS_E_NOT_FOUND, so a daemon never
 * reformats a volume whose metadata it merely failed to find. io must
 * outlive the filesystem. */
kfs_status kfs_fs_open(kfs_blockio *io, const kfs_fs_opts *opts, kfs_fs **out);

/* Final sync, then frees everything; returns the sync result. */
int kfs_fs_close(kfs_fs *fs);

int kfs_fs_getattr(kfs_fs *fs, const char *path, kfs_stat *st);
int kfs_fs_readdir(kfs_fs *fs, const char *path, kfs_dirent_fn fn, void *ctx);
int kfs_fs_mkdir(kfs_fs *fs, const char *path, uint32_t mode, uint32_t uid, uint32_t gid);
int kfs_fs_create(kfs_fs *fs, const char *path, uint32_t mode, uint32_t uid, uint32_t gid);
int kfs_fs_unlink(kfs_fs *fs, const char *path);
int kfs_fs_rmdir(kfs_fs *fs, const char *path);
int kfs_fs_rename(kfs_fs *fs, const char *from, const char *to, unsigned flags);
int kfs_fs_read(kfs_fs *fs, const char *path, uint8_t *buf, size_t size, uint64_t off);
int kfs_fs_write(kfs_fs *fs, const char *path, const uint8_t *buf, size_t size, uint64_t off);
int kfs_fs_truncate(kfs_fs *fs, const char *path, uint64_t size);
int kfs_fs_chmod(kfs_fs *fs, const char *path, uint32_t mode);
int kfs_fs_chown(kfs_fs *fs, const char *path, uint32_t uid, uint32_t gid);
int kfs_fs_utimens(kfs_fs *fs, const char *path, int64_t mtime_ns);

/* Writes back every dirty block, then commits metadata. */
int kfs_fs_sync(kfs_fs *fs);

typedef struct kfs_fs_usage {
    uint64_t        files;
    uint64_t        dirs;
    uint64_t        data_blocks; /* blocks holding data, excluding holes */
    kfs_cache_stats cache;
} kfs_fs_usage;

void kfs_fs_usage_get(kfs_fs *fs, kfs_fs_usage *out);

/* Depth-first listing for the dashboard: fn gets each entry's full path
 * (the root is "/"), depth, and stat. Stops after max_entries entries;
 * returns true if the whole tree was listed. */
typedef void (*kfs_walk_fn)(void *ctx, const char *path, unsigned depth, const kfs_stat *st);
bool kfs_fs_walk(kfs_fs *fs, size_t max_entries, kfs_walk_fn fn, void *ctx);

#endif /* KRYPTON_FS_H */
