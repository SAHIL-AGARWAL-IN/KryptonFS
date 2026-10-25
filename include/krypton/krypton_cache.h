/*
 * krypton_cache.h - Plaintext block cache.
 *
 * A fixed pool of block-sized frames in one anonymous mmap region,
 * optionally mlock()ed so plaintext never reaches swap, and always
 * excluded from core dumps. Frames are keyed by (inode, block index),
 * found through a hash table and evicted least-recently-used first; a
 * dirty frame is written back through the caller's callback before its
 * frame is reused.
 *
 * Not thread-safe: the filesystem layer serializes access.
 */
#ifndef KRYPTON_CACHE_H
#define KRYPTON_CACHE_H

#include <stdbool.h>
#include <stdint.h>

#include "krypton_common.h"

typedef struct kfs_cache kfs_cache;

typedef kfs_status (*kfs_cache_writeback_fn)(void *ctx, uint64_t ino,
                                             uint32_t index, const uint8_t *data);

typedef struct kfs_cache_stats {
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t writebacks;
    uint32_t frames;
    uint32_t used;
    uint32_t dirty;
} kfs_cache_stats;

/* KFS_E_NOMEM if the region cannot be mapped, or locked when
 * lock_memory is set (raise RLIMIT_MEMLOCK or grant CAP_IPC_LOCK). */
kfs_status kfs_cache_new(uint64_t bytes, uint32_t block_size, bool lock_memory,
                         kfs_cache **out);
void kfs_cache_free(kfs_cache *c);

/* The cached frame, or NULL on a miss. Marks it most recently used. */
uint8_t *kfs_cache_find(kfs_cache *c, uint64_t ino, uint32_t index);

/* A frame for a block not yet cached; its contents are unspecified. */
kfs_status kfs_cache_alloc(kfs_cache *c, uint64_t ino, uint32_t index,
                           kfs_cache_writeback_fn wb, void *ctx, uint8_t **frame);

void kfs_cache_mark_dirty(kfs_cache *c, uint64_t ino, uint32_t index);

/* Writes back every dirty frame; stops at the first failure. */
kfs_status kfs_cache_flush(kfs_cache *c, kfs_cache_writeback_fn wb, void *ctx);

/* Discards (without writing back) the inode's frames with index >= from. */
void kfs_cache_invalidate(kfs_cache *c, uint64_t ino, uint32_t from_index);

/* Discards one frame without writing it back. */
void kfs_cache_drop(kfs_cache *c, uint64_t ino, uint32_t index);

void kfs_cache_get_stats(const kfs_cache *c, kfs_cache_stats *out);

#endif /* KRYPTON_CACHE_H */
