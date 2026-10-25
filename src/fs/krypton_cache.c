/*
 * krypton_cache.c - mmap-backed LRU block cache.
 */
#define _DEFAULT_SOURCE /* MADV_DONTDUMP, MAP_ANONYMOUS */

#include "krypton/krypton_cache.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "krypton/krypton_crypto.h"

#define NONE UINT32_MAX

typedef struct frame {
    uint64_t ino;
    uint32_t index;
    uint32_t hnext; /* hash chain */
    uint32_t prev;  /* LRU list, most recent at head */
    uint32_t next;
    bool     used;
    bool     dirty;
} frame;

struct kfs_cache {
    uint8_t  *region;
    size_t    region_size;
    bool      locked;
    uint32_t  block_size;
    uint32_t  nframes;
    frame    *frames;
    uint32_t *buckets;
    uint32_t  nbuckets; /* power of two */
    uint32_t *free_stack;
    uint32_t  nfree;
    uint32_t  lru_head;
    uint32_t  lru_tail;
    kfs_cache_stats stats;
};

static uint32_t bucket_of(const kfs_cache *c, uint64_t ino, uint32_t index)
{
    uint64_t h = (ino * 0x9E3779B97F4A7C15ull) ^ ((uint64_t)index * 0xC2B2AE3D27D4EB4Full);

    return (uint32_t)(h >> 32) & (c->nbuckets - 1);
}

static uint8_t *frame_data(const kfs_cache *c, uint32_t f)
{
    return c->region + (size_t)f * c->block_size;
}

static void lru_unlink(kfs_cache *c, uint32_t f)
{
    frame *fr = &c->frames[f];

    if (fr->prev != NONE)
        c->frames[fr->prev].next = fr->next;
    else
        c->lru_head = fr->next;
    if (fr->next != NONE)
        c->frames[fr->next].prev = fr->prev;
    else
        c->lru_tail = fr->prev;
    fr->prev = fr->next = NONE;
}

static void lru_push_head(kfs_cache *c, uint32_t f)
{
    frame *fr = &c->frames[f];

    fr->prev = NONE;
    fr->next = c->lru_head;
    if (c->lru_head != NONE)
        c->frames[c->lru_head].prev = f;
    c->lru_head = f;
    if (c->lru_tail == NONE)
        c->lru_tail = f;
}

static uint32_t lookup(const kfs_cache *c, uint64_t ino, uint32_t index)
{
    for (uint32_t f = c->buckets[bucket_of(c, ino, index)]; f != NONE; f = c->frames[f].hnext) {
        if (c->frames[f].ino == ino && c->frames[f].index == index)
            return f;
    }
    return NONE;
}

static void hash_remove(kfs_cache *c, uint32_t f)
{
    uint32_t *link = &c->buckets[bucket_of(c, c->frames[f].ino, c->frames[f].index)];

    while (*link != NONE) {
        if (*link == f) {
            *link = c->frames[f].hnext;
            return;
        }
        link = &c->frames[*link].hnext;
    }
}

static void release_frame(kfs_cache *c, uint32_t f)
{
    hash_remove(c, f);
    lru_unlink(c, f);
    kfs_wipe(frame_data(c, f), c->block_size);
    if (c->frames[f].dirty)
        c->stats.dirty--;
    c->frames[f].used = c->frames[f].dirty = false;
    c->stats.used--;
    c->free_stack[c->nfree++] = f;
}

kfs_status kfs_cache_new(uint64_t bytes, uint32_t block_size, bool lock_memory,
                         kfs_cache **out)
{
    kfs_cache *c;
    uint64_t nframes = bytes / block_size;

    if (block_size == 0 || nframes < 2 || nframes >= NONE)
        return KFS_E_INVAL;
    c = calloc(1, sizeof(*c));
    if (c == NULL)
        return KFS_E_NOMEM;
    c->block_size = block_size;
    c->nframes = (uint32_t)nframes;
    c->region_size = (size_t)nframes * block_size;
    c->nbuckets = 1;
    while (c->nbuckets < c->nframes * 2)
        c->nbuckets *= 2;

    c->region = mmap(NULL, c->region_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    c->frames = calloc(c->nframes, sizeof(*c->frames));
    c->buckets = malloc((size_t)c->nbuckets * sizeof(*c->buckets));
    c->free_stack = malloc((size_t)c->nframes * sizeof(*c->free_stack));
    if (c->region == MAP_FAILED || c->frames == NULL || c->buckets == NULL ||
        c->free_stack == NULL)
        goto fail;
    if (lock_memory) {
        if (mlock(c->region, c->region_size) != 0)
            goto fail;
        c->locked = true;
    }
    madvise(c->region, c->region_size, MADV_DONTDUMP);

    memset(c->buckets, 0xff, (size_t)c->nbuckets * sizeof(*c->buckets));
    for (uint32_t i = 0; i < c->nframes; i++) {
        c->frames[i].prev = c->frames[i].next = c->frames[i].hnext = NONE;
        c->free_stack[i] = c->nframes - 1 - i;
    }
    c->nfree = c->nframes;
    c->lru_head = c->lru_tail = NONE;
    c->stats.frames = c->nframes;
    *out = c;
    return KFS_OK;
fail:
    if (c->region != MAP_FAILED)
        munmap(c->region, c->region_size);
    c->region = NULL;
    kfs_cache_free(c);
    return KFS_E_NOMEM;
}

void kfs_cache_free(kfs_cache *c)
{
    if (c == NULL)
        return;
    if (c->region != NULL) {
        kfs_wipe(c->region, c->region_size);
        if (c->locked)
            munlock(c->region, c->region_size);
        munmap(c->region, c->region_size);
    }
    free(c->frames);
    free(c->buckets);
    free(c->free_stack);
    free(c);
}

uint8_t *kfs_cache_find(kfs_cache *c, uint64_t ino, uint32_t index)
{
    uint32_t f = lookup(c, ino, index);

    if (f == NONE) {
        c->stats.misses++;
        return NULL;
    }
    c->stats.hits++;
    lru_unlink(c, f);
    lru_push_head(c, f);
    return frame_data(c, f);
}

kfs_status kfs_cache_alloc(kfs_cache *c, uint64_t ino, uint32_t index,
                           kfs_cache_writeback_fn wb, void *ctx, uint8_t **out)
{
    uint32_t f, b;

    if (c->nfree == 0) {
        uint32_t victim = c->lru_tail;

        if (c->frames[victim].dirty) {
            kfs_status st = wb(ctx, c->frames[victim].ino, c->frames[victim].index,
                               frame_data(c, victim));

            if (st != KFS_OK)
                return st;
            c->stats.writebacks++;
        }
        release_frame(c, victim);
        c->stats.evictions++;
    }

    f = c->free_stack[--c->nfree];
    c->frames[f].ino = ino;
    c->frames[f].index = index;
    c->frames[f].used = true;
    c->frames[f].dirty = false;
    b = bucket_of(c, ino, index);
    c->frames[f].hnext = c->buckets[b];
    c->buckets[b] = f;
    lru_push_head(c, f);
    c->stats.used++;
    *out = frame_data(c, f);
    return KFS_OK;
}

void kfs_cache_mark_dirty(kfs_cache *c, uint64_t ino, uint32_t index)
{
    uint32_t f = lookup(c, ino, index);

    if (f != NONE && !c->frames[f].dirty) {
        c->frames[f].dirty = true;
        c->stats.dirty++;
    }
}

kfs_status kfs_cache_flush(kfs_cache *c, kfs_cache_writeback_fn wb, void *ctx)
{
    for (uint32_t f = 0; f < c->nframes; f++) {
        frame *fr = &c->frames[f];

        if (fr->used && fr->dirty) {
            kfs_status st = wb(ctx, fr->ino, fr->index, frame_data(c, f));

            if (st != KFS_OK)
                return st;
            fr->dirty = false;
            c->stats.dirty--;
            c->stats.writebacks++;
        }
    }
    return KFS_OK;
}

void kfs_cache_invalidate(kfs_cache *c, uint64_t ino, uint32_t from_index)
{
    for (uint32_t f = 0; f < c->nframes; f++) {
        if (c->frames[f].used && c->frames[f].ino == ino && c->frames[f].index >= from_index)
            release_frame(c, f);
    }
}

void kfs_cache_drop(kfs_cache *c, uint64_t ino, uint32_t index)
{
    uint32_t f = lookup(c, ino, index);

    if (f != NONE)
        release_frame(c, f);
}

void kfs_cache_get_stats(const kfs_cache *c, kfs_cache_stats *out)
{
    *out = c->stats;
}
