/*
 * krypton_meta.h - Inode table and its encrypted, crash-safe persistence.
 *
 * All metadata (names, sizes, modes, times and the generation of every
 * data block) lives in memory and is committed as one serialized blob,
 * split into block-sized chunks and sealed like file data:
 *
 *   chunk i   -> kfs_bid(0, KFS_META_CHUNK_INDEX + i, meta_gen)
 *   root      -> kfs_bid(0, KFS_META_ROOT_INDEX, meta_gen)
 *                (meta_gen, blob length, chunk count)
 *
 * meta_gen increments per commit, so consecutive commits alternate
 * between the two storage copies. Chunks are written first and the root
 * last; a crash at any point leaves the previous commit intact. Every
 * chunk must carry the root's generation, so stale chunks are rejected.
 *
 * Data block generations come from one volume-wide counter, so a
 * generation is never reused, and each rewrite picks the parity opposite
 * to the block's *committed* generation. Storage copies made obsolete by
 * unlink or truncate are deleted only after the next commit lands.
 *
 * Not thread-safe: the filesystem layer serializes access.
 */
#ifndef KRYPTON_META_H
#define KRYPTON_META_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "krypton_blockio.h"
#include "krypton_common.h"

#define KFS_ROOT_INO     1u
#define KFS_NAME_LEN_MAX 255u

typedef struct kfs_inode {
    uint64_t  ino;
    uint64_t  parent;     /* the root is its own parent */
    uint32_t  mode;       /* S_IFDIR or S_IFREG plus permission bits */
    uint32_t  uid;
    uint32_t  gid;
    uint64_t  size;
    int64_t   mtime_ns;
    int64_t   ctime_ns;
    char     *name;       /* within the parent; "" for the root */
    uint64_t *gens;       /* current generation per block, 0 = hole */
    uint64_t *committed;  /* generation as of the last commit */
    uint32_t  ngens;      /* length of both arrays */
    uint64_t *children;   /* directories only */
    uint32_t  nchildren;
    uint32_t  children_cap;
} kfs_inode;

typedef struct kfs_freed {
    uint64_t ino;
    uint32_t index;
} kfs_freed;

typedef struct kfs_meta {
    kfs_inode **table;      /* indexed by inode number */
    uint64_t    table_cap;
    uint64_t    next_ino;
    uint64_t    next_gen;   /* last data generation handed out */
    uint64_t    meta_gen;   /* generation of the last commit, 0 = none */
    uint32_t    block_size;
    uint32_t    chunks[2];  /* chunk count stored in each copy */
    kfs_freed  *freed;      /* storage to delete after the next commit */
    size_t      nfreed;
    size_t      freed_cap;
    bool        dirty;
} kfs_meta;

/* An empty volume holding only the root directory. */
kfs_status kfs_meta_init(kfs_meta *m, uint32_t block_size, uint32_t root_mode,
                         uint32_t uid, uint32_t gid, int64_t now_ns);
void kfs_meta_destroy(kfs_meta *m);

/* KFS_E_NOT_FOUND when the volume has no committed metadata yet. */
kfs_status kfs_meta_load(kfs_meta *m, kfs_blockio *io, uint32_t block_size);
kfs_status kfs_meta_commit(kfs_meta *m, kfs_blockio *io);

kfs_inode *kfs_meta_get(const kfs_meta *m, uint64_t ino);
kfs_inode *kfs_meta_child(const kfs_meta *m, const kfs_inode *dir, const char *name);

/* Path lookups return 0 or a negative errno (-ENOENT, -ENOTDIR,
 * -ENAMETOOLONG, -EINVAL). resolve_parent copies the final component to
 * leaf and fails with -EINVAL for "/". */
int kfs_meta_resolve(const kfs_meta *m, const char *path, kfs_inode **out);
int kfs_meta_resolve_parent(const kfs_meta *m, const char *path,
                            kfs_inode **parent, char leaf[KFS_NAME_LEN_MAX + 1]);

bool kfs_meta_name_ok(const char *name);

kfs_status kfs_meta_create(kfs_meta *m, kfs_inode *dir, const char *name,
                           uint32_t mode, uint32_t uid, uint32_t gid,
                           int64_t now_ns, kfs_inode **out);

/* Moves ino under dir as name; any existing entry must be removed first. */
kfs_status kfs_meta_move(kfs_meta *m, kfs_inode *ino, kfs_inode *dir, const char *name);

/* Unlinks and frees an inode, queuing its storage for deletion. */
void kfs_meta_remove(kfs_meta *m, kfs_inode *ino);

/* Turns blocks >= from_index into holes, queuing their storage. */
void kfs_meta_drop_blocks(kfs_meta *m, kfs_inode *ino, uint32_t from_index);

uint64_t kfs_meta_block_gen(const kfs_inode *ino, uint32_t index);

/* A fresh generation for rewriting a block, of the parity opposite to the
 * block's committed copy. */
uint64_t kfs_meta_next_gen(kfs_meta *m, const kfs_inode *ino, uint32_t index);
kfs_status kfs_meta_set_gen(kfs_meta *m, kfs_inode *ino, uint32_t index, uint64_t gen);

/* Serialization, exposed for tests. */
kfs_status kfs_meta_serialize(const kfs_meta *m, uint8_t **buf, size_t *len);
kfs_status kfs_meta_deserialize(kfs_meta *m, const uint8_t *buf, size_t len,
                                uint32_t block_size);

#endif /* KRYPTON_META_H */
