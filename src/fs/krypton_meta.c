/*
 * krypton_meta.c - Inode table, path resolution and metadata commits.
 */
#define _XOPEN_SOURCE 700 /* strdup, S_IFDIR / S_IFREG */

#include "krypton/krypton_meta.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "krypton/krypton_volume.h"

#define META_MAGIC 0x4B464D31u /* 'K' 'F' 'M' '1' */
#define ROOT_LEN   24u          /* meta_gen u64 | blob_len u64 | nchunks u32 | 0 u32 */

/* ---------------------------------------------------------------------
 * Inodes and the table
 * ------------------------------------------------------------------- */

static kfs_inode *inode_alloc(uint64_t ino, const char *name)
{
    kfs_inode *n = calloc(1, sizeof(*n));

    if (n == NULL)
        return NULL;
    n->ino = ino;
    n->name = strdup(name);
    if (n->name == NULL) {
        free(n);
        return NULL;
    }
    return n;
}

static void inode_free(kfs_inode *n)
{
    if (n == NULL)
        return;
    free(n->name);
    free(n->gens);
    free(n->committed);
    free(n->children);
    free(n);
}

static kfs_status table_put(kfs_meta *m, kfs_inode *n)
{
    if (n->ino >= m->table_cap) {
        uint64_t cap = m->table_cap != 0 ? m->table_cap : 64;
        kfs_inode **t;

        while (cap <= n->ino)
            cap *= 2;
        t = realloc(m->table, (size_t)cap * sizeof(*t));
        if (t == NULL)
            return KFS_E_NOMEM;
        memset(t + m->table_cap, 0, (size_t)(cap - m->table_cap) * sizeof(*t));
        m->table = t;
        m->table_cap = cap;
    }
    m->table[n->ino] = n;
    return KFS_OK;
}

static kfs_status child_add(kfs_inode *dir, uint64_t ino)
{
    if (dir->nchildren == dir->children_cap) {
        uint32_t cap = dir->children_cap != 0 ? dir->children_cap * 2 : 8;
        uint64_t *c = realloc(dir->children, (size_t)cap * sizeof(*c));

        if (c == NULL)
            return KFS_E_NOMEM;
        dir->children = c;
        dir->children_cap = cap;
    }
    dir->children[dir->nchildren++] = ino;
    return KFS_OK;
}

static void child_del(kfs_inode *dir, uint64_t ino)
{
    for (uint32_t i = 0; i < dir->nchildren; i++) {
        if (dir->children[i] == ino) {
            dir->children[i] = dir->children[--dir->nchildren];
            return;
        }
    }
}

static kfs_status freed_push(kfs_meta *m, uint64_t ino, uint32_t index)
{
    if (m->nfreed == m->freed_cap) {
        size_t cap = m->freed_cap != 0 ? m->freed_cap * 2 : 64;
        kfs_freed *f = realloc(m->freed, cap * sizeof(*f));

        if (f == NULL)
            return KFS_E_NOMEM; /* the copy leaks on storage; harmless */
        m->freed = f;
        m->freed_cap = cap;
    }
    m->freed[m->nfreed++] = (kfs_freed){ ino, index };
    return KFS_OK;
}

static kfs_status grow_gens(kfs_inode *n, uint32_t need)
{
    uint32_t cap = n->ngens != 0 ? n->ngens : 4;
    uint64_t *g, *c;

    if (need <= n->ngens)
        return KFS_OK;
    while (cap < need)
        cap = cap > KFS_MAX_FILE_BLOCKS / 2 ? KFS_MAX_FILE_BLOCKS : cap * 2;
    g = realloc(n->gens, (size_t)cap * sizeof(*g));
    if (g == NULL)
        return KFS_E_NOMEM;
    n->gens = g;
    c = realloc(n->committed, (size_t)cap * sizeof(*c));
    if (c == NULL)
        return KFS_E_NOMEM;
    n->committed = c;
    memset(n->gens + n->ngens, 0, (size_t)(cap - n->ngens) * sizeof(*g));
    memset(n->committed + n->ngens, 0, (size_t)(cap - n->ngens) * sizeof(*c));
    n->ngens = cap;
    return KFS_OK;
}

kfs_status kfs_meta_init(kfs_meta *m, uint32_t block_size, uint32_t root_mode,
                         uint32_t uid, uint32_t gid, int64_t now_ns)
{
    kfs_inode *root;

    memset(m, 0, sizeof(*m));
    m->block_size = block_size;
    m->next_ino = KFS_ROOT_INO + 1;
    root = inode_alloc(KFS_ROOT_INO, "");
    if (root == NULL)
        return KFS_E_NOMEM;
    root->parent = KFS_ROOT_INO;
    root->mode = S_IFDIR | (root_mode & 07777);
    root->uid = uid;
    root->gid = gid;
    root->mtime_ns = root->ctime_ns = now_ns;
    if (table_put(m, root) != KFS_OK) {
        inode_free(root);
        return KFS_E_NOMEM;
    }
    m->dirty = true;
    return KFS_OK;
}

void kfs_meta_destroy(kfs_meta *m)
{
    for (uint64_t i = 0; i < m->table_cap; i++)
        inode_free(m->table[i]);
    free(m->table);
    free(m->freed);
    memset(m, 0, sizeof(*m));
}

kfs_inode *kfs_meta_get(const kfs_meta *m, uint64_t ino)
{
    return ino < m->table_cap ? m->table[ino] : NULL;
}

kfs_inode *kfs_meta_child(const kfs_meta *m, const kfs_inode *dir, const char *name)
{
    for (uint32_t i = 0; i < dir->nchildren; i++) {
        kfs_inode *c = kfs_meta_get(m, dir->children[i]);

        if (c != NULL && strcmp(c->name, name) == 0)
            return c;
    }
    return NULL;
}

bool kfs_meta_name_ok(const char *name)
{
    size_t n = strlen(name);

    return n > 0 && n <= KFS_NAME_LEN_MAX && strchr(name, '/') == NULL &&
           strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

static int walk(const kfs_meta *m, const char *path, bool want_parent,
                kfs_inode **out, char *leaf)
{
    kfs_inode *cur = kfs_meta_get(m, KFS_ROOT_INO);
    const char *p = path;

    if (*p != '/' || cur == NULL)
        return -EINVAL;
    for (;;) {
        char name[KFS_NAME_LEN_MAX + 1];
        const char *end;
        size_t n;

        while (*p == '/')
            p++;
        if (*p == '\0') {
            if (want_parent)
                return -EINVAL; /* "/" has no parent entry */
            *out = cur;
            return 0;
        }
        end = strchr(p, '/');
        n = end != NULL ? (size_t)(end - p) : strlen(p);
        if (n > KFS_NAME_LEN_MAX)
            return -ENAMETOOLONG;
        memcpy(name, p, n);
        name[n] = '\0';
        p += n;
        while (*p == '/')
            p++;

        if (!S_ISDIR(cur->mode))
            return -ENOTDIR;
        if (*p == '\0' && want_parent) {
            memcpy(leaf, name, n + 1);
            *out = cur;
            return 0;
        }
        cur = kfs_meta_child(m, cur, name);
        if (cur == NULL)
            return -ENOENT;
    }
}

int kfs_meta_resolve(const kfs_meta *m, const char *path, kfs_inode **out)
{
    return walk(m, path, false, out, NULL);
}

int kfs_meta_resolve_parent(const kfs_meta *m, const char *path,
                            kfs_inode **parent, char leaf[KFS_NAME_LEN_MAX + 1])
{
    return walk(m, path, true, parent, leaf);
}

kfs_status kfs_meta_create(kfs_meta *m, kfs_inode *dir, const char *name,
                           uint32_t mode, uint32_t uid, uint32_t gid,
                           int64_t now_ns, kfs_inode **out)
{
    kfs_inode *n;

    if (!kfs_meta_name_ok(name) || !S_ISDIR(dir->mode))
        return KFS_E_INVAL;
    if (m->next_ino > KFS_MAX_INO)
        return KFS_E_NOMEM;
    n = inode_alloc(m->next_ino, name);
    if (n == NULL)
        return KFS_E_NOMEM;
    n->parent = dir->ino;
    n->mode = mode;
    n->uid = uid;
    n->gid = gid;
    n->mtime_ns = n->ctime_ns = now_ns;
    if (table_put(m, n) != KFS_OK || child_add(dir, n->ino) != KFS_OK) {
        if (n->ino < m->table_cap)
            m->table[n->ino] = NULL;
        inode_free(n);
        return KFS_E_NOMEM;
    }
    m->next_ino++;
    dir->mtime_ns = dir->ctime_ns = now_ns;
    m->dirty = true;
    *out = n;
    return KFS_OK;
}

kfs_status kfs_meta_move(kfs_meta *m, kfs_inode *ino, kfs_inode *dir, const char *name)
{
    kfs_inode *old_parent = kfs_meta_get(m, ino->parent);
    char *new_name;

    if (!kfs_meta_name_ok(name) || !S_ISDIR(dir->mode) || old_parent == NULL)
        return KFS_E_INVAL;
    new_name = strdup(name);
    if (new_name == NULL)
        return KFS_E_NOMEM;
    if (dir != old_parent) {
        if (child_add(dir, ino->ino) != KFS_OK) {
            free(new_name);
            return KFS_E_NOMEM;
        }
        child_del(old_parent, ino->ino);
        ino->parent = dir->ino;
    }
    free(ino->name);
    ino->name = new_name;
    m->dirty = true;
    return KFS_OK;
}

void kfs_meta_drop_blocks(kfs_meta *m, kfs_inode *ino, uint32_t from_index)
{
    for (uint32_t i = from_index; i < ino->ngens; i++) {
        if (ino->gens[i] != 0 || ino->committed[i] != 0)
            freed_push(m, ino->ino, i);
        ino->gens[i] = 0;
    }
    m->dirty = true;
}

void kfs_meta_remove(kfs_meta *m, kfs_inode *ino)
{
    kfs_inode *parent = kfs_meta_get(m, ino->parent);

    kfs_meta_drop_blocks(m, ino, 0);
    if (parent != NULL && parent != ino)
        child_del(parent, ino->ino);
    m->table[ino->ino] = NULL;
    inode_free(ino);
    m->dirty = true;
}

uint64_t kfs_meta_block_gen(const kfs_inode *ino, uint32_t index)
{
    return index < ino->ngens ? ino->gens[index] : 0;
}

uint64_t kfs_meta_next_gen(kfs_meta *m, const kfs_inode *ino, uint32_t index)
{
    uint64_t committed = index < ino->ngens ? ino->committed[index] : 0;
    uint64_t g = m->next_gen + 1;

    if (committed != 0 && (g & 1) == (committed & 1))
        g++;
    m->next_gen = g;
    m->dirty = true;
    return g;
}

kfs_status kfs_meta_set_gen(kfs_meta *m, kfs_inode *ino, uint32_t index, uint64_t gen)
{
    kfs_status st;

    if (index >= KFS_MAX_FILE_BLOCKS)
        return KFS_E_INVAL;
    st = grow_gens(ino, index + 1);
    if (st != KFS_OK)
        return st;
    ino->gens[index] = gen;
    m->dirty = true;
    return KFS_OK;
}

/* ---------------------------------------------------------------------
 * Serialization
 * ------------------------------------------------------------------- */

typedef struct writer {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
    bool     failed;
} writer;

static void w_bytes(writer *w, const void *p, size_t n)
{
    if (w->failed)
        return;
    if (w->len + n > w->cap) {
        size_t cap = w->cap != 0 ? w->cap : 4096;
        uint8_t *b;

        while (cap < w->len + n)
            cap *= 2;
        b = realloc(w->buf, cap);
        if (b == NULL) {
            w->failed = true;
            return;
        }
        w->buf = b;
        w->cap = cap;
    }
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}

static void w_u16(writer *w, uint16_t v) { uint8_t b[2]; kfs_store_be16(b, v); w_bytes(w, b, 2); }
static void w_u32(writer *w, uint32_t v) { uint8_t b[4]; kfs_store_be32(b, v); w_bytes(w, b, 4); }
static void w_u64(writer *w, uint64_t v) { uint8_t b[8]; kfs_store_be64(b, v); w_bytes(w, b, 8); }

typedef struct reader {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
} reader;

static bool r_bytes(reader *r, void *out, size_t n)
{
    if (r->len - r->pos < n)
        return false;
    memcpy(out, r->buf + r->pos, n);
    r->pos += n;
    return true;
}

static bool r_u16(reader *r, uint16_t *v) { uint8_t b[2]; if (!r_bytes(r, b, 2)) return false; *v = kfs_load_be16(b); return true; }
static bool r_u32(reader *r, uint32_t *v) { uint8_t b[4]; if (!r_bytes(r, b, 4)) return false; *v = kfs_load_be32(b); return true; }
static bool r_u64(reader *r, uint64_t *v) { uint8_t b[8]; if (!r_bytes(r, b, 8)) return false; *v = kfs_load_be64(b); return true; }

/* Trailing holes are not stored. */
static uint32_t used_gens(const kfs_inode *n)
{
    uint32_t used = n->ngens;

    while (used > 0 && n->gens[used - 1] == 0)
        used--;
    return used;
}

kfs_status kfs_meta_serialize(const kfs_meta *m, uint8_t **buf, size_t *len)
{
    writer w = { NULL, 0, 0, false };
    uint32_t count = 0;

    for (uint64_t i = 0; i < m->table_cap; i++)
        count += m->table[i] != NULL;

    w_u32(&w, META_MAGIC);
    w_u32(&w, m->block_size);
    w_u64(&w, m->next_ino);
    w_u64(&w, m->next_gen);
    w_u32(&w, count);
    for (uint64_t i = 0; i < m->table_cap; i++) {
        const kfs_inode *n = m->table[i];
        uint32_t used;
        size_t nl;

        if (n == NULL)
            continue;
        used = used_gens(n);
        nl = strlen(n->name);
        w_u64(&w, n->ino);
        w_u64(&w, n->parent);
        w_u32(&w, n->mode);
        w_u32(&w, n->uid);
        w_u32(&w, n->gid);
        w_u64(&w, n->size);
        w_u64(&w, (uint64_t)n->mtime_ns);
        w_u64(&w, (uint64_t)n->ctime_ns);
        w_u16(&w, (uint16_t)nl);
        w_bytes(&w, n->name, nl);
        w_u32(&w, used);
        for (uint32_t g = 0; g < used; g++)
            w_u64(&w, n->gens[g]);
    }
    if (w.failed) {
        free(w.buf);
        return KFS_E_NOMEM;
    }
    *buf = w.buf;
    *len = w.len;
    return KFS_OK;
}

/* Every inode's parent chain must reach the root without a cycle. */
static bool reaches_root(const kfs_meta *m, const kfs_inode *n, uint32_t count)
{
    for (uint32_t steps = 0; steps <= count; steps++) {
        if (n->ino == KFS_ROOT_INO)
            return true;
        n = kfs_meta_get(m, n->parent);
        if (n == NULL)
            return false;
    }
    return false;
}

kfs_status kfs_meta_deserialize(kfs_meta *m, const uint8_t *buf, size_t len,
                                uint32_t block_size)
{
    reader r = { buf, len, 0 };
    uint32_t magic, bs, count;
    kfs_inode *root;

    memset(m, 0, sizeof(*m));
    if (!r_u32(&r, &magic) || !r_u32(&r, &bs) || !r_u64(&r, &m->next_ino) ||
        !r_u64(&r, &m->next_gen) || !r_u32(&r, &count) ||
        magic != META_MAGIC || bs != block_size ||
        m->next_ino <= KFS_ROOT_INO || m->next_ino > KFS_MAX_INO + 1)
        goto bad;
    m->block_size = block_size;

    for (uint32_t i = 0; i < count; i++) {
        uint64_t ino, parent, size, mtime, ctime;
        uint32_t mode, uid, gid, ngens;
        uint16_t nl;
        char name[KFS_NAME_LEN_MAX + 1];
        kfs_inode *n;

        if (!r_u64(&r, &ino) || !r_u64(&r, &parent) || !r_u32(&r, &mode) ||
            !r_u32(&r, &uid) || !r_u32(&r, &gid) || !r_u64(&r, &size) ||
            !r_u64(&r, &mtime) || !r_u64(&r, &ctime) || !r_u16(&r, &nl) ||
            nl > KFS_NAME_LEN_MAX || !r_bytes(&r, name, nl))
            goto bad;
        name[nl] = '\0';
        if (ino == KFS_META_INO || ino >= m->next_ino || kfs_meta_get(m, ino) != NULL ||
            (!S_ISDIR(mode) && !S_ISREG(mode)) || strlen(name) != nl ||
            (ino == KFS_ROOT_INO ? (nl != 0 || parent != KFS_ROOT_INO || !S_ISDIR(mode))
                                 : !kfs_meta_name_ok(name)))
            goto bad;
        if (!r_u32(&r, &ngens) || ngens > KFS_MAX_FILE_BLOCKS ||
            (S_ISDIR(mode) && ngens != 0))
            goto bad;

        n = inode_alloc(ino, name);
        if (n == NULL || table_put(m, n) != KFS_OK) {
            inode_free(n);
            goto nomem;
        }
        n->parent = parent;
        n->mode = mode;
        n->uid = uid;
        n->gid = gid;
        n->size = size;
        n->mtime_ns = (int64_t)mtime;
        n->ctime_ns = (int64_t)ctime;
        if (ngens > 0 && grow_gens(n, ngens) != KFS_OK)
            goto nomem;
        for (uint32_t g = 0; g < ngens; g++) {
            if (!r_u64(&r, &n->gens[g]) || n->gens[g] > m->next_gen)
                goto bad;
            n->committed[g] = n->gens[g];
        }
        if (S_ISREG(mode) && size > (uint64_t)KFS_MAX_FILE_BLOCKS * block_size)
            goto bad;
    }
    if (r.pos != r.len)
        goto bad;

    root = kfs_meta_get(m, KFS_ROOT_INO);
    if (root == NULL)
        goto bad;
    for (uint64_t i = 0; i < m->table_cap; i++) {
        kfs_inode *n = m->table[i], *parent;

        if (n == NULL || n->ino == KFS_ROOT_INO)
            continue;
        parent = kfs_meta_get(m, n->parent);
        if (parent == NULL || !S_ISDIR(parent->mode) || !reaches_root(m, n, count) ||
            kfs_meta_child(m, parent, n->name) != NULL)
            goto bad;
        if (child_add(parent, n->ino) != KFS_OK)
            goto nomem;
    }
    return KFS_OK;

bad:
    kfs_meta_destroy(m);
    return KFS_E_PROTO;
nomem:
    kfs_meta_destroy(m);
    return KFS_E_NOMEM;
}

/* ---------------------------------------------------------------------
 * Commit and load
 * ------------------------------------------------------------------- */

kfs_status kfs_meta_commit(kfs_meta *m, kfs_blockio *io)
{
    uint64_t gen = m->meta_gen + 1;
    uint32_t bs = m->block_size, parity = (uint32_t)(gen & 1), nchunks;
    uint8_t root[ROOT_LEN], *blob = NULL, *padded;
    size_t len = 0;
    kfs_status st;

    st = kfs_meta_serialize(m, &blob, &len);
    if (st != KFS_OK)
        return st;
    nchunks = (uint32_t)((len + bs - 1) / bs);
    if ((uint64_t)nchunks + KFS_META_CHUNK_INDEX > KFS_MAX_FILE_BLOCKS) {
        kfs_wipe(blob, len);
        free(blob);
        return KFS_E_NOMEM;
    }
    padded = calloc(nchunks, bs);
    if (padded == NULL) {
        kfs_wipe(blob, len);
        free(blob);
        return KFS_E_NOMEM;
    }
    memcpy(padded, blob, len);
    kfs_wipe(blob, len);
    free(blob);

    /* Chunks first, root last: until the root lands, the previous commit
     * (in the other copy) is still the valid one. */
    for (uint32_t i = 0; i < nchunks && st == KFS_OK; i++)
        st = kfs_blockio_write(io, kfs_bid(KFS_META_INO, KFS_META_CHUNK_INDEX + i, gen),
                               gen, padded + (size_t)i * bs, bs);
    kfs_wipe(padded, (size_t)nchunks * bs);
    free(padded);
    if (st != KFS_OK)
        return st;

    kfs_store_be64(root, gen);
    kfs_store_be64(root + 8, len);
    kfs_store_be32(root + 16, nchunks);
    kfs_store_be32(root + 20, 0);
    st = kfs_blockio_write(io, kfs_bid(KFS_META_INO, KFS_META_ROOT_INDEX, gen), gen,
                           root, ROOT_LEN);
    if (st != KFS_OK)
        return st;

    /* Committed. Everything below is cleanup that may fail harmlessly. */
    m->meta_gen = gen;
    m->dirty = false;
    for (uint64_t i = 0; i < m->table_cap; i++) {
        kfs_inode *n = m->table[i];

        if (n != NULL && n->ngens > 0)
            memcpy(n->committed, n->gens, (size_t)n->ngens * sizeof(*n->gens));
    }
    for (uint32_t i = nchunks; i < m->chunks[parity]; i++)
        kfs_backend_del(io->backend, kfs_bid(KFS_META_INO, KFS_META_CHUNK_INDEX + i, gen));
    m->chunks[parity] = nchunks;

    /* Delete obsolete data copies, sparing whichever copy is now live. */
    for (size_t i = 0; i < m->nfreed; i++) {
        const kfs_inode *n = kfs_meta_get(m, m->freed[i].ino);
        uint64_t live = n != NULL ? kfs_meta_block_gen(n, m->freed[i].index) : 0;

        for (uint64_t p = 0; p < 2; p++) {
            if (live == 0 || (live & 1) != p)
                kfs_backend_del(io->backend, kfs_bid(m->freed[i].ino, m->freed[i].index, p));
        }
    }
    m->nfreed = 0;
    return KFS_OK;
}

static kfs_status read_root(kfs_blockio *io, uint64_t parity, uint64_t *gen,
                            uint64_t *blob_len, uint32_t *nchunks)
{
    uint8_t root[ROOT_LEN];
    uint64_t env_gen;
    kfs_status st;

    st = kfs_blockio_read(io, kfs_bid(KFS_META_INO, KFS_META_ROOT_INDEX, parity),
                          root, ROOT_LEN, KFS_GEN_NEWEST, &env_gen);
    if (st != KFS_OK)
        return st;
    *gen = kfs_load_be64(root);
    *blob_len = kfs_load_be64(root + 8);
    *nchunks = kfs_load_be32(root + 16);
    if (*gen != env_gen || *gen == 0 || (*gen & 1) != parity ||
        kfs_load_be32(root + 20) != 0)
        return KFS_E_AUTH;
    return KFS_OK;
}

kfs_status kfs_meta_load(kfs_meta *m, kfs_blockio *io, uint32_t block_size)
{
    uint64_t gen[2] = { 0, 0 }, blob_len[2] = { 0, 0 };
    uint32_t nchunks[2] = { 0, 0 }, use;
    uint8_t *blob;
    kfs_status st;

    for (uint64_t p = 0; p < 2; p++) {
        st = read_root(io, p, &gen[p], &blob_len[p], &nchunks[p]);
        /* A root with no authentic copy on any replica, or an unreachable
         * replica that might hold a newer one, fails the mount: falling
         * back to the other root would let storage roll the volume back. */
        if (st != KFS_OK && st != KFS_E_NOT_FOUND)
            return st;
        if (st == KFS_E_NOT_FOUND)
            gen[p] = 0;
    }
    if (gen[0] == 0 && gen[1] == 0)
        return KFS_E_NOT_FOUND;
    use = gen[1] > gen[0] ? 1 : 0;

    if (nchunks[use] == 0 || nchunks[use] > KFS_MAX_FILE_BLOCKS ||
        blob_len[use] > (uint64_t)nchunks[use] * block_size ||
        blob_len[use] <= (uint64_t)(nchunks[use] - 1) * block_size)
        return KFS_E_PROTO;
    blob = malloc((size_t)nchunks[use] * block_size);
    if (blob == NULL)
        return KFS_E_NOMEM;

    st = KFS_OK;
    for (uint32_t i = 0; i < nchunks[use] && st == KFS_OK; i++) {
        uint64_t chunk_gen = 0;

        /* Chunks must carry the root's generation: a chunk left over
         * from another commit is rejected. */
        st = kfs_blockio_read(io, kfs_bid(KFS_META_INO, KFS_META_CHUNK_INDEX + i, gen[use]),
                              blob + (size_t)i * block_size, block_size, gen[use],
                              &chunk_gen);
    }
    if (st == KFS_OK)
        st = kfs_meta_deserialize(m, blob, (size_t)blob_len[use], block_size);
    kfs_wipe(blob, (size_t)nchunks[use] * block_size);
    free(blob);
    if (st != KFS_OK)
        return st;

    m->meta_gen = gen[use];
    m->chunks[use] = nchunks[use];
    m->chunks[use ^ 1] = gen[use ^ 1] != 0 ? nchunks[use ^ 1] : 0;
    return KFS_OK;
}
