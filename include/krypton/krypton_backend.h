/*
 * krypton_backend.h - Block storage backends.
 *
 * A backend stores opaque objects (encoded envelope + ciphertext, or the
 * volume header) under 64-bit block ids. It never sees keys or plaintext.
 * Every put must be atomic: a reader sees the old object or the new one,
 * never a mix.
 *
 * Phase 3 ships a local-directory backend; Phase 4 adds the replicated
 * network backend behind the same interface.
 */
#ifndef KRYPTON_BACKEND_H
#define KRYPTON_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "krypton_common.h"

typedef struct kfs_backend kfs_backend;

typedef struct kfs_backend_ops {
    kfs_status (*put)(kfs_backend *b, uint64_t id, const uint8_t *buf, size_t len);
    /*
     * Fetches the object from copy holder number replica (0 .. replicas-1,
     * in the backend's preference order). KFS_E_NOT_FOUND if that holder
     * lacks it, KFS_E_UNAVAILABLE if it cannot be reached, KFS_E_PROTO if
     * the object is larger than cap.
     */
    kfs_status (*get)(kfs_backend *b, uint64_t id, uint32_t replica,
                      uint8_t *buf, size_t cap, size_t *len);
    /* Deleting an absent object succeeds. */
    kfs_status (*del)(kfs_backend *b, uint64_t id);
    void       (*close)(kfs_backend *b);
} kfs_backend_ops;

struct kfs_backend {
    const kfs_backend_ops *ops;
    uint32_t               replicas; /* copies a get can be served from */
};

static inline kfs_status kfs_backend_put(kfs_backend *b, uint64_t id,
                                         const uint8_t *buf, size_t len)
{
    return b->ops->put(b, id, buf, len);
}

static inline kfs_status kfs_backend_get_replica(kfs_backend *b, uint64_t id,
                                                 uint32_t replica, uint8_t *buf,
                                                 size_t cap, size_t *len)
{
    return b->ops->get(b, id, replica, buf, cap, len);
}

/* First copy found, trying holders in preference order. KFS_E_NOT_FOUND
 * only if every holder answered that it has none; if any was unreachable
 * the answer is unknown, KFS_E_UNAVAILABLE. */
static inline kfs_status kfs_backend_get(kfs_backend *b, uint64_t id,
                                         uint8_t *buf, size_t cap, size_t *len)
{
    bool unreachable = false;

    for (uint32_t r = 0; r < b->replicas; r++) {
        kfs_status st = kfs_backend_get_replica(b, id, r, buf, cap, len);

        if (st == KFS_OK || st == KFS_E_PROTO)
            return st;
        unreachable = unreachable || st != KFS_E_NOT_FOUND;
    }
    return unreachable ? KFS_E_UNAVAILABLE : KFS_E_NOT_FOUND;
}

static inline kfs_status kfs_backend_del(kfs_backend *b, uint64_t id)
{
    return b->ops->del(b, id);
}

static inline void kfs_backend_close(kfs_backend *b)
{
    if (b != NULL)
        b->ops->close(b);
}

/* Objects live at <dir>/<last 2 hex digits>/<16 hex digits>; puts write a
 * temporary file, fsync it, rename it into place and fsync the directory. */
kfs_status kfs_backend_open_local(const char *dir, kfs_backend **out);

#endif /* KRYPTON_BACKEND_H */
