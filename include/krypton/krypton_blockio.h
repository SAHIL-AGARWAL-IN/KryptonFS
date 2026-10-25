/*
 * krypton_blockio.h - Encrypted block I/O over a backend.
 *
 * Writes seal a plaintext block and store "envelope header || ciphertext".
 * Reads fetch, verify the tag, decrypt, and return the authenticated
 * generation, which callers compare against the generation their metadata
 * expects: a storage node serving an older, validly tagged copy is a
 * rollback, reported as KFS_E_AUTH.
 *
 * The cipher is pluggable: the FUSE daemon routes it to the sandboxed
 * crypto workers; tests and tools use kfs_cipher_local().
 *
 * A kfs_blockio owns one scratch buffer and is not thread-safe.
 */
#ifndef KRYPTON_BLOCKIO_H
#define KRYPTON_BLOCKIO_H

#include <stddef.h>
#include <stdint.h>

#include "krypton_backend.h"
#include "krypton_common.h"
#include "krypton_crypto.h"
#include "krypton_protocol.h"

typedef struct kfs_cipher_ops {
    kfs_status (*seal)(void *ctx, uint64_t block_id, uint64_t generation,
                       uint8_t *data, size_t len, kfs_envelope_hdr *env);
    kfs_status (*open)(void *ctx, uint64_t block_id, const kfs_envelope_hdr *env,
                       uint8_t *data, size_t len);
} kfs_cipher_ops;

typedef struct kfs_cipher {
    const kfs_cipher_ops *ops;
    void                 *ctx;
} kfs_cipher;

/* In-process cipher; keys must outlive the cipher. */
void kfs_cipher_local(kfs_cipher *c, const kfs_block_keys *keys);

typedef struct kfs_blockio {
    kfs_cipher   cipher;
    kfs_backend *backend;
    uint8_t     *scratch; /* envelope header + one block, mlocked */
    size_t       scratch_size;
} kfs_blockio;

kfs_status kfs_blockio_init(kfs_blockio *io, const kfs_cipher *cipher,
                            kfs_backend *backend);
void kfs_blockio_destroy(kfs_blockio *io);

/* len is at most KFS_BLOCK_SIZE_MAX. */
kfs_status kfs_blockio_write(kfs_blockio *io, uint64_t block_id,
                             uint64_t generation, const uint8_t *plain, size_t len);

/* Reads exactly len plaintext bytes. KFS_E_NOT_FOUND if absent,
 * KFS_E_PROTO for a wrong-sized object, KFS_E_AUTH if tampered. */
kfs_status kfs_blockio_read(kfs_blockio *io, uint64_t block_id,
                            uint8_t *plain, size_t len, uint64_t *generation);

#endif /* KRYPTON_BLOCKIO_H */
