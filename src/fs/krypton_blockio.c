/*
 * krypton_blockio.c - Seal/store and fetch/verify/open of single blocks.
 */
#define _POSIX_C_SOURCE 200809L

#include "krypton/krypton_blockio.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static kfs_status local_seal(void *ctx, uint64_t block_id, uint64_t generation,
                             uint8_t *data, size_t len, kfs_envelope_hdr *env)
{
    return kfs_block_seal(ctx, block_id, generation, data, len, env);
}

static kfs_status local_open(void *ctx, uint64_t block_id, const kfs_envelope_hdr *env,
                             uint8_t *data, size_t len)
{
    return kfs_block_open(ctx, block_id, env, data, len);
}

static const kfs_cipher_ops LOCAL_CIPHER = { local_seal, local_open };

void kfs_cipher_local(kfs_cipher *c, const kfs_block_keys *keys)
{
    c->ops = &LOCAL_CIPHER;
    c->ctx = (void *)(uintptr_t)keys; /* only ever read through */
}

kfs_status kfs_blockio_init(kfs_blockio *io, const kfs_cipher *cipher,
                            kfs_backend *backend)
{
    io->cipher = *cipher;
    io->backend = backend;
    io->scratch_size = KFS_ENVELOPE_HDR_SIZE + KFS_BLOCK_SIZE_MAX;
    io->scratch = calloc(1, io->scratch_size);
    if (io->scratch == NULL)
        return KFS_E_NOMEM;
    mlock(io->scratch, io->scratch_size); /* best effort: holds plaintext */
    return KFS_OK;
}

void kfs_blockio_destroy(kfs_blockio *io)
{
    if (io->scratch != NULL) {
        kfs_wipe(io->scratch, io->scratch_size);
        munlock(io->scratch, io->scratch_size);
        free(io->scratch);
        io->scratch = NULL;
    }
}

kfs_status kfs_blockio_write(kfs_blockio *io, uint64_t block_id,
                             uint64_t generation, const uint8_t *plain, size_t len)
{
    uint8_t *body = io->scratch + KFS_ENVELOPE_HDR_SIZE;
    kfs_envelope_hdr env;
    kfs_status st;

    if (len > KFS_BLOCK_SIZE_MAX)
        return KFS_E_INVAL;
    memcpy(body, plain, len);
    st = io->cipher.ops->seal(io->cipher.ctx, block_id, generation, body, len, &env);
    if (st == KFS_OK) {
        kfs_envelope_hdr_encode(&env, io->scratch);
        st = kfs_backend_put(io->backend, block_id, io->scratch,
                             KFS_ENVELOPE_HDR_SIZE + len);
    }
    return st;
}

kfs_status kfs_blockio_read(kfs_blockio *io, uint64_t block_id,
                            uint8_t *plain, size_t len, uint64_t *generation)
{
    uint8_t *body = io->scratch + KFS_ENVELOPE_HDR_SIZE;
    kfs_envelope_hdr env;
    size_t got = 0;
    kfs_status st;

    if (len > KFS_BLOCK_SIZE_MAX)
        return KFS_E_INVAL;
    st = kfs_backend_get(io->backend, block_id, io->scratch, io->scratch_size, &got);
    if (st != KFS_OK)
        return st;
    if (got != KFS_ENVELOPE_HDR_SIZE + len)
        return KFS_E_PROTO;

    kfs_envelope_hdr_decode(io->scratch, &env);
    st = io->cipher.ops->open(io->cipher.ctx, block_id, &env, body, len);
    if (st != KFS_OK)
        return st;
    memcpy(plain, body, len);
    kfs_wipe(body, len);
    *generation = env.generation;
    return KFS_OK;
}
