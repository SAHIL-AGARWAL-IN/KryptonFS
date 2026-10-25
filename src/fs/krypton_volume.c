/*
 * krypton_volume.c - Volume header creation and passphrase unlock.
 */
#include "krypton/krypton_volume.h"

#include <string.h>

#define OFF_MAGIC      0u
#define OFF_BLOCK_SIZE 4u
#define OFF_ITERATIONS 8u
#define OFF_RESERVED   12u
#define OFF_SALT       16u
#define OFF_VOLUME_ID  32u
#define OFF_WRAP_ENV   48u
#define OFF_WRAPPED    104u

_Static_assert(OFF_WRAP_ENV == KFS_VOLUME_PARAMS_SIZE, "params precede the wrap");
_Static_assert(OFF_WRAPPED == OFF_WRAP_ENV + KFS_ENVELOPE_HDR_SIZE, "header layout");
_Static_assert(OFF_WRAPPED + KFS_KEY_SIZE == KFS_VOLUME_HDR_SIZE, "header layout");

static const char KEK_LABEL[] = "kryptonfs v1 kek";

static kfs_status kek_keys(const char *pass, size_t pass_len,
                           const uint8_t params[KFS_VOLUME_PARAMS_SIZE],
                           uint32_t iterations, kfs_block_keys *keys)
{
    uint8_t kek[KFS_KEY_SIZE], okm[2 * KFS_KEY_SIZE];
    kfs_status st;

    st = kfs_pbkdf2_sha256(pass, pass_len, params + OFF_SALT, KFS_SALT_SIZE,
                           iterations, kek, sizeof(kek));
    if (st == KFS_OK)
        st = kfs_hkdf_sha256(kek, sizeof(kek), params, KFS_VOLUME_PARAMS_SIZE,
                             (const uint8_t *)KEK_LABEL, sizeof(KEK_LABEL) - 1,
                             okm, sizeof(okm));
    if (st == KFS_OK) {
        memcpy(keys->data_key, okm, KFS_KEY_SIZE);
        memcpy(keys->mac_key, okm + KFS_KEY_SIZE, KFS_KEY_SIZE);
    }
    kfs_wipe(kek, sizeof(kek));
    kfs_wipe(okm, sizeof(okm));
    return st;
}

static bool block_size_ok(uint32_t bs)
{
    return bs >= KFS_BLOCK_SIZE_MIN && bs <= KFS_BLOCK_SIZE_MAX && kfs_is_pow2(bs);
}

kfs_status kfs_volume_create(const char *pass, size_t pass_len,
                             uint32_t block_size, uint32_t iterations,
                             uint8_t out[KFS_VOLUME_HDR_SIZE],
                             uint8_t volume_key[KFS_KEY_SIZE])
{
    kfs_block_keys kk;
    kfs_envelope_hdr env;
    kfs_status st;

    if (!block_size_ok(block_size) || iterations == 0)
        return KFS_E_INVAL;

    memset(out, 0, KFS_VOLUME_HDR_SIZE);
    kfs_store_be32(out + OFF_MAGIC, KFS_VOLUME_MAGIC);
    kfs_store_be32(out + OFF_BLOCK_SIZE, block_size);
    kfs_store_be32(out + OFF_ITERATIONS, iterations);
    st = kfs_random_bytes(out + OFF_SALT, KFS_SALT_SIZE);
    if (st == KFS_OK)
        st = kfs_random_bytes(out + OFF_VOLUME_ID, KFS_VOLUME_ID_SIZE);
    if (st == KFS_OK)
        st = kfs_random_bytes(volume_key, KFS_KEY_SIZE);
    if (st == KFS_OK)
        st = kek_keys(pass, pass_len, out, iterations, &kk);
    if (st == KFS_OK) {
        memcpy(out + OFF_WRAPPED, volume_key, KFS_KEY_SIZE);
        st = kfs_block_seal(&kk, KFS_BID_VOLUME_HEADER, 0,
                            out + OFF_WRAPPED, KFS_KEY_SIZE, &env);
        if (st == KFS_OK)
            kfs_envelope_hdr_encode(&env, out + OFF_WRAP_ENV);
    }
    kfs_wipe(&kk, sizeof(kk));
    if (st != KFS_OK) {
        kfs_wipe(volume_key, KFS_KEY_SIZE);
        memset(out, 0, KFS_VOLUME_HDR_SIZE);
    }
    return st;
}

uint32_t kfs_volume_block_size(const uint8_t in[KFS_VOLUME_HDR_SIZE])
{
    uint32_t bs = kfs_load_be32(in + OFF_BLOCK_SIZE);

    return kfs_load_be32(in + OFF_MAGIC) == KFS_VOLUME_MAGIC && block_size_ok(bs) ? bs : 0;
}

kfs_status kfs_volume_unlock(const uint8_t in[KFS_VOLUME_HDR_SIZE],
                             const char *pass, size_t pass_len,
                             kfs_volume_header *hdr,
                             uint8_t volume_key[KFS_KEY_SIZE])
{
    uint32_t block_size = kfs_load_be32(in + OFF_BLOCK_SIZE);
    uint32_t iterations = kfs_load_be32(in + OFF_ITERATIONS);
    kfs_block_keys kk;
    kfs_envelope_hdr env;
    kfs_status st;

    if (kfs_load_be32(in + OFF_MAGIC) != KFS_VOLUME_MAGIC ||
        !block_size_ok(block_size) || iterations == 0 ||
        kfs_load_be32(in + OFF_RESERVED) != 0)
        return KFS_E_PROTO;

    st = kek_keys(pass, pass_len, in, iterations, &kk);
    if (st == KFS_OK) {
        kfs_envelope_hdr_decode(in + OFF_WRAP_ENV, &env);
        memcpy(volume_key, in + OFF_WRAPPED, KFS_KEY_SIZE);
        st = kfs_block_open(&kk, KFS_BID_VOLUME_HEADER, &env, volume_key, KFS_KEY_SIZE);
    }
    kfs_wipe(&kk, sizeof(kk));
    if (st != KFS_OK) {
        kfs_wipe(volume_key, KFS_KEY_SIZE);
        return st;
    }

    hdr->block_size = block_size;
    hdr->kdf_iterations = iterations;
    memcpy(hdr->salt, in + OFF_SALT, KFS_SALT_SIZE);
    memcpy(hdr->volume_id, in + OFF_VOLUME_ID, KFS_VOLUME_ID_SIZE);
    return KFS_OK;
}
