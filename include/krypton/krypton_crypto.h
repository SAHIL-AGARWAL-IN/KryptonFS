/*
 * krypton_crypto.h - Cryptographic primitives for KryptonFS (OpenSSL 3).
 *
 * Key hierarchy (see docs/ARCHITECTURE.md):
 *
 *   passphrase + salt --PBKDF2-HMAC-SHA256--> key-encryption key
 *   volume key (random, wrapped in the volume header)
 *       --HKDF-SHA256--> data key (AES-256-CTR) + MAC key (HMAC-SHA256)
 *
 * Blocks are encrypt-then-MAC: kfs_block_open() verifies the tag before
 * it decrypts, so tampered or swapped ciphertext never yields plaintext.
 */
#ifndef KRYPTON_CRYPTO_H
#define KRYPTON_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "krypton_common.h"
#include "krypton_protocol.h"

#define KFS_KEY_SIZE  32u
#define KFS_SALT_SIZE 16u

/* Floor for new volumes (OWASP 2023 guidance for PBKDF2-HMAC-SHA256).
 * kfs_pbkdf2_sha256() itself accepts any count so test vectors work. */
#define KFS_KDF_MIN_ITERATIONS 600000u

typedef struct kfs_block_keys {
    uint8_t data_key[KFS_KEY_SIZE];
    uint8_t mac_key[KFS_KEY_SIZE];
} kfs_block_keys;

/* One input segment of a multi-part MAC. */
typedef struct kfs_buf {
    const void *data;
    size_t      len;
} kfs_buf;

kfs_status kfs_random_bytes(uint8_t *buf, size_t len);

/* Zeroes memory in a way the compiler cannot optimize out. */
void kfs_wipe(void *buf, size_t len);

/* Constant-time equality, for comparing MACs. */
bool kfs_ct_equal(const void *a, const void *b, size_t len);

kfs_status kfs_pbkdf2_sha256(const char *pass, size_t pass_len,
                             const uint8_t *salt, size_t salt_len,
                             uint32_t iterations,
                             uint8_t *out, size_t out_len);

kfs_status kfs_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                           const uint8_t *salt, size_t salt_len,
                           const uint8_t *info, size_t info_len,
                           uint8_t *out, size_t out_len);

/* Splits the volume key into independent data and MAC keys. */
kfs_status kfs_block_keys_derive(const uint8_t volume_key[KFS_KEY_SIZE],
                                 kfs_block_keys *keys);

/* HMAC-SHA256 over the concatenation of parts. */
kfs_status kfs_hmac_sha256(const uint8_t *key, size_t key_len,
                           const kfs_buf *parts, size_t nparts,
                           uint8_t out[KFS_HMAC_SIZE]);

/* Encrypts data in place under a fresh random IV and fills env with
 * generation, IV and tag. len is at most KFS_BLOCK_SIZE_MAX. */
kfs_status kfs_block_seal(const kfs_block_keys *keys, uint64_t block_id,
                          uint64_t generation, uint8_t *data, size_t len,
                          kfs_envelope_hdr *env);

/* Verifies env's tag for (block_id, data), then decrypts in place.
 * KFS_E_AUTH on mismatch, with data left untouched. */
kfs_status kfs_block_open(const kfs_block_keys *keys, uint64_t block_id,
                          const kfs_envelope_hdr *env,
                          uint8_t *data, size_t len);

/* Frame MAC as defined in krypton_protocol.h; payload holds
 * hdr->payload_len bytes. */
kfs_status kfs_frame_mac(const uint8_t session_key[KFS_KEY_SIZE],
                         const kfs_frame_hdr *hdr, uint64_t seq,
                         const uint8_t *payload, uint8_t out[KFS_HMAC_SIZE]);

/* KFS_E_AUTH unless hdr->hmac matches. */
kfs_status kfs_frame_verify(const uint8_t session_key[KFS_KEY_SIZE],
                            const kfs_frame_hdr *hdr, uint64_t seq,
                            const uint8_t *payload);

/* Write / check the hmac field of an encoded heartbeat datagram. */
kfs_status kfs_heartbeat_sign(const uint8_t cluster_key[KFS_KEY_SIZE],
                              uint8_t wire[KFS_HB_SIZE]);
kfs_status kfs_heartbeat_verify(const uint8_t cluster_key[KFS_KEY_SIZE],
                                const uint8_t wire[KFS_HB_SIZE]);

#endif /* KRYPTON_CRYPTO_H */
