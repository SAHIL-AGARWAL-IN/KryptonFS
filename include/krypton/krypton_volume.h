/*
 * krypton_volume.h - Volume header and logical block addressing.
 *
 * The volume header is the only unencrypted block. It records the
 * parameters fixed at creation and the volume key wrapped under the
 * passphrase:
 *
 *   off  size  field
 *     0     4  magic           'K' 'F' 'V' v1
 *     4     4  block_size
 *     8     4  kdf_iterations  PBKDF2-HMAC-SHA256 rounds
 *    12     4  reserved        zero
 *    16    16  salt            random per volume
 *    32    16  volume_id       random per volume
 *    48    56  wrap envelope   (generation, iv, tag) of the wrapped key
 *   104    32  wrapped volume key
 *
 *   kek_keys = HKDF-SHA256(PBKDF2(passphrase, salt, iterations),
 *                          salt = header[0..48), info = "kryptonfs v1 kek")
 *
 * Binding header[0..48) into the HKDF means editing any parameter (block
 * size, iterations, salt) makes the wrapped key fail to open, just like a
 * wrong passphrase.
 *
 * Logical block ids
 * -----------------
 *   bits 63..24  inode number
 *   bits 23..1   block index within the file
 *   bit  0       storage copy, = generation & 1
 *
 * Each block has two storage copies. A rewrite goes to the copy the
 * committed metadata does not reference, so a crash mid-write never
 * destroys the last committed version. Inode 0 is reserved: index 0 is
 * this header, index 1 the metadata root, indexes 2.. metadata chunks.
 */
#ifndef KRYPTON_VOLUME_H
#define KRYPTON_VOLUME_H

#include <stddef.h>
#include <stdint.h>

#include "krypton_common.h"
#include "krypton_crypto.h"
#include "krypton_protocol.h"

#define KFS_VOLUME_MAGIC      0x4B465601u /* 'K' 'F' 'V' v1 */
#define KFS_VOLUME_HDR_SIZE   136u
#define KFS_VOLUME_PARAMS_SIZE 48u
#define KFS_VOLUME_ID_SIZE    16u

#define KFS_BID_INDEX_BITS    23
#define KFS_MAX_FILE_BLOCKS   (1u << KFS_BID_INDEX_BITS)
#define KFS_MAX_INO           ((UINT64_C(1) << 40) - 1)

#define KFS_META_INO          0u
#define KFS_BID_VOLUME_HEADER 0u /* kfs_bid(0, 0, 0) */
#define KFS_META_ROOT_INDEX   1u
#define KFS_META_CHUNK_INDEX  2u

static inline uint64_t kfs_bid(uint64_t ino, uint32_t index, uint64_t generation)
{
    return ino << 24 | (uint64_t)index << 1 | (generation & 1);
}

typedef struct kfs_volume_header {
    uint32_t block_size;
    uint32_t kdf_iterations;
    uint8_t  salt[KFS_SALT_SIZE];
    uint8_t  volume_id[KFS_VOLUME_ID_SIZE];
} kfs_volume_header;

/* Generates salt, volume id and a random volume key; writes the encoded
 * header to out and the plaintext volume key to volume_key. */
kfs_status kfs_volume_create(const char *pass, size_t pass_len,
                             uint32_t block_size, uint32_t iterations,
                             uint8_t out[KFS_VOLUME_HDR_SIZE],
                             uint8_t volume_key[KFS_KEY_SIZE]);

/* KFS_E_PROTO for a malformed header, KFS_E_AUTH for a wrong passphrase
 * or edited parameters. */
kfs_status kfs_volume_unlock(const uint8_t in[KFS_VOLUME_HDR_SIZE],
                             const char *pass, size_t pass_len,
                             kfs_volume_header *hdr,
                             uint8_t volume_key[KFS_KEY_SIZE]);

#endif /* KRYPTON_VOLUME_H */
