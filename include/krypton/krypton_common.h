/*
 * krypton_common.h - Primitives shared by every KryptonFS component.
 *
 * Status codes, build-wide limits, and the big-endian load/store helpers
 * used by the wire formats in krypton_protocol.h.
 */
#ifndef KRYPTON_COMMON_H
#define KRYPTON_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KFS_VERSION_MAJOR 0
#define KFS_VERSION_MINOR 1
#define KFS_VERSION_PATCH 0

#define KFS_PATH_MAX 512
#define KFS_HOST_MAX 256

/* Plaintext block size bounds. A volume's block size is a power of two in
 * this range, fixed when the volume is created. */
#define KFS_BLOCK_SIZE_MIN     4096u
#define KFS_BLOCK_SIZE_MAX     65536u
#define KFS_BLOCK_SIZE_DEFAULT 4096u

#define KFS_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#if defined(__MINGW32__)
#define KFS_PRINTF_FMT(f, a) __attribute__((format(gnu_printf, f, a)))
#elif defined(__GNUC__)
#define KFS_PRINTF_FMT(f, a) __attribute__((format(printf, f, a)))
#else
#define KFS_PRINTF_FMT(f, a)
#endif

/*
 * Result of every fallible KryptonFS call. Values cross the wire in RPC
 * replies and IPC messages: append new codes, never renumber.
 */
typedef enum kfs_status {
    KFS_OK            = 0,
    KFS_E_INVAL       = 1,  /* bad argument */
    KFS_E_NOMEM       = 2,
    KFS_E_IO          = 3,
    KFS_E_PROTO       = 4,  /* malformed frame, datagram or IPC message */
    KFS_E_AUTH        = 5,  /* MAC, signature or handshake failure */
    KFS_E_CRYPTO      = 6,  /* cipher or key-derivation failure */
    KFS_E_MALWARE     = 7,  /* write rejected by the inline scanner */
    KFS_E_NOT_FOUND   = 8,
    KFS_E_TIMEOUT     = 9,
    KFS_E_UNAVAILABLE = 10, /* no healthy replica reachable */
    KFS_E_CONFIG      = 11
} kfs_status;

const char *kfs_strerror(kfs_status st);

static inline bool kfs_is_pow2(uint64_t v)
{
    return v != 0 && (v & (v - 1)) == 0;
}

static inline void kfs_store_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void kfs_store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void kfs_store_be64(uint8_t *p, uint64_t v)
{
    kfs_store_be32(p, (uint32_t)(v >> 32));
    kfs_store_be32(p + 4, (uint32_t)v);
}

static inline uint16_t kfs_load_be16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static inline uint32_t kfs_load_be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static inline uint64_t kfs_load_be64(const uint8_t *p)
{
    return (uint64_t)kfs_load_be32(p) << 32 | kfs_load_be32(p + 4);
}

#endif /* KRYPTON_COMMON_H */
