/*
 * krypton_scanner.h - Inline static inspection of written blocks.
 *
 * Two checks run on plaintext inside the scan workers, which hold no keys:
 *
 *   - ELF header: the block at file offset 0 begins with "\x7f" "ELF".
 *     Reported as signature id KFS_SIG_ELF_HEADER.
 *   - Byte signatures: every pattern loaded from the signature database is
 *     matched in a single pass with an Aho-Corasick automaton, so scan
 *     cost is linear in the block size regardless of how many signatures
 *     are loaded.
 *
 * Signature database format, one signature per line:
 *
 *   # comment
 *   <id> <hex bytes> [name ...]
 *
 * id is 1..2^32-1 (0 is reserved for the ELF check); the pattern is
 * KFS_SIG_MIN_LEN..KFS_SIG_MAX_LEN bytes of contiguous hex.
 *
 * Blocks are scanned independently, so a pattern straddling a block
 * boundary is not detected.
 */
#ifndef KRYPTON_SCANNER_H
#define KRYPTON_SCANNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "krypton_common.h"

#define KFS_SIG_ELF_HEADER 0u
#define KFS_SIG_MIN_LEN    4u   /* shorter patterns false-positive on ordinary data */
#define KFS_SIG_MAX_LEN    256u
#define KFS_SIG_NAME_MAX   48u

/* Automaton size cap: each state costs 1 KiB of transition table. */
#define KFS_SCANNER_MAX_STATES 65536u

typedef struct kfs_scanner kfs_scanner;

typedef struct kfs_scan_hit {
    uint32_t sig_id;
    uint32_t offset; /* byte offset of the match within the scanned block */
} kfs_scan_hit;

kfs_scanner *kfs_scanner_new(void);
void kfs_scanner_free(kfs_scanner *sc);

/* Adds one signature. KFS_E_INVAL for a bad id or length, or once the
 * scanner is compiled; KFS_E_NOMEM past KFS_SCANNER_MAX_STATES. */
kfs_status kfs_scanner_add(kfs_scanner *sc, uint32_t id, const char *name,
                           const uint8_t *pattern, size_t len);

/* Adds every signature in a database text; errors name the line. */
kfs_status kfs_scanner_parse(kfs_scanner *sc, const char *text, size_t len,
                             char *err, size_t errlen);
kfs_status kfs_scanner_load(kfs_scanner *sc, const char *path,
                            char *err, size_t errlen);

/* Builds failure links. Call once after the last add; the scanner is then
 * read-only and safe to share between threads. */
kfs_status kfs_scanner_compile(kfs_scanner *sc);

/*
 * Scans one plaintext block written at file_offset. Returns KFS_OK when
 * clean, or KFS_E_MALWARE with *hit describing the earliest match.
 */
kfs_status kfs_scanner_scan(const kfs_scanner *sc, const uint8_t *data,
                            size_t len, uint64_t file_offset, bool block_elf,
                            kfs_scan_hit *hit);

/* Name of a signature for audit logs; never NULL. */
const char *kfs_scanner_sig_name(const kfs_scanner *sc, uint32_t sig_id);

#endif /* KRYPTON_SCANNER_H */
