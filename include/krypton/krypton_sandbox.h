/*
 * krypton_sandbox.h - Jailed worker pools for scanning and cryptography
 * (Linux only).
 *
 * Lifecycle, in this order:
 *
 *   kfs_sandbox_create()        queues + shared arena, forks the scan pool
 *   (derive volume keys)
 *   kfs_sandbox_start_crypto()  forks the crypto pool with the keys, starts
 *                               the supervisor; the caller then wipes its
 *                               own copy of the keys
 *   ... kfs_sandbox_acquire / scan / seal / open / release ...
 *   kfs_sandbox_destroy()
 *
 * Scan workers are forked before any key exists in the process, so they
 * never inherit key material. Each worker, after fork():
 *
 *   - closes every inherited file descriptor above stderr
 *   - chroot()s into an empty directory and chdir("/")
 *   - drops supplementary groups, then gid, then uid (setres*id)
 *   - verifies it cannot regain uid 0
 *   - sets PR_SET_NO_NEW_PRIVS, disables core dumps / ptrace attach,
 *     and asks to be killed if the parent dies
 *
 * Failure policy is fail-closed: if any worker exits unexpectedly, every
 * in-flight request and every later call returns KFS_E_UNAVAILABLE. A
 * crashed parser may be an exploited parser.
 *
 * The supervisor reaps children with waitpid(-1), so the owning process
 * must not fork other children it expects to wait for itself.
 */
#ifndef KRYPTON_SANDBOX_H
#define KRYPTON_SANDBOX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "krypton_common.h"
#include "krypton_crypto.h"
#include "krypton_protocol.h"
#include "krypton_scanner.h"

typedef struct kfs_sandbox kfs_sandbox;

typedef struct kfs_sandbox_opts {
    uint32_t           scan_workers;
    uint32_t           crypto_workers;
    uint32_t           slots;
    uint32_t           block_size;
    const kfs_scanner *scanner;          /* compiled, or NULL to skip scanning */
    bool               block_elf;
    bool               drop_privileges;  /* false only for unprivileged tests */
    const char        *chroot_dir;       /* required when drop_privileges */
    uint32_t           uid;
    uint32_t           gid;
} kfs_sandbox_opts;

typedef enum kfs_worker_kind {
    KFS_WORKER_SCAN,
    KFS_WORKER_CRYPTO
} kfs_worker_kind;

typedef struct kfs_worker_info {
    pid_t           pid;
    kfs_worker_kind kind;
    bool            alive;
} kfs_worker_info;

kfs_status kfs_sandbox_create(const kfs_sandbox_opts *opts, kfs_sandbox **out);
kfs_status kfs_sandbox_start_crypto(kfs_sandbox *sb, const kfs_block_keys *keys);
void kfs_sandbox_destroy(kfs_sandbox *sb);

/* Blocks until a slot is free. KFS_E_UNAVAILABLE once the sandbox failed. */
kfs_status kfs_sandbox_acquire(kfs_sandbox *sb, uint32_t *slot);
void kfs_sandbox_release(kfs_sandbox *sb, uint32_t slot);

uint8_t *kfs_sandbox_data(kfs_sandbox *sb, uint32_t slot);
kfs_envelope_hdr *kfs_sandbox_meta(kfs_sandbox *sb, uint32_t slot);

/* KFS_OK when clean; KFS_E_MALWARE with *hit filled on a match. */
kfs_status kfs_sandbox_scan(kfs_sandbox *sb, uint32_t slot, uint32_t len,
                            bool file_start, kfs_scan_hit *hit);

/* Encrypts the slot in place; generation is stored in the slot's meta. */
kfs_status kfs_sandbox_seal(kfs_sandbox *sb, uint32_t slot, uint64_t block_id,
                            uint64_t generation, uint32_t len);

/* Verifies the slot's meta tag, then decrypts in place. */
kfs_status kfs_sandbox_open(kfs_sandbox *sb, uint32_t slot, uint64_t block_id,
                            uint32_t len);

/* Snapshot of the worker processes, for telemetry. Returns the count
 * written (at most cap). */
size_t kfs_sandbox_workers(kfs_sandbox *sb, kfs_worker_info *out, size_t cap);

bool kfs_sandbox_failed(const kfs_sandbox *sb);

#endif /* KRYPTON_SANDBOX_H */
