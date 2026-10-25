/*
 * krypton_ipc.h - FUSE daemon <-> sandbox worker IPC structures.
 *
 * Sandbox workers are fork()ed, chroot()ed, privilege-dropped children in
 * two pools:
 *
 *   scan workers    parse untrusted file content; never hold keys
 *   crypto workers  hold volume keys; never parse
 *
 * so a parser exploit cannot reach key material. Both pools exchange work
 * with the FUSE daemon through System V message queues and one shared
 * memory arena.
 *
 * Block bytes never travel through the queues: kernel.msgmnb caps a queue
 * at 16 KiB by default, about three 4 KiB blocks in flight. Instead:
 *
 *   - The arena is mmap(MAP_SHARED | MAP_ANONYMOUS)'d before fork(), so
 *     every worker inherits it and needs no path inside its chroot.
 *   - It holds ipc_slots fixed-size slots. Only the FUSE daemon allocates
 *     slots; workers operate on the slot index a message hands them.
 *   - Fixed-size descriptors (kfs_ipc_msg) travel on one request queue,
 *     where mtype selects the pool, and one reply queue, where mtype is
 *     slot + 1 so each waiting FUSE thread msgrcv()s only its own reply.
 *
 * A slot's owner fills it, msgsnd()s, and does not touch it again until
 * the matching reply arrives. SEAL and OPEN run in place; SEAL reads the
 * generation from the slot's envelope header and writes iv and tag back.
 *
 * Arena layout (offsets from the mapping base):
 *
 *   +--------------------------------+---------+
 *   | kfs_envelope_hdr x slot_count  | padding |  data_offset is page aligned
 *   +--------------------------------+---------+
 *   | slot 0 data | slot 1 data | ... | slot N-1 data |   block_size each
 *   +-------------+-------------+-----+---------------+
 *
 * The arena holds no header. Each process keeps its kfs_shm_layout in
 * private memory, so a compromised worker can scribble on shared bytes
 * but cannot move the bounds the other side checks indices against.
 */
#ifndef KRYPTON_IPC_H
#define KRYPTON_IPC_H

#include <stddef.h>
#include <stdint.h>

#include "krypton_common.h"
#include "krypton_protocol.h"

#define KFS_IPC_MAX_SLOTS 1024u

/* Request queue mtypes: each pool msgrcv()s only its own type. */
#define KFS_IPC_MTYPE_SCAN   1L
#define KFS_IPC_MTYPE_CRYPTO 2L

typedef enum kfs_ipc_op {
    KFS_IPC_SCAN     = 1, /* scan pool: inspect plaintext, report a verdict */
    KFS_IPC_SEAL     = 2, /* crypto pool: random iv, encrypt + tag in place */
    KFS_IPC_OPEN     = 3, /* crypto pool: verify tag, then decrypt in place */
    KFS_IPC_SHUTDOWN = 4  /* either pool: exit without replying */
} kfs_ipc_op;

typedef struct kfs_ipc_msg {
    long     mtype;       /* msgsnd(2) requires this first */
    uint32_t op;          /* kfs_ipc_op */
    uint32_t slot;
    uint64_t req_id;      /* echoed in the reply; the FUSE side drops mismatches */
    uint64_t block_id;    /* bound into the envelope tag */
    uint32_t len;         /* valid bytes in the slot's data */
    uint32_t flags;       /* KFS_IPC_F_* */
    uint32_t status;      /* reply: kfs_status */
    uint32_t scan_sig;    /* SCAN reply with KFS_E_MALWARE: matched signature id */
    uint32_t scan_offset; /* ... and the match's byte offset within the block */
} kfs_ipc_msg;

/* SCAN: the slot holds the block at file offset 0 (enables the ELF check). */
#define KFS_IPC_F_FILE_START 0x1u

/* The size argument to msgsnd/msgrcv: the message body after mtype. */
#define KFS_IPC_MSG_BODY_SIZE (sizeof(kfs_ipc_msg) - sizeof(long))

typedef struct kfs_shm_layout {
    uint32_t slot_count;
    uint32_t block_size;
    size_t   data_offset; /* slot i's data starts at data_offset + i * block_size */
    size_t   total_size;  /* bytes to mmap */
} kfs_shm_layout;

/* page_size comes from sysconf(_SC_PAGESIZE). KFS_E_INVAL if any argument
 * is out of range or not a power of two. */
kfs_status kfs_shm_layout_init(kfs_shm_layout *layout, uint32_t slot_count,
                               uint32_t block_size, size_t page_size);

/* Rejects unknown ops, slot >= slot_count and len > block_size with
 * KFS_E_PROTO. Call on every received message before using its slot. */
kfs_status kfs_ipc_msg_check(const kfs_shm_layout *layout,
                             const kfs_ipc_msg *msg);

static inline long kfs_ipc_reply_mtype(uint32_t slot)
{
    return (long)slot + 1;
}

/* slot must already be checked against layout->slot_count. */
static inline kfs_envelope_hdr *kfs_shm_slot_meta(void *base, uint32_t slot)
{
    return (kfs_envelope_hdr *)base + slot;
}

static inline uint8_t *kfs_shm_slot_data(const kfs_shm_layout *layout,
                                         void *base, uint32_t slot)
{
    return (uint8_t *)base + layout->data_offset +
           (size_t)slot * layout->block_size;
}

#endif /* KRYPTON_IPC_H */
