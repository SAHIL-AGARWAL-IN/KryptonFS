/*
 * krypton_ipc.c - Shared-memory arena layout and IPC message validation.
 * Queue and mapping setup (msgget, mmap, fork) belongs to the sandbox
 * layer; everything here is pure arithmetic shared by both sides.
 */
#include "krypton/krypton_ipc.h"

kfs_status kfs_shm_layout_init(kfs_shm_layout *layout, uint32_t slot_count,
                               uint32_t block_size, size_t page_size)
{
    size_t meta_size;

    if (slot_count == 0 || slot_count > KFS_IPC_MAX_SLOTS ||
        block_size < KFS_BLOCK_SIZE_MIN || block_size > KFS_BLOCK_SIZE_MAX ||
        !kfs_is_pow2(block_size) || !kfs_is_pow2(page_size))
        return KFS_E_INVAL;

    meta_size = (size_t)slot_count * sizeof(kfs_envelope_hdr);
    layout->slot_count = slot_count;
    layout->block_size = block_size;
    layout->data_offset = (meta_size + page_size - 1) & ~(page_size - 1);
    layout->total_size = layout->data_offset + (size_t)slot_count * block_size;
    return KFS_OK;
}

kfs_status kfs_ipc_msg_check(const kfs_shm_layout *layout,
                             const kfs_ipc_msg *msg)
{
    switch (msg->op) {
    case KFS_IPC_SHUTDOWN:
        return KFS_OK;
    case KFS_IPC_SCAN:
    case KFS_IPC_SEAL:
    case KFS_IPC_OPEN:
        if (msg->slot >= layout->slot_count || msg->len > layout->block_size)
            return KFS_E_PROTO;
        return KFS_OK;
    default:
        return KFS_E_PROTO;
    }
}
