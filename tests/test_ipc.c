/*
 * test_ipc.c - Shared-memory arena layout and IPC message bounds checks.
 */
#include "krypton/krypton_ipc.h"

#include <stdlib.h>

#include "kfs_test.h"

static void test_layout_4k_pages(void)
{
    kfs_shm_layout l;

    CHECK_EQ(kfs_shm_layout_init(&l, 64, 4096, 4096), KFS_OK);
    CHECK_EQ(l.slot_count, 64);
    CHECK_EQ(l.block_size, 4096);
    CHECK_EQ(l.data_offset, 4096); /* 64 * 56 = 3584 bytes of meta, rounded up */
    CHECK_EQ(l.total_size, 4096 + 64 * 4096);
}

static void test_layout_large_pages(void)
{
    kfs_shm_layout l;

    CHECK_EQ(kfs_shm_layout_init(&l, 1024, 65536, 16384), KFS_OK);
    CHECK_EQ(l.data_offset % 16384, 0);
    CHECK(l.data_offset >= 1024 * sizeof(kfs_envelope_hdr));
    CHECK_EQ(l.total_size, l.data_offset + 1024u * 65536u);
}

static void test_layout_rejects_bad_arguments(void)
{
    kfs_shm_layout l;

    CHECK_EQ(kfs_shm_layout_init(&l, 0, 4096, 4096), KFS_E_INVAL);
    CHECK_EQ(kfs_shm_layout_init(&l, KFS_IPC_MAX_SLOTS + 1, 4096, 4096), KFS_E_INVAL);
    CHECK_EQ(kfs_shm_layout_init(&l, 8, 2048, 4096), KFS_E_INVAL);
    CHECK_EQ(kfs_shm_layout_init(&l, 8, 131072, 4096), KFS_E_INVAL);
    CHECK_EQ(kfs_shm_layout_init(&l, 8, 12288, 4096), KFS_E_INVAL);
    CHECK_EQ(kfs_shm_layout_init(&l, 8, 4096, 0), KFS_E_INVAL);
    CHECK_EQ(kfs_shm_layout_init(&l, 8, 4096, 3000), KFS_E_INVAL);
}

static void test_slot_accessors(void)
{
    kfs_shm_layout l;
    uint8_t *base;

    CHECK_EQ(kfs_shm_layout_init(&l, 2, 4096, 4096), KFS_OK);
    base = calloc(1, l.total_size);
    CHECK(base != NULL);
    if (base == NULL)
        return;

    CHECK((uint8_t *)kfs_shm_slot_meta(base, 1) == base + sizeof(kfs_envelope_hdr));
    CHECK(kfs_shm_slot_data(&l, base, 0) == base + l.data_offset);
    CHECK(kfs_shm_slot_data(&l, base, 1) + l.block_size == base + l.total_size);
    free(base);
}

static void test_msg_check(void)
{
    kfs_shm_layout l;
    kfs_ipc_msg m = { .mtype = KFS_IPC_MTYPE_CRYPTO, .op = KFS_IPC_SEAL, .slot = 7, .len = 4096 };

    CHECK_EQ(kfs_shm_layout_init(&l, 8, 4096, 4096), KFS_OK);
    CHECK_EQ(kfs_ipc_msg_check(&l, &m), KFS_OK);

    m.slot = 8;
    CHECK_EQ(kfs_ipc_msg_check(&l, &m), KFS_E_PROTO);

    m.slot = 0;
    m.len = 4097;
    CHECK_EQ(kfs_ipc_msg_check(&l, &m), KFS_E_PROTO);

    m.len = 0;
    m.op = 99;
    CHECK_EQ(kfs_ipc_msg_check(&l, &m), KFS_E_PROTO);

    /* SHUTDOWN carries no slot, so garbage there is ignored. */
    m.op = KFS_IPC_SHUTDOWN;
    m.slot = UINT32_MAX;
    CHECK_EQ(kfs_ipc_msg_check(&l, &m), KFS_OK);

    CHECK_EQ(kfs_ipc_reply_mtype(0), 1);
    CHECK(kfs_ipc_reply_mtype(0) != 0); /* msgsnd rejects mtype <= 0 */
}

int main(void)
{
    RUN(test_layout_4k_pages);
    RUN(test_layout_large_pages);
    RUN(test_layout_rejects_bad_arguments);
    RUN(test_slot_accessors);
    RUN(test_msg_check);
    TEST_EXIT();
}
