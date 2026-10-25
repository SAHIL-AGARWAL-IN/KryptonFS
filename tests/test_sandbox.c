/*
 * test_sandbox.c - Worker pools end to end: seal/open through the jail,
 * scanning, privilege drop, concurrency and fail-closed behaviour.
 *
 * Run as root to exercise chroot + setuid; unprivileged runs test the
 * IPC paths only.
 */
#define _GNU_SOURCE /* mkdtemp, readlink */

#include "krypton/krypton_sandbox.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "kfs_test.h"

#define BLOCK 4096u

static kfs_sandbox *sb;
static kfs_scanner *scanner;
static kfs_block_keys keys;
static char jail[] = "/tmp/kfs-jail-XXXXXX";
static bool privileged;

static void fill(uint8_t *p, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        p[i] = (uint8_t)(seed + i * 31);
}

static void test_seal_open(void)
{
    uint8_t plain[BLOCK], cipher[BLOCK];
    kfs_envelope_hdr env;
    uint32_t slot;

    CHECK_EQ(kfs_sandbox_acquire(sb, &slot), KFS_OK);
    fill(plain, sizeof(plain), 7);
    memcpy(kfs_sandbox_data(sb, slot), plain, BLOCK);

    CHECK_EQ(kfs_sandbox_seal(sb, slot, 1234, 9, BLOCK), KFS_OK);
    env = *kfs_sandbox_meta(sb, slot);
    CHECK_EQ(env.generation, 9);
    memcpy(cipher, kfs_sandbox_data(sb, slot), BLOCK);
    CHECK(memcmp(cipher, plain, BLOCK) != 0);

    /* The worker's envelope opens with the same keys outside the jail ... */
    {
        uint8_t copy[BLOCK];

        memcpy(copy, cipher, BLOCK);
        CHECK_EQ(kfs_block_open(&keys, 1234, &env, copy, BLOCK), KFS_OK);
        CHECK(memcmp(copy, plain, BLOCK) == 0);
    }
    /* ... and the worker opens it back in place. */
    CHECK_EQ(kfs_sandbox_open(sb, slot, 1234, BLOCK), KFS_OK);
    CHECK(memcmp(kfs_sandbox_data(sb, slot), plain, BLOCK) == 0);
    kfs_sandbox_release(sb, slot);
}

static void test_open_rejects_tampering(void)
{
    uint32_t slot;

    CHECK_EQ(kfs_sandbox_acquire(sb, &slot), KFS_OK);
    fill(kfs_sandbox_data(sb, slot), BLOCK, 1);
    CHECK_EQ(kfs_sandbox_seal(sb, slot, 5, 1, BLOCK), KFS_OK);
    kfs_sandbox_data(sb, slot)[42] ^= 1;
    CHECK_EQ(kfs_sandbox_open(sb, slot, 5, BLOCK), KFS_E_AUTH);
    kfs_sandbox_data(sb, slot)[42] ^= 1;
    CHECK_EQ(kfs_sandbox_open(sb, slot, 6, BLOCK), KFS_E_AUTH); /* wrong block id */
    CHECK_EQ(kfs_sandbox_open(sb, slot, 5, BLOCK), KFS_OK);
    kfs_sandbox_release(sb, slot);
}

static void test_scan(void)
{
    static const uint8_t elf[] = { 0x7f, 'E', 'L', 'F', 2, 1, 1 };
    kfs_scan_hit hit = { 0, 0 };
    uint32_t slot;
    uint8_t *data;

    CHECK_EQ(kfs_sandbox_acquire(sb, &slot), KFS_OK);
    data = kfs_sandbox_data(sb, slot);

    memset(data, 'a', 64);
    CHECK_EQ(kfs_sandbox_scan(sb, slot, 64, true, &hit), KFS_OK);

    memcpy(data + 20, "TEST", 4);
    CHECK_EQ(kfs_sandbox_scan(sb, slot, 64, false, &hit), KFS_E_MALWARE);
    CHECK_EQ(hit.sig_id, 10);
    CHECK_EQ(hit.offset, 20);

    memset(data, 'a', 64);
    memcpy(data, elf, sizeof(elf));
    CHECK_EQ(kfs_sandbox_scan(sb, slot, 64, true, &hit), KFS_E_MALWARE);
    CHECK_EQ(hit.sig_id, KFS_SIG_ELF_HEADER);
    CHECK_EQ(kfs_sandbox_scan(sb, slot, 64, false, &hit), KFS_OK); /* not file start */
    kfs_sandbox_release(sb, slot);
}

/* Returns the first number after "<field>:" in /proc/<pid>/status. */
static long proc_status(pid_t pid, const char *field)
{
    char path[64], line[256];
    size_t flen = strlen(field);
    long v = -1;
    FILE *fp;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    fp = fopen(path, "r");
    if (fp == NULL)
        return -1;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, field, flen) == 0 && line[flen] == ':') {
            v = strtol(line + flen + 1, NULL, 10);
            break;
        }
    }
    fclose(fp);
    return v;
}

static void test_workers_are_jailed(void)
{
    kfs_worker_info w[8];
    size_t n = kfs_sandbox_workers(sb, w, 8);

    CHECK_EQ(n, 4);
    for (size_t i = 0; i < n; i++) {
        char path[64], root[256];
        ssize_t len;

        CHECK(w[i].alive);
        CHECK_EQ(proc_status(w[i].pid, "NoNewPrivs"), 1);
        if (!privileged)
            continue;
        CHECK_EQ(proc_status(w[i].pid, "Uid"), 65534);
        CHECK_EQ(proc_status(w[i].pid, "Gid"), 65534);

        /* Non-dumpable workers hide /proc/<pid>/root from anyone without
         * CAP_SYS_PTRACE, which is itself the hardening working. */
        snprintf(path, sizeof(path), "/proc/%d/root", (int)w[i].pid);
        len = readlink(path, root, sizeof(root) - 1);
        if (len < 0 && errno == EACCES) {
            if (i == 0)
                printf("note: chroot path hidden (non-dumpable); "
                       "run with CAP_SYS_PTRACE to verify it\n");
            continue;
        }
        CHECK(len > 0);
        if (len > 0) {
            root[len] = '\0';
            CHECK_STR(root, jail);
        }
    }
}

static void *hammer(void *arg)
{
    uint8_t seed = (uint8_t)(uintptr_t)arg, plain[BLOCK];

    for (int i = 0; i < 300; i++) {
        uint64_t id = (uint64_t)seed << 32 | (uint64_t)i;
        uint32_t slot;

        if (kfs_sandbox_acquire(sb, &slot) != KFS_OK) {
            kfs_test_failures++;
            return NULL;
        }
        fill(plain, BLOCK, (uint8_t)(seed + i));
        memcpy(kfs_sandbox_data(sb, slot), plain, BLOCK);
        if (kfs_sandbox_seal(sb, slot, id, (uint64_t)i, BLOCK) != KFS_OK ||
            kfs_sandbox_open(sb, slot, id, BLOCK) != KFS_OK ||
            memcmp(kfs_sandbox_data(sb, slot), plain, BLOCK) != 0)
            kfs_test_failures++;
        kfs_sandbox_release(sb, slot);
    }
    return NULL;
}

static void test_concurrency(void)
{
    pthread_t t[8];

    for (uintptr_t i = 0; i < 8; i++)
        CHECK_EQ(pthread_create(&t[i], NULL, hammer, (void *)i), 0);
    for (int i = 0; i < 8; i++)
        pthread_join(t[i], NULL);
}

static void test_fail_closed(void)
{
    struct timespec tick = { 0, 10 * 1000 * 1000 };
    kfs_worker_info w[8];
    size_t n = kfs_sandbox_workers(sb, w, 8);
    uint32_t slot;

    for (size_t i = 0; i < n; i++) {
        if (w[i].kind == KFS_WORKER_CRYPTO) {
            kill(w[i].pid, SIGKILL);
            break;
        }
    }
    for (int i = 0; i < 200 && !kfs_sandbox_failed(sb); i++)
        nanosleep(&tick, NULL);
    CHECK(kfs_sandbox_failed(sb));
    CHECK_EQ(kfs_sandbox_acquire(sb, &slot), KFS_E_UNAVAILABLE);
}

int main(void)
{
    static const uint8_t pattern[] = { 'T', 'E', 'S', 'T' };
    uint8_t volume_key[KFS_KEY_SIZE];
    kfs_sandbox_opts opts;

    privileged = geteuid() == 0;
    if (privileged && mkdtemp(jail) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    printf("running %s\n", privileged ? "as root: chroot + setuid enabled"
                                      : "unprivileged: IPC only");

    scanner = kfs_scanner_new();
    if (scanner == NULL || kfs_scanner_add(scanner, 10, "test", pattern, sizeof(pattern)) != KFS_OK ||
        kfs_scanner_compile(scanner) != KFS_OK)
        return 1;
    memset(volume_key, 0x5c, sizeof(volume_key));
    if (kfs_block_keys_derive(volume_key, &keys) != KFS_OK)
        return 1;

    memset(&opts, 0, sizeof(opts));
    opts.scan_workers = 2;
    opts.crypto_workers = 2;
    opts.slots = 4;
    opts.block_size = BLOCK;
    opts.scanner = scanner;
    opts.block_elf = true;
    opts.drop_privileges = privileged;
    opts.chroot_dir = jail;
    opts.uid = 65534;
    opts.gid = 65534;

    if (kfs_sandbox_create(&opts, &sb) != KFS_OK ||
        kfs_sandbox_start_crypto(sb, &keys) != KFS_OK) {
        fprintf(stderr, "sandbox start failed\n");
        return 1;
    }

    RUN(test_seal_open);
    RUN(test_open_rejects_tampering);
    RUN(test_scan);
    RUN(test_workers_are_jailed);
    RUN(test_concurrency);
    RUN(test_fail_closed); /* last: leaves the sandbox failed */

    kfs_sandbox_destroy(sb);
    kfs_scanner_free(scanner);
    if (privileged)
        rmdir(jail);
    TEST_EXIT();
}
