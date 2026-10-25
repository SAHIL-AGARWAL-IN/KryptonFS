/*
 * test_fs.c - Volume header, metadata persistence and filesystem
 * semantics over a real local block store, including crash safety,
 * rollback and tamper detection, scanner gating and at-rest secrecy.
 */
#define _GNU_SOURCE /* mkdtemp, memmem */

#include "krypton/krypton_fs.h"

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "krypton/krypton_meta.h"
#include "krypton/krypton_volume.h"
#include "kfs_test.h"

#define BS 4096u

static char store[] = "/tmp/kfs-store-XXXXXX";
static kfs_block_keys keys;
static kfs_cipher cipher;
static kfs_scanner *scanner;
static int audit_calls;
static bool audit_blocked;

typedef struct mount {
    kfs_backend *backend;
    kfs_blockio  io;
    kfs_fs      *fs;
} mount;

static kfs_status scan_local(void *ctx, const uint8_t *block, size_t len,
                             bool file_start, kfs_scan_hit *hit)
{
    return kfs_scanner_scan(ctx, block, len, file_start ? 0 : 1, true, hit);
}

static void audit(void *ctx, const char *path, const kfs_scan_hit *hit, bool blocked)
{
    (void)ctx;
    (void)path;
    (void)hit;
    audit_calls++;
    audit_blocked = blocked;
}

static bool mount_open(mount *m, uint64_t cache_bytes, kfs_scan_action action)
{
    kfs_fs_opts o;

    memset(&o, 0, sizeof(o));
    o.block_size = BS;
    o.cache_bytes = cache_bytes;
    o.scan = scan_local;
    o.scan_ctx = scanner;
    o.scan_action = action;
    o.audit = audit;
    o.format_if_empty = true;
    o.root_uid = 1000;
    o.root_gid = 1000;
    if (kfs_backend_open_local(store, &m->backend) != KFS_OK ||
        kfs_blockio_init(&m->io, &cipher, m->backend) != KFS_OK ||
        kfs_fs_open(&m->io, &o, &m->fs) != KFS_OK) {
        fprintf(stderr, "mount failed\n");
        kfs_test_failures++;
        return false;
    }
    return true;
}

static int mount_close(mount *m)
{
    int rc = kfs_fs_close(m->fs);

    kfs_blockio_destroy(&m->io);
    kfs_backend_close(m->backend);
    return rc;
}

/* Removes every object so each test starts from an empty volume. */
static void wipe_store(void)
{
    DIR *top = opendir(store);
    struct dirent *a;

    if (top == NULL)
        return;
    while ((a = readdir(top)) != NULL) {
        char sub[600];
        DIR *d;
        struct dirent *b;

        if (a->d_name[0] == '.')
            continue;
        snprintf(sub, sizeof(sub), "%s/%s", store, a->d_name);
        d = opendir(sub);
        while (d != NULL && (b = readdir(d)) != NULL) {
            char path[900];

            if (strcmp(b->d_name, ".") == 0 || strcmp(b->d_name, "..") == 0)
                continue;
            snprintf(path, sizeof(path), "%s/%s", sub, b->d_name);
            unlink(path);
        }
        if (d != NULL)
            closedir(d);
        rmdir(sub);
    }
    closedir(top);
}

static void object_path(uint64_t bid, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%02x/%016llx", store, (unsigned)(bid & 0xff),
             (unsigned long long)bid);
}

static bool read_file(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *fp = fopen(path, "rb");

    if (fp == NULL)
        return false;
    *len = fread(buf, 1, cap, fp);
    fclose(fp);
    return true;
}

static void write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *fp = fopen(path, "wb");

    CHECK(fp != NULL);
    if (fp == NULL)
        return;
    CHECK_EQ(fwrite(buf, 1, len, fp), len);
    fclose(fp);
}

static int put(kfs_fs *fs, const char *path, const char *text)
{
    return kfs_fs_write(fs, path, (const uint8_t *)text, strlen(text), 0);
}

static void check_content(kfs_fs *fs, const char *path, const char *expect)
{
    char buf[256];
    int n = kfs_fs_read(fs, path, (uint8_t *)buf, sizeof(buf) - 1, 0);

    CHECK_EQ(n, (int)strlen(expect));
    if (n >= 0) {
        buf[n] = '\0';
        CHECK_STR(buf, expect);
    }
}

/* ------------------------------------------------------------------ */

static void test_volume_header(void)
{
    uint8_t hdr[KFS_VOLUME_HDR_SIZE], key[KFS_KEY_SIZE], back[KFS_KEY_SIZE], bad[KFS_VOLUME_HDR_SIZE];
    kfs_volume_header h;

    CHECK_EQ(kfs_volume_create("correct horse", 13, BS, 1000, hdr, key), KFS_OK);
    CHECK_EQ(kfs_volume_unlock(hdr, "correct horse", 13, &h, back), KFS_OK);
    CHECK(memcmp(key, back, sizeof(key)) == 0);
    CHECK_EQ(h.block_size, BS);
    CHECK_EQ(h.kdf_iterations, 1000);

    CHECK_EQ(kfs_volume_unlock(hdr, "wrong horse", 11, &h, back), KFS_E_AUTH);

    memcpy(bad, hdr, sizeof(bad));
    kfs_store_be32(bad + 4, 8192); /* edited block size */
    CHECK_EQ(kfs_volume_unlock(bad, "correct horse", 13, &h, back), KFS_E_AUTH);

    memcpy(bad, hdr, sizeof(bad));
    kfs_store_be32(bad + 8, 999); /* weakened iteration count */
    CHECK_EQ(kfs_volume_unlock(bad, "correct horse", 13, &h, back), KFS_E_AUTH);

    memcpy(bad, hdr, sizeof(bad));
    bad[0] ^= 1;
    CHECK_EQ(kfs_volume_unlock(bad, "correct horse", 13, &h, back), KFS_E_PROTO);

    CHECK_EQ(kfs_volume_create("p", 1, 3000, 1000, hdr, key), KFS_E_INVAL);
}

static void test_meta_serialization(void)
{
    kfs_meta m, back;
    kfs_inode *dir, *file;
    uint8_t *blob;
    size_t len;

    CHECK_EQ(kfs_meta_init(&m, BS, 0755, 0, 0, 1), KFS_OK);
    CHECK_EQ(kfs_meta_create(&m, kfs_meta_get(&m, KFS_ROOT_INO), "docs", S_IFDIR | 0700, 1, 2, 3, &dir), KFS_OK);
    CHECK_EQ(kfs_meta_create(&m, dir, "a.txt", S_IFREG | 0600, 1, 2, 3, &file), KFS_OK);
    file->size = 3 * BS;
    CHECK_EQ(kfs_meta_set_gen(&m, file, 2, kfs_meta_next_gen(&m, file, 2)), KFS_OK);

    CHECK_EQ(kfs_meta_serialize(&m, &blob, &len), KFS_OK);
    CHECK_EQ(kfs_meta_deserialize(&back, blob, len, BS), KFS_OK);
    {
        kfs_inode *n;

        CHECK_EQ(kfs_meta_resolve(&back, "/docs/a.txt", &n), 0);
        if (kfs_meta_resolve(&back, "/docs/a.txt", &n) == 0) {
            CHECK_EQ(n->size, 3 * BS);
            CHECK_EQ(kfs_meta_block_gen(n, 2), 1);
            CHECK_EQ(kfs_meta_block_gen(n, 0), 0);
            CHECK_EQ(n->uid, 1);
        }
        kfs_meta_destroy(&back);
    }

    CHECK_EQ(kfs_meta_deserialize(&back, blob, len - 1, BS), KFS_E_PROTO);   /* truncated */
    CHECK_EQ(kfs_meta_deserialize(&back, blob, len, 2 * BS), KFS_E_PROTO);   /* wrong volume */
    blob[0] ^= 1;
    CHECK_EQ(kfs_meta_deserialize(&back, blob, len, BS), KFS_E_PROTO);       /* bad magic */
    free(blob);
    kfs_meta_destroy(&m);
}

static void test_path_errors(void)
{
    kfs_meta m;
    kfs_inode *n, *dir;
    char leaf[KFS_NAME_LEN_MAX + 1], longname[300];

    CHECK_EQ(kfs_meta_init(&m, BS, 0755, 0, 0, 1), KFS_OK);
    CHECK_EQ(kfs_meta_create(&m, kfs_meta_get(&m, KFS_ROOT_INO), "f", S_IFREG | 0600, 0, 0, 1, &n), KFS_OK);
    CHECK_EQ(kfs_meta_resolve(&m, "/", &n), 0);
    CHECK_EQ(n->ino, KFS_ROOT_INO);
    CHECK_EQ(kfs_meta_resolve(&m, "/missing", &n), -ENOENT);
    CHECK_EQ(kfs_meta_resolve(&m, "/f/x", &n), -ENOTDIR);
    CHECK_EQ(kfs_meta_resolve(&m, "relative", &n), -EINVAL);
    CHECK_EQ(kfs_meta_resolve_parent(&m, "/", &dir, leaf), -EINVAL);
    CHECK_EQ(kfs_meta_resolve_parent(&m, "/new", &dir, leaf), 0);
    CHECK_STR(leaf, "new");
    memset(longname, 'x', sizeof(longname));
    longname[0] = '/';
    longname[sizeof(longname) - 1] = '\0';
    CHECK_EQ(kfs_meta_resolve(&m, longname, &n), -ENAMETOOLONG);
    kfs_meta_destroy(&m);
}

static int count_entry(void *ctx, const char *name, const kfs_stat *st)
{
    (void)name;
    (void)st;
    (*(int *)ctx)++;
    return 0;
}

static void test_tree_operations(void)
{
    mount mt;
    kfs_stat st;
    int entries = 0;

    wipe_store();
    if (!mount_open(&mt, 64 * BS, KFS_SCAN_REJECT))
        return;
    CHECK_EQ(kfs_fs_mkdir(mt.fs, "/docs", 0750, 1000, 1000), 0);
    CHECK_EQ(kfs_fs_mkdir(mt.fs, "/docs", 0750, 1000, 1000), -EEXIST);
    CHECK_EQ(kfs_fs_create(mt.fs, "/docs/a.txt", 0640, 1000, 1000), 0);
    CHECK_EQ(kfs_fs_create(mt.fs, "/missing/a.txt", 0640, 1000, 1000), -ENOENT);
    CHECK_EQ(put(mt.fs, "/docs/a.txt", "hello krypton"), 13);
    check_content(mt.fs, "/docs/a.txt", "hello krypton");

    CHECK_EQ(kfs_fs_getattr(mt.fs, "/docs/a.txt", &st), 0);
    CHECK_EQ(st.size, 13);
    CHECK_EQ(st.mode, S_IFREG | 0640);
    CHECK_EQ(kfs_fs_getattr(mt.fs, "/docs", &st), 0);
    CHECK_EQ(st.nlink, 2);
    CHECK_EQ(kfs_fs_getattr(mt.fs, "/", &st), 0);
    CHECK_EQ(st.nlink, 3);
    CHECK_EQ(st.uid, 1000);

    CHECK_EQ(kfs_fs_readdir(mt.fs, "/docs", count_entry, &entries), 0);
    CHECK_EQ(entries, 1);
    CHECK_EQ(kfs_fs_readdir(mt.fs, "/docs/a.txt", count_entry, &entries), -ENOTDIR);

    CHECK_EQ(kfs_fs_rmdir(mt.fs, "/docs"), -ENOTEMPTY);
    CHECK_EQ(kfs_fs_rmdir(mt.fs, "/docs/a.txt"), -ENOTDIR);
    CHECK_EQ(kfs_fs_unlink(mt.fs, "/docs"), -EISDIR);
    CHECK_EQ(kfs_fs_rmdir(mt.fs, "/"), -EBUSY);

    CHECK_EQ(kfs_fs_rename(mt.fs, "/docs/a.txt", "/b.txt", 0), 0);
    check_content(mt.fs, "/b.txt", "hello krypton");
    CHECK_EQ(kfs_fs_getattr(mt.fs, "/docs/a.txt", &st), -ENOENT);
    CHECK_EQ(kfs_fs_create(mt.fs, "/c.txt", 0600, 0, 0), 0);
    CHECK_EQ(kfs_fs_rename(mt.fs, "/b.txt", "/c.txt", KFS_RENAME_NOREPLACE), -EEXIST);
    CHECK_EQ(kfs_fs_rename(mt.fs, "/b.txt", "/c.txt", 0), 0); /* replaces */
    check_content(mt.fs, "/c.txt", "hello krypton");
    CHECK_EQ(kfs_fs_rename(mt.fs, "/docs", "/docs/sub", 0), -EINVAL);
    CHECK_EQ(kfs_fs_rename(mt.fs, "/c.txt", "/docs", 0), -EISDIR);

    CHECK_EQ(kfs_fs_chmod(mt.fs, "/c.txt", 0400), 0);
    CHECK_EQ(kfs_fs_getattr(mt.fs, "/c.txt", &st), 0);
    CHECK_EQ(st.mode, S_IFREG | 0400);
    CHECK_EQ(kfs_fs_unlink(mt.fs, "/c.txt"), 0);
    CHECK_EQ(kfs_fs_rmdir(mt.fs, "/docs"), 0);
    CHECK_EQ(mount_close(&mt), 0);
}

static void test_persistence_and_eviction(void)
{
    enum { NBLOCKS = 100 };
    uint8_t *data = malloc(NBLOCKS * BS), *back = malloc(NBLOCKS * BS);
    mount mt;

    CHECK(data != NULL && back != NULL);
    if (data == NULL || back == NULL)
        goto out;
    for (size_t i = 0; i < NBLOCKS * BS; i++)
        data[i] = (uint8_t)(i * 2654435761u >> 24);

    wipe_store();
    /* A 4-frame cache forces constant eviction and writeback. */
    if (!mount_open(&mt, 4 * BS, KFS_SCAN_REJECT))
        goto out;
    CHECK_EQ(kfs_fs_mkdir(mt.fs, "/d", 0755, 0, 0), 0);
    CHECK_EQ(kfs_fs_create(mt.fs, "/d/big", 0644, 0, 0), 0);
    for (size_t off = 0; off < NBLOCKS * BS; off += 10000) {
        size_t n = NBLOCKS * BS - off < 10000 ? NBLOCKS * BS - off : 10000;

        CHECK_EQ(kfs_fs_write(mt.fs, "/d/big", data + off, n, off), (int)n);
    }
    memset(back, 0, NBLOCKS * BS);
    for (size_t off = 0; off < NBLOCKS * BS; off += BS)
        CHECK_EQ(kfs_fs_read(mt.fs, "/d/big", back + off, BS, off), (int)BS);
    CHECK(memcmp(data, back, NBLOCKS * BS) == 0);
    {
        kfs_fs_usage u;

        kfs_fs_usage_get(mt.fs, &u);
        CHECK(u.cache.evictions > 0);
        CHECK_EQ(u.files, 1);
        CHECK_EQ(u.dirs, 2);
    }
    CHECK_EQ(mount_close(&mt), 0);

    /* A fresh mount sees everything. */
    if (!mount_open(&mt, 4 * BS, KFS_SCAN_REJECT))
        goto out;
    memset(back, 0, NBLOCKS * BS);
    CHECK_EQ(kfs_fs_read(mt.fs, "/d/big", back, NBLOCKS * BS, 0), NBLOCKS * BS);
    CHECK(memcmp(data, back, NBLOCKS * BS) == 0);
    CHECK_EQ(mount_close(&mt), 0);
out:
    free(data);
    free(back);
}

static void test_sparse_and_truncate(void)
{
    uint8_t buf[3 * BS];
    mount mt;

    wipe_store();
    if (!mount_open(&mt, 16 * BS, KFS_SCAN_REJECT))
        return;
    CHECK_EQ(kfs_fs_create(mt.fs, "/f", 0644, 0, 0), 0);
    CHECK_EQ(kfs_fs_write(mt.fs, "/f", (const uint8_t *)"end", 3, 2 * BS + 10), 3);
    memset(buf, 0xAA, sizeof(buf));
    CHECK_EQ(kfs_fs_read(mt.fs, "/f", buf, sizeof(buf), 0), 2 * BS + 13);
    for (size_t i = 0; i < 2 * BS + 10; i++) {
        if (buf[i] != 0) {
            CHECK_EQ(buf[i], 0); /* holes read as zeros */
            break;
        }
    }

    memset(buf, 'x', BS);
    CHECK_EQ(kfs_fs_write(mt.fs, "/f", buf, BS, 0), (int)BS);
    CHECK_EQ(kfs_fs_truncate(mt.fs, "/f", 100), 0);
    CHECK_EQ(kfs_fs_truncate(mt.fs, "/f", 2 * BS), 0);
    memset(buf, 0xAA, sizeof(buf));
    CHECK_EQ(kfs_fs_read(mt.fs, "/f", buf, sizeof(buf), 0), 2 * BS);
    CHECK_EQ(buf[99], 'x');
    CHECK_EQ(buf[100], 0); /* cut bytes stay gone after regrowing */
    CHECK_EQ(buf[BS + 5], 0);
    CHECK_EQ(kfs_fs_truncate(mt.fs, "/f", UINT64_MAX), -EFBIG);
    CHECK_EQ(mount_close(&mt), 0);
}

static void test_crash_keeps_last_commit(void)
{
    mount a, b;

    wipe_store();
    if (!mount_open(&a, 4 * BS, KFS_SCAN_REJECT))
        return;
    CHECK_EQ(kfs_fs_create(a.fs, "/f", 0644, 0, 0), 0);
    CHECK_EQ(put(a.fs, "/f", "committed"), 9);
    CHECK_EQ(kfs_fs_sync(a.fs), 0);

    /* Uncommitted changes, some of them already written to storage by
     * eviction, as if the daemon died before its next commit. */
    CHECK_EQ(put(a.fs, "/f", "UNCOMMITTED"), 11);
    CHECK_EQ(kfs_fs_create(a.fs, "/g", 0644, 0, 0), 0);
    for (int i = 0; i < 8; i++) {
        char name[16];

        snprintf(name, sizeof(name), "/e%d", i);
        CHECK_EQ(kfs_fs_create(a.fs, name, 0644, 0, 0), 0);
        CHECK_EQ(put(a.fs, name, "evict"), 5);
    }

    /* A second instance mounting now sees exactly the committed state. */
    if (mount_open(&b, 4 * BS, KFS_SCAN_REJECT)) {
        kfs_stat st;

        check_content(b.fs, "/f", "committed");
        CHECK_EQ(kfs_fs_getattr(b.fs, "/g", &st), -ENOENT);
        kfs_fs_close(b.fs); /* nothing dirty: no commit */
        kfs_blockio_destroy(&b.io);
        kfs_backend_close(b.backend);
    }
    CHECK_EQ(mount_close(&a), 0);
}

static void test_rollback_detected(void)
{
    uint8_t saved[KFS_ENVELOPE_HDR_SIZE + BS];
    char path[2][700];
    size_t saved_len = 0;
    int which = -1;
    kfs_stat st;
    mount mt;

    wipe_store();
    if (!mount_open(&mt, 16 * BS, KFS_SCAN_REJECT))
        return;
    CHECK_EQ(kfs_fs_create(mt.fs, "/f", 0644, 0, 0), 0);
    CHECK_EQ(put(mt.fs, "/f", "version one"), 11);
    CHECK_EQ(kfs_fs_sync(mt.fs), 0);
    CHECK_EQ(kfs_fs_getattr(mt.fs, "/f", &st), 0);

    for (int p = 0; p < 2; p++) {
        object_path(kfs_bid(st.ino, 0, (uint64_t)p), path[p], sizeof(path[p]));
        if (which < 0 && read_file(path[p], saved, sizeof(saved), &saved_len))
            which = p;
    }
    CHECK(which >= 0);

    /* Two rewrites bring the block back to the saved copy's parity. */
    CHECK_EQ(put(mt.fs, "/f", "version two"), 11);
    CHECK_EQ(kfs_fs_sync(mt.fs), 0);
    CHECK_EQ(put(mt.fs, "/f", "version 333"), 11);
    CHECK_EQ(kfs_fs_sync(mt.fs), 0);
    CHECK_EQ(mount_close(&mt), 0);

    /* The node now serves the old, validly tagged envelope. */
    if (which >= 0)
        write_file(path[which], saved, saved_len);
    if (!mount_open(&mt, 16 * BS, KFS_SCAN_REJECT))
        return;
    {
        char buf[32];

        CHECK_EQ(kfs_fs_read(mt.fs, "/f", (uint8_t *)buf, sizeof(buf), 0), -EIO);
    }
    CHECK_EQ(mount_close(&mt), 0);
}

static void test_tamper_detected(void)
{
    uint8_t obj[KFS_ENVELOPE_HDR_SIZE + BS];
    char path[700];
    size_t len = 0;
    kfs_stat st;
    mount mt;

    wipe_store();
    if (!mount_open(&mt, 16 * BS, KFS_SCAN_REJECT))
        return;
    CHECK_EQ(kfs_fs_create(mt.fs, "/f", 0644, 0, 0), 0);
    CHECK_EQ(put(mt.fs, "/f", "integrity matters"), 17);
    CHECK_EQ(kfs_fs_getattr(mt.fs, "/f", &st), 0);
    CHECK_EQ(mount_close(&mt), 0);

    for (int p = 0; p < 2; p++) {
        object_path(kfs_bid(st.ino, 0, (uint64_t)p), path, sizeof(path));
        if (read_file(path, obj, sizeof(obj), &len)) {
            obj[KFS_ENVELOPE_HDR_SIZE + 3] ^= 0x01; /* one ciphertext bit */
            write_file(path, obj, len);
            break;
        }
    }
    if (!mount_open(&mt, 16 * BS, KFS_SCAN_REJECT))
        return;
    {
        char buf[32];

        CHECK_EQ(kfs_fs_read(mt.fs, "/f", (uint8_t *)buf, sizeof(buf), 0), -EIO);
    }
    CHECK_EQ(mount_close(&mt), 0);
}

static void test_scanner_gates_writes(void)
{
    static const uint8_t elf[] = { 0x7f, 'E', 'L', 'F', 2, 1, 1, 0 };
    mount mt;

    wipe_store();
    if (!mount_open(&mt, 16 * BS, KFS_SCAN_REJECT))
        return;
    CHECK_EQ(kfs_fs_create(mt.fs, "/f", 0644, 0, 0), 0);
    CHECK_EQ(put(mt.fs, "/f", "clean data"), 10);

    audit_calls = 0;
    CHECK_EQ(kfs_fs_write(mt.fs, "/f", (const uint8_t *)"..TEST..", 8, 100), -EACCES);
    CHECK_EQ(audit_calls, 1);
    CHECK(audit_blocked);
    check_content(mt.fs, "/f", "clean data"); /* unchanged, size included */

    /* A signature split across two writes is caught on the second. */
    CHECK_EQ(kfs_fs_write(mt.fs, "/f", (const uint8_t *)"TE", 2, 200), 2);
    CHECK_EQ(kfs_fs_write(mt.fs, "/f", (const uint8_t *)"ST", 2, 202), -EACCES);

    CHECK_EQ(kfs_fs_create(mt.fs, "/bin", 0755, 0, 0), 0);
    CHECK_EQ(kfs_fs_write(mt.fs, "/bin", elf, sizeof(elf), 0), -EACCES);
    CHECK_EQ(kfs_fs_write(mt.fs, "/bin", elf, sizeof(elf), BS), (int)sizeof(elf)); /* not at offset 0 */
    CHECK_EQ(mount_close(&mt), 0);

    /* In log mode the write lands and the match is still audited. */
    if (!mount_open(&mt, 16 * BS, KFS_SCAN_LOG))
        return;
    audit_calls = 0;
    CHECK_EQ(kfs_fs_write(mt.fs, "/f", (const uint8_t *)"TEST", 4, 0), 4);
    CHECK_EQ(audit_calls, 1);
    CHECK(!audit_blocked);
    CHECK_EQ(mount_close(&mt), 0);
}

static bool store_contains(const void *needle, size_t len)
{
    DIR *top = opendir(store);
    struct dirent *a;
    bool found = false;
    static uint8_t buf[KFS_ENVELOPE_HDR_SIZE + BS + 16];

    while (!found && top != NULL && (a = readdir(top)) != NULL) {
        char sub[600];
        DIR *d;
        struct dirent *b;

        if (a->d_name[0] == '.')
            continue;
        snprintf(sub, sizeof(sub), "%s/%s", store, a->d_name);
        d = opendir(sub);
        while (!found && d != NULL && (b = readdir(d)) != NULL) {
            char path[900];
            size_t n;

            snprintf(path, sizeof(path), "%s/%s", sub, b->d_name);
            if (b->d_name[0] != '.' && read_file(path, buf, sizeof(buf), &n))
                found = memmem(buf, n, needle, len) != NULL;
        }
        if (d != NULL)
            closedir(d);
    }
    if (top != NULL)
        closedir(top);
    return found;
}

static void test_nothing_plaintext_at_rest(void)
{
    mount mt;

    wipe_store();
    if (!mount_open(&mt, 16 * BS, KFS_SCAN_REJECT))
        return;
    CHECK_EQ(kfs_fs_mkdir(mt.fs, "/quarterly-secrets", 0700, 0, 0), 0);
    CHECK_EQ(kfs_fs_create(mt.fs, "/quarterly-secrets/payroll.csv", 0600, 0, 0), 0);
    CHECK_EQ(put(mt.fs, "/quarterly-secrets/payroll.csv", "PLAINTEXT-MARKER alice,90000"), 28);
    CHECK_EQ(mount_close(&mt), 0);

    CHECK(!store_contains("PLAINTEXT-MARKER", 16));
    CHECK(!store_contains("payroll.csv", 11));
    CHECK(!store_contains("quarterly-secrets", 17));
}

int main(void)
{
    static const uint8_t pattern[] = { 'T', 'E', 'S', 'T' };
    uint8_t volume_key[KFS_KEY_SIZE];

    if (mkdtemp(store) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    memset(volume_key, 0x77, sizeof(volume_key));
    scanner = kfs_scanner_new();
    if (kfs_block_keys_derive(volume_key, &keys) != KFS_OK || scanner == NULL ||
        kfs_scanner_add(scanner, 10, "test", pattern, sizeof(pattern)) != KFS_OK ||
        kfs_scanner_compile(scanner) != KFS_OK)
        return 1;
    kfs_cipher_local(&cipher, &keys);

    RUN(test_volume_header);
    RUN(test_meta_serialization);
    RUN(test_path_errors);
    RUN(test_tree_operations);
    RUN(test_persistence_and_eviction);
    RUN(test_sparse_and_truncate);
    RUN(test_crash_keeps_last_commit);
    RUN(test_rollback_detected);
    RUN(test_tamper_detected);
    RUN(test_scanner_gates_writes);
    RUN(test_nothing_plaintext_at_rest);

    wipe_store();
    rmdir(store);
    kfs_scanner_free(scanner);
    TEST_EXIT();
}
