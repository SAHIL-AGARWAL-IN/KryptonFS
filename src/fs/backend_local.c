/*
 * backend_local.c - Block store in a local directory (POSIX).
 */
#define _POSIX_C_SOURCE 200809L

#include "krypton/krypton_backend.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct local_backend {
    kfs_backend    base; /* first: kfs_backend * converts to local_backend * */
    char           dir[KFS_PATH_MAX];
    atomic_ulong   tmp_seq;
} local_backend;

static local_backend *local_of(kfs_backend *b)
{
    return (local_backend *)(void *)b;
}

static void object_dir(const local_backend *lb, uint64_t id, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%02x", lb->dir, (unsigned)(id & 0xff));
}

static void object_path(const local_backend *lb, uint64_t id, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%02x/%016llx", lb->dir, (unsigned)(id & 0xff),
             (unsigned long long)id);
}

static bool write_all(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        buf += n;
        len -= (size_t)n;
    }
    return true;
}

static bool fsync_dir(const char *dir)
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    bool ok;

    if (fd < 0)
        return false;
    ok = fsync(fd) == 0;
    close(fd);
    return ok;
}

static kfs_status local_put(kfs_backend *b, uint64_t id, const uint8_t *buf, size_t len)
{
    local_backend *lb = local_of(b);
    char dir[KFS_PATH_MAX + 8], path[KFS_PATH_MAX + 32], tmp[KFS_PATH_MAX + 64];
    int fd;

    object_dir(lb, id, dir, sizeof(dir));
    object_path(lb, id, path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s/.tmp.%016llx.%lu", dir, (unsigned long long)id,
             atomic_fetch_add(&lb->tmp_seq, 1));

    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return KFS_E_IO;
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return KFS_E_IO;
    if (!write_all(fd, buf, len) || fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return KFS_E_IO;
    }
    close(fd);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return KFS_E_IO;
    }
    return fsync_dir(dir) ? KFS_OK : KFS_E_IO;
}

static kfs_status local_get(kfs_backend *b, uint64_t id, uint8_t *buf, size_t cap, size_t *len)
{
    char path[KFS_PATH_MAX + 32];
    struct stat st;
    size_t done = 0;
    int fd;

    object_path(local_of(b), id, path, sizeof(path));
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT ? KFS_E_NOT_FOUND : KFS_E_IO;
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        close(fd);
        return KFS_E_IO;
    }
    if ((uint64_t)st.st_size > cap) {
        close(fd);
        return KFS_E_PROTO;
    }
    while (done < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + done, (size_t)st.st_size - done);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            close(fd);
            return KFS_E_IO;
        }
        done += (size_t)n;
    }
    close(fd);
    *len = done;
    return KFS_OK;
}

static kfs_status local_del(kfs_backend *b, uint64_t id)
{
    char path[KFS_PATH_MAX + 32];

    object_path(local_of(b), id, path, sizeof(path));
    if (unlink(path) != 0 && errno != ENOENT)
        return KFS_E_IO;
    return KFS_OK;
}

static void local_close(kfs_backend *b)
{
    free(local_of(b));
}

static const kfs_backend_ops LOCAL_OPS = {
    local_put, local_get, local_del, local_close,
};

kfs_status kfs_backend_open_local(const char *dir, kfs_backend **out)
{
    local_backend *lb;
    struct stat st;

    if (strlen(dir) >= KFS_PATH_MAX - 8)
        return KFS_E_INVAL;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
        return KFS_E_NOT_FOUND;
    lb = calloc(1, sizeof(*lb));
    if (lb == NULL)
        return KFS_E_NOMEM;
    lb->base.ops = &LOCAL_OPS;
    snprintf(lb->dir, sizeof(lb->dir), "%s", dir);
    atomic_init(&lb->tmp_seq, 0);
    *out = &lb->base;
    return KFS_OK;
}
