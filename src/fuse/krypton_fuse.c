/*
 * krypton_fuse.c - kryptonfs: the FUSE client daemon.
 *
 *   kryptonfs [-c CONFIG] --local-store DIR [MOUNTPOINT] [FUSE options]
 *
 * Start-up order is what keeps secrets out of the scan workers:
 *
 *   1. read the volume header (unencrypted) for the block size
 *   2. fork the scan pool: no passphrase or key exists in memory yet
 *   3. read the passphrase, unlock the volume key, derive block keys
 *   4. fork the crypto pool with the keys; wipe every copy held here
 *   5. mount; all sealing, opening and scanning goes through the pools
 *
 * The daemon stays in the foreground: daemonizing would fork after the
 * pools exist and orphan them. Run it under a supervisor (e.g. systemd).
 * Until Phase 4 adds the replicated network backend, blocks live in a
 * local directory given with --local-store.
 */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 31

#include <errno.h>
#include <fuse.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "krypton/krypton_backend.h"
#include "krypton/krypton_blockio.h"
#include "krypton/krypton_config.h"
#include "krypton/krypton_fs.h"
#include "krypton/krypton_meta.h"
#include "krypton/krypton_passphrase.h"
#include "krypton/krypton_sandbox.h"
#include "krypton/krypton_scanner.h"
#include "krypton/krypton_volume.h"

typedef struct daemon_ctx {
    kfs_config   cfg;
    kfs_backend *backend;
    kfs_scanner *scanner;
    kfs_sandbox *sandbox;
    kfs_blockio  io;
    bool         io_ready;
    kfs_fs      *fs;
    uint32_t     block_size;
} daemon_ctx;

static kfs_fs *FS(void)
{
    return ((daemon_ctx *)fuse_get_context()->private_data)->fs;
}

/* ---------------------------------------------------------------------
 * Sandbox adapters: copy into a shared slot, run the op in the jail,
 * copy the result out, and wipe the slot.
 * ------------------------------------------------------------------- */

static kfs_status sb_seal(void *ctx, uint64_t id, uint64_t gen, uint8_t *data,
                          size_t len, kfs_envelope_hdr *env)
{
    kfs_sandbox *sb = ctx;
    uint32_t slot;
    kfs_status st = kfs_sandbox_acquire(sb, &slot);

    if (st != KFS_OK)
        return st;
    memcpy(kfs_sandbox_data(sb, slot), data, len);
    st = kfs_sandbox_seal(sb, slot, id, gen, (uint32_t)len);
    if (st == KFS_OK) {
        memcpy(data, kfs_sandbox_data(sb, slot), len);
        *env = *kfs_sandbox_meta(sb, slot);
    }
    kfs_wipe(kfs_sandbox_data(sb, slot), len);
    kfs_sandbox_release(sb, slot);
    return st;
}

static kfs_status sb_open(void *ctx, uint64_t id, const kfs_envelope_hdr *env,
                          uint8_t *data, size_t len)
{
    kfs_sandbox *sb = ctx;
    uint32_t slot;
    kfs_status st = kfs_sandbox_acquire(sb, &slot);

    if (st != KFS_OK)
        return st;
    memcpy(kfs_sandbox_data(sb, slot), data, len);
    *kfs_sandbox_meta(sb, slot) = *env;
    st = kfs_sandbox_open(sb, slot, id, (uint32_t)len);
    if (st == KFS_OK)
        memcpy(data, kfs_sandbox_data(sb, slot), len);
    kfs_wipe(kfs_sandbox_data(sb, slot), len);
    kfs_sandbox_release(sb, slot);
    return st;
}

static const kfs_cipher_ops SANDBOX_CIPHER = { sb_seal, sb_open };

static kfs_status sb_scan(void *ctx, const uint8_t *block, size_t len,
                          bool file_start, kfs_scan_hit *hit)
{
    kfs_sandbox *sb = ctx;
    uint32_t slot;
    kfs_status st = kfs_sandbox_acquire(sb, &slot);

    if (st != KFS_OK)
        return st;
    memcpy(kfs_sandbox_data(sb, slot), block, len);
    st = kfs_sandbox_scan(sb, slot, (uint32_t)len, file_start, hit);
    kfs_wipe(kfs_sandbox_data(sb, slot), len);
    kfs_sandbox_release(sb, slot);
    return st;
}

static void audit(void *ctx, const char *path, const kfs_scan_hit *hit, bool blocked)
{
    daemon_ctx *d = ctx;

    syslog(blocked ? LOG_WARNING : LOG_NOTICE,
           "%s write to %s: signature %u (%s) at offset %u",
           blocked ? "blocked" : "allowed", path, hit->sig_id,
           kfs_scanner_sig_name(d->scanner, hit->sig_id), hit->offset);
}

/* ---------------------------------------------------------------------
 * FUSE callbacks
 * ------------------------------------------------------------------- */

static void to_stat(const kfs_stat *k, uint32_t block_size, struct stat *st)
{
    memset(st, 0, sizeof(*st));
    st->st_ino = k->ino;
    st->st_mode = k->mode;
    st->st_nlink = k->nlink;
    st->st_uid = k->uid;
    st->st_gid = k->gid;
    st->st_size = (off_t)k->size;
    st->st_blocks = (blkcnt_t)k->blocks512;
    st->st_blksize = (blksize_t)block_size;
    st->st_mtim.tv_sec = k->mtime_ns / 1000000000;
    st->st_mtim.tv_nsec = k->mtime_ns % 1000000000;
    st->st_ctim.tv_sec = k->ctime_ns / 1000000000;
    st->st_ctim.tv_nsec = k->ctime_ns % 1000000000;
    st->st_atim = st->st_mtim; /* atime is not tracked */
}

static uint32_t block_size(void)
{
    return ((daemon_ctx *)fuse_get_context()->private_data)->block_size;
}

static void *op_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    (void)conn;
    cfg->use_ino = 1;
    return fuse_get_context()->private_data;
}

static int op_getattr(const char *path, struct stat *st, struct fuse_file_info *fi)
{
    kfs_stat k;
    int rc = kfs_fs_getattr(FS(), path, &k);

    (void)fi;
    if (rc == 0)
        to_stat(&k, block_size(), st);
    return rc;
}

typedef struct fill_ctx {
    void            *buf;
    fuse_fill_dir_t  filler;
    uint32_t         block_size;
} fill_ctx;

static int fill_entry(void *ctx, const char *name, const kfs_stat *k)
{
    fill_ctx *f = ctx;
    struct stat st;

    to_stat(k, f->block_size, &st);
    return f->filler(f->buf, name, &st, 0, 0);
}

static int op_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off,
                      struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
    fill_ctx f = { buf, filler, block_size() };

    (void)off;
    (void)fi;
    (void)flags;
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    return kfs_fs_readdir(FS(), path, fill_entry, &f);
}

static uint32_t apply_umask(mode_t mode)
{
    return (uint32_t)(mode & ~fuse_get_context()->umask);
}

static int op_mkdir(const char *path, mode_t mode)
{
    struct fuse_context *c = fuse_get_context();

    return kfs_fs_mkdir(FS(), path, apply_umask(mode), c->uid, c->gid);
}

static int op_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    struct fuse_context *c = fuse_get_context();

    (void)fi;
    return kfs_fs_create(FS(), path, apply_umask(mode), c->uid, c->gid);
}

static int op_open(const char *path, struct fuse_file_info *fi)
{
    kfs_stat k;
    int rc = kfs_fs_getattr(FS(), path, &k);

    (void)fi;
    if (rc == 0 && S_ISDIR(k.mode))
        rc = -EISDIR;
    return rc;
}

static int op_read(const char *path, char *buf, size_t size, off_t off,
                   struct fuse_file_info *fi)
{
    (void)fi;
    if (off < 0)
        return -EINVAL;
    return kfs_fs_read(FS(), path, (uint8_t *)buf, size, (uint64_t)off);
}

static int op_write(const char *path, const char *buf, size_t size, off_t off,
                    struct fuse_file_info *fi)
{
    (void)fi;
    if (off < 0)
        return -EINVAL;
    return kfs_fs_write(FS(), path, (const uint8_t *)buf, size, (uint64_t)off);
}

static int op_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    (void)fi;
    if (size < 0)
        return -EINVAL;
    return kfs_fs_truncate(FS(), path, (uint64_t)size);
}

static int op_unlink(const char *path)
{
    return kfs_fs_unlink(FS(), path);
}

static int op_rmdir(const char *path)
{
    return kfs_fs_rmdir(FS(), path);
}

static int op_rename(const char *from, const char *to, unsigned int flags)
{
    if (flags & ~(unsigned)RENAME_NOREPLACE)
        return -EINVAL;
    return kfs_fs_rename(FS(), from, to, (flags & RENAME_NOREPLACE) ? KFS_RENAME_NOREPLACE : 0);
}

static int op_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void)fi;
    return kfs_fs_chmod(FS(), path, (uint32_t)mode);
}

static int op_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
    (void)fi;
    return kfs_fs_chown(FS(), path, (uint32_t)uid, (uint32_t)gid);
}

static int op_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi)
{
    struct timespec now;
    const struct timespec *m = tv != NULL ? &tv[1] : NULL;

    (void)fi;
    if (m != NULL && m->tv_nsec == UTIME_OMIT)
        return 0;
    if (m == NULL || m->tv_nsec == UTIME_NOW) {
        clock_gettime(CLOCK_REALTIME, &now);
        m = &now;
    }
    return kfs_fs_utimens(FS(), path, (int64_t)m->tv_sec * 1000000000 + m->tv_nsec);
}

static int op_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    (void)path;
    (void)datasync;
    (void)fi;
    return kfs_fs_sync(FS());
}

static int op_statfs(const char *path, struct statvfs *sv)
{
    kfs_fs_usage u;
    uint32_t bs = block_size();

    (void)path;
    kfs_fs_usage_get(FS(), &u);
    memset(sv, 0, sizeof(*sv));
    sv->f_bsize = bs;
    sv->f_frsize = bs;
    sv->f_blocks = KFS_MAX_FILE_BLOCKS;
    sv->f_bfree = sv->f_bavail = KFS_MAX_FILE_BLOCKS - (u.data_blocks < KFS_MAX_FILE_BLOCKS
                                                         ? u.data_blocks : KFS_MAX_FILE_BLOCKS);
    sv->f_files = u.files + u.dirs;
    sv->f_namemax = KFS_NAME_LEN_MAX;
    return 0;
}

static const struct fuse_operations OPS = {
    .init     = op_init,
    .getattr  = op_getattr,
    .readdir  = op_readdir,
    .mkdir    = op_mkdir,
    .create   = op_create,
    .open     = op_open,
    .read     = op_read,
    .write    = op_write,
    .truncate = op_truncate,
    .unlink   = op_unlink,
    .rmdir    = op_rmdir,
    .rename   = op_rename,
    .chmod    = op_chmod,
    .chown    = op_chown,
    .utimens  = op_utimens,
    .fsync    = op_fsync,
    .statfs   = op_statfs,
};

/* ---------------------------------------------------------------------
 * Start-up
 * ------------------------------------------------------------------- */

typedef struct cli_opts {
    char *config;
    char *store;
    int   help;
    bool  has_mountpoint;
} cli_opts;

/* Notes whether a positional (mountpoint) argument was given; every
 * argument not matched by CLI_SPEC passes through to FUSE. */
static int keep_arg(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    (void)arg;
    (void)outargs;
    if (key == FUSE_OPT_KEY_NONOPT)
        ((cli_opts *)data)->has_mountpoint = true;
    return 1;
}

static const struct fuse_opt CLI_SPEC[] = {
    { "-c %s",            offsetof(cli_opts, config), 0 },
    { "--config=%s",      offsetof(cli_opts, config), 0 },
    { "--local-store=%s", offsetof(cli_opts, store), 0 },
    { "-h",               offsetof(cli_opts, help), 1 },
    { "--help",           offsetof(cli_opts, help), 1 },
    FUSE_OPT_END,
};

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [-c CONFIG] --local-store DIR [MOUNTPOINT] [FUSE options]\n"
            "  -c, --config=FILE     configuration (default /etc/kryptonfs/kryptonfs.conf)\n"
            "  --local-store=DIR     block store created by kfs-mkvol\n"
            "MOUNTPOINT defaults to [volume] mountpoint.\n",
            prog);
}

/* Loads, compiles and returns the scanner, or NULL when disabled. */
static kfs_status build_scanner(const kfs_config *cfg, kfs_scanner **out)
{
    char err[512];
    kfs_scanner *sc;
    kfs_status st = KFS_OK;

    *out = NULL;
    if (!cfg->scanner.enabled)
        return KFS_OK;
    sc = kfs_scanner_new();
    if (sc == NULL)
        return KFS_E_NOMEM;
    if (cfg->scanner.signatures[0] != '\0') {
        st = kfs_scanner_load(sc, cfg->scanner.signatures, err, sizeof(err));
        if (st != KFS_OK)
            fprintf(stderr, "kryptonfs: %s\n", err);
    }
    if (st == KFS_OK)
        st = kfs_scanner_compile(sc);
    if (st != KFS_OK) {
        kfs_scanner_free(sc);
        return st;
    }
    *out = sc;
    return KFS_OK;
}

/* Steps 1-4 of the start-up order described at the top of this file. */
static int start_sandbox(daemon_ctx *d)
{
    static char pass[KFS_PASSPHRASE_MAX];
    uint8_t hdr[KFS_VOLUME_HDR_SIZE], volume_key[KFS_KEY_SIZE];
    kfs_volume_header vh;
    kfs_block_keys keys;
    kfs_sandbox_opts so;
    size_t hdr_len = 0, pass_len = 0;
    kfs_status st;

    st = kfs_backend_get(d->backend, KFS_BID_VOLUME_HEADER, hdr, sizeof(hdr), &hdr_len);
    if (st == KFS_E_NOT_FOUND) {
        fprintf(stderr, "kryptonfs: no volume in the store; create one with kfs-mkvol\n");
        return -1;
    }
    d->block_size = st == KFS_OK && hdr_len == sizeof(hdr) ? kfs_volume_block_size(hdr) : 0;
    if (d->block_size == 0) {
        fprintf(stderr, "kryptonfs: unreadable volume header\n");
        return -1;
    }

    if (build_scanner(&d->cfg, &d->scanner) != KFS_OK)
        return -1;

    memset(&so, 0, sizeof(so));
    so.scan_workers = d->cfg.sandbox.scan_workers;
    so.crypto_workers = d->cfg.sandbox.crypto_workers;
    so.slots = d->cfg.sandbox.ipc_slots;
    so.block_size = d->block_size;
    so.scanner = d->scanner;
    so.block_elf = d->cfg.scanner.block_elf;
    so.drop_privileges = true;
    so.chroot_dir = d->cfg.sandbox.chroot_dir;
    so.uid = d->cfg.sandbox.uid;
    so.gid = d->cfg.sandbox.gid;
    st = kfs_sandbox_create(&so, &d->sandbox);
    if (st != KFS_OK) {
        fprintf(stderr, "kryptonfs: cannot start scan workers in %s: %s\n",
                so.chroot_dir, kfs_strerror(st));
        return -1;
    }

    mlock(pass, sizeof(pass));
    mlock(volume_key, sizeof(volume_key));
    mlock(&keys, sizeof(keys));
    if (kfs_read_passphrase("Volume passphrase: ", false, pass, sizeof(pass), &pass_len) != KFS_OK)
        return -1;
    st = kfs_volume_unlock(hdr, pass, pass_len, &vh, volume_key);
    kfs_wipe(pass, sizeof(pass));
    if (st == KFS_OK)
        st = kfs_block_keys_derive(volume_key, &keys);
    kfs_wipe(volume_key, sizeof(volume_key));
    if (st == KFS_E_AUTH) {
        fprintf(stderr, "kryptonfs: wrong passphrase (or tampered volume header)\n");
        return -1;
    }
    if (st == KFS_OK)
        st = kfs_sandbox_start_crypto(d->sandbox, &keys);
    kfs_wipe(&keys, sizeof(keys));
    if (st != KFS_OK) {
        fprintf(stderr, "kryptonfs: cannot start crypto workers: %s\n", kfs_strerror(st));
        return -1;
    }
    return 0;
}

static int open_fs(daemon_ctx *d)
{
    kfs_cipher cipher = { &SANDBOX_CIPHER, d->sandbox };
    kfs_fs_opts fo;
    kfs_status st;

    if (kfs_blockio_init(&d->io, &cipher, d->backend) != KFS_OK)
        return -1;
    d->io_ready = true;

    memset(&fo, 0, sizeof(fo));
    fo.block_size = d->block_size;
    fo.cache_bytes = d->cfg.cache.size_bytes;
    fo.lock_memory = d->cfg.cache.lock_memory;
    fo.writeback_ms = d->cfg.cache.writeback_ms;
    if (d->scanner != NULL) {
        fo.scan = sb_scan;
        fo.scan_ctx = d->sandbox;
    }
    fo.scan_action = d->cfg.scanner.action;
    fo.audit = audit;
    fo.audit_ctx = d;
    st = kfs_fs_open(&d->io, &fo, &d->fs);
    if (st != KFS_OK) {
        fprintf(stderr, "kryptonfs: cannot open volume: %s%s\n", kfs_strerror(st),
                st == KFS_E_NOMEM && fo.lock_memory
                    ? " (lock_memory needs CAP_IPC_LOCK or a higher RLIMIT_MEMLOCK)" : "");
        return -1;
    }
    return 0;
}

static void shutdown_all(daemon_ctx *d)
{
    if (d->fs != NULL && kfs_fs_close(d->fs) != 0)
        fprintf(stderr, "kryptonfs: final sync failed; last committed state is intact\n");
    if (d->io_ready)
        kfs_blockio_destroy(&d->io);
    kfs_sandbox_destroy(d->sandbox);
    kfs_scanner_free(d->scanner);
    kfs_backend_close(d->backend);
}

int main(int argc, char **argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    static daemon_ctx d;
    cli_opts cli = { NULL, NULL, 0, false };
    char err[512];
    int rc = 1;

    openlog("kryptonfs", LOG_PID | LOG_PERROR, LOG_DAEMON); /* foreground: mirror to stderr */
    if (fuse_opt_parse(&args, &cli, CLI_SPEC, keep_arg) != 0)
        return 2;
    if (cli.help || cli.store == NULL) {
        usage(argv[0]);
        return cli.help ? 0 : 2;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "kryptonfs: must start as root to chroot and drop privileges "
                        "of its sandbox workers\n");
        return 1;
    }

    kfs_config_defaults(&d.cfg);
    if (kfs_config_load(&d.cfg, cli.config != NULL ? cli.config : "/etc/kryptonfs/kryptonfs.conf",
                        err, sizeof(err)) != KFS_OK ||
        kfs_config_validate(&d.cfg, KFS_ROLE_CLIENT, err, sizeof(err)) != KFS_OK) {
        fprintf(stderr, "kryptonfs: %s\n", err);
        return 1;
    }
    if (kfs_backend_open_local(cli.store, &d.backend) != KFS_OK) {
        fprintf(stderr, "kryptonfs: %s: not a directory\n", cli.store);
        return 1;
    }

    if (start_sandbox(&d) == 0 && open_fs(&d) == 0) {
        /* Foreground, so the worker pools stay children of this process.
         * The kernel enforces permissions from the stored modes. */
        fuse_opt_add_arg(&args, "-f");
        fuse_opt_add_arg(&args, "-odefault_permissions,allow_other,fsname=kryptonfs,subtype=kryptonfs");
        if (!cli.has_mountpoint)
            fuse_opt_add_arg(&args, d.cfg.volume.mountpoint);
        rc = fuse_main(args.argc, args.argv, &OPS, &d);
    }

    shutdown_all(&d);
    fuse_opt_free_args(&args);
    free(cli.config);
    free(cli.store);
    closelog();
    return rc;
}
