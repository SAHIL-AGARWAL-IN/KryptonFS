/*
 * kfs-mkvol - Create a KryptonFS volume.
 *
 *   kfs-mkvol --local-store DIR [--block-size N] [--iterations N] [--owner UID:GID]
 *
 * Writes the volume header (salt, KDF parameters, wrapped volume key) and
 * formats an empty root directory owned by UID:GID (default: $SUDO_UID /
 * $SUDO_GID, else the caller). Refuses to touch a store that already
 * holds a volume. See krypton_passphrase.h for how the passphrase is read.
 */
#define _POSIX_C_SOURCE 200809L

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "krypton/krypton_backend.h"
#include "krypton/krypton_blockio.h"
#include "krypton/krypton_fs.h"
#include "krypton/krypton_passphrase.h"
#include "krypton/krypton_volume.h"

static int usage(void)
{
    fprintf(stderr,
            "usage: kfs-mkvol --local-store DIR [--block-size N] [--iterations N]\n"
            "                 [--owner UID:GID]\n");
    return 2;
}

static bool parse_u32(const char *s, uint32_t *out)
{
    char *end;
    unsigned long long v;

    if (*s < '0' || *s > '9')
        return false;
    v = strtoull(s, &end, 10);
    if (*end != '\0' || v > UINT32_MAX)
        return false;
    *out = (uint32_t)v;
    return true;
}

static uint32_t id_from_env(const char *name, uint32_t fallback)
{
    const char *v = getenv(name);
    uint32_t id;

    return v != NULL && parse_u32(v, &id) ? id : fallback;
}

int main(int argc, char **argv)
{
    static const struct option longopts[] = {
        { "local-store", required_argument, NULL, 's' },
        { "block-size",  required_argument, NULL, 'b' },
        { "iterations",  required_argument, NULL, 'i' },
        { "owner",       required_argument, NULL, 'o' },
        { NULL, 0, NULL, 0 },
    };
    const char *store = NULL;
    uint32_t block_size = KFS_BLOCK_SIZE_DEFAULT, iterations = KFS_KDF_MIN_ITERATIONS;
    uint32_t uid = id_from_env("SUDO_UID", (uint32_t)getuid());
    uint32_t gid = id_from_env("SUDO_GID", (uint32_t)getgid());
    static char pass[KFS_PASSPHRASE_MAX];
    uint8_t hdr[KFS_VOLUME_HDR_SIZE], probe[KFS_VOLUME_HDR_SIZE], volume_key[KFS_KEY_SIZE];
    kfs_block_keys keys;
    kfs_backend *backend = NULL;
    kfs_cipher cipher;
    kfs_blockio io;
    kfs_fs_opts fo;
    kfs_fs *fs;
    size_t pass_len = 0, probe_len = 0;
    kfs_status st;
    int c, rc = 1;

    while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
        switch (c) {
        case 's':
            store = optarg;
            break;
        case 'b':
            if (!parse_u32(optarg, &block_size))
                return usage();
            break;
        case 'i':
            if (!parse_u32(optarg, &iterations))
                return usage();
            break;
        case 'o': {
            char *colon = strchr(optarg, ':');

            if (colon == NULL)
                return usage();
            *colon = '\0';
            if (!parse_u32(optarg, &uid) || !parse_u32(colon + 1, &gid))
                return usage();
            break;
        }
        default:
            return usage();
        }
    }
    if (store == NULL || optind != argc)
        return usage();
    if (iterations < KFS_KDF_MIN_ITERATIONS) {
        fprintf(stderr, "kfs-mkvol: --iterations must be at least %u\n", KFS_KDF_MIN_ITERATIONS);
        return 2;
    }

    mlock(pass, sizeof(pass));
    mlock(volume_key, sizeof(volume_key));
    mlock(&keys, sizeof(keys));

    st = kfs_backend_open_local(store, &backend);
    if (st != KFS_OK) {
        fprintf(stderr, "kfs-mkvol: %s: not a directory\n", store);
        return 1;
    }
    if (kfs_backend_get(backend, KFS_BID_VOLUME_HEADER, probe, sizeof(probe), &probe_len) !=
        KFS_E_NOT_FOUND) {
        fprintf(stderr, "kfs-mkvol: %s already holds a volume; refusing to overwrite it\n", store);
        goto out;
    }

    if (kfs_read_passphrase("New volume passphrase: ", true, pass, sizeof(pass), &pass_len) != KFS_OK)
        goto out;

    st = kfs_volume_create(pass, pass_len, block_size, iterations, hdr, volume_key);
    kfs_wipe(pass, sizeof(pass));
    if (st == KFS_OK)
        st = kfs_block_keys_derive(volume_key, &keys);
    kfs_wipe(volume_key, sizeof(volume_key));
    if (st != KFS_OK) {
        fprintf(stderr, "kfs-mkvol: %s\n", kfs_strerror(st));
        goto out;
    }

    /* Format the root before publishing the header, so a store with a
     * header always holds a mountable volume. */
    kfs_cipher_local(&cipher, &keys);
    memset(&fo, 0, sizeof(fo));
    fo.block_size = block_size;
    fo.cache_bytes = 16ull * block_size;
    fo.root_uid = uid;
    fo.root_gid = gid;
    st = kfs_blockio_init(&io, &cipher, backend);
    if (st == KFS_OK) {
        st = kfs_fs_open(&io, &fo, &fs);
        if (st == KFS_OK && kfs_fs_close(fs) != 0)
            st = KFS_E_IO;
        kfs_blockio_destroy(&io);
    }
    if (st == KFS_OK)
        st = kfs_backend_put(backend, KFS_BID_VOLUME_HEADER, hdr, sizeof(hdr));
    if (st != KFS_OK) {
        fprintf(stderr, "kfs-mkvol: formatting failed: %s\n", kfs_strerror(st));
        goto out;
    }

    printf("created volume in %s (block size %u, %u KDF iterations, root owned by %u:%u)\n",
           store, block_size, iterations, uid, gid);
    rc = 0;
out:
    kfs_wipe(&keys, sizeof(keys));
    kfs_backend_close(backend);
    return rc;
}
