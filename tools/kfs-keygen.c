/*
 * kfs-keygen - Create KryptonFS key material.
 *
 *   kfs-keygen node <node_id> <dir>
 *       Writes <dir>/node.key.pem (0600) and <dir>/<node_id>.pub.pem, and
 *       prints the public key fingerprint. Copy the .pub.pem into every
 *       peer's [crypto] trusted_keys directory.
 *
 *   kfs-keygen cluster <path>
 *       Writes a random 32-byte heartbeat key (0600). Every host in the
 *       cluster needs the same file at [crypto] cluster_key.
 *
 * Existing files are never overwritten.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "krypton/krypton_crypto.h"
#include "krypton/krypton_keystore.h"

static int usage(void)
{
    fprintf(stderr,
            "usage: kfs-keygen node <node_id> <dir>\n"
            "       kfs-keygen cluster <path>\n");
    return 2;
}

static void print_hex(const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x%s", b[i], i + 1 < len && i % 2 == 1 ? ":" : "");
    printf("\n");
}

static int make_node(const char *id_str, const char *dir)
{
    char key_path[KFS_PATH_MAX + 32], pub_path[KFS_PATH_MAX + 32], *end;
    uint8_t fp[KFS_FINGERPRINT_SIZE];
    unsigned long long id;
    kfs_identity *ident = NULL;
    kfs_status st;

    errno = 0;
    id = strtoull(id_str, &end, 10);
    if (id_str[0] < '0' || id_str[0] > '9' || errno != 0 || *end != '\0' ||
        id == 0 || id > UINT32_MAX) {
        fprintf(stderr, "kfs-keygen: node_id must be 1..%u\n", UINT32_MAX);
        return 2;
    }
    if (snprintf(key_path, sizeof(key_path), "%s/node.key.pem", dir) >= (int)sizeof(key_path) ||
        snprintf(pub_path, sizeof(pub_path), "%s/%llu.pub.pem", dir, id) >= (int)sizeof(pub_path)) {
        fprintf(stderr, "kfs-keygen: directory path too long\n");
        return 2;
    }

    st = kfs_identity_generate(&ident);
    if (st != KFS_OK) {
        fprintf(stderr, "kfs-keygen: key generation failed: %s\n", kfs_strerror(st));
        return 1;
    }
    st = kfs_identity_save_private(ident, key_path);
    if (st != KFS_OK) {
        fprintf(stderr, "kfs-keygen: cannot create %s (exists or not writable)\n", key_path);
        kfs_identity_free(ident);
        return 1;
    }
    st = kfs_identity_save_public(ident, pub_path);
    if (st != KFS_OK) {
        fprintf(stderr, "kfs-keygen: cannot create %s (exists or not writable)\n", pub_path);
        kfs_identity_free(ident);
        return 1;
    }
    st = kfs_identity_fingerprint(ident, fp);
    kfs_identity_free(ident);
    if (st != KFS_OK) {
        fprintf(stderr, "kfs-keygen: fingerprint failed: %s\n", kfs_strerror(st));
        return 1;
    }

    printf("private key: %s\npublic key:  %s\nfingerprint: ", key_path, pub_path);
    print_hex(fp, sizeof(fp));
    return 0;
}

static int make_cluster_key(const char *path)
{
    uint8_t key[KFS_KEY_SIZE];
    kfs_status st = kfs_random_bytes(key, sizeof(key));

    if (st == KFS_OK)
        st = kfs_secret_write(path, key, sizeof(key));
    kfs_wipe(key, sizeof(key));
    if (st != KFS_OK) {
        fprintf(stderr, "kfs-keygen: cannot create %s: %s\n", path, kfs_strerror(st));
        return 1;
    }
    printf("cluster key: %s\n", path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "node") == 0)
        return make_node(argv[2], argv[3]);
    if (argc == 3 && strcmp(argv[1], "cluster") == 0)
        return make_cluster_key(argv[2]);
    return usage();
}
