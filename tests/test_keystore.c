/*
 * test_keystore.c - RSA-2048 identities, pinned peer lookup and secret
 * files. Writes scratch files under KFS_TEST_TMPDIR.
 */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L /* chmod */
#endif

#include "krypton/krypton_keystore.h"

#include <stdio.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "kfs_test.h"

static kfs_identity *alice, *bob;

static const char *tmp(const char *name)
{
    static char path[KFS_PATH_MAX + 64];

    snprintf(path, sizeof(path), "%s/%s", KFS_TEST_TMPDIR, name);
    remove(path);
    return path;
}

static void test_sign_verify(void)
{
    static const uint8_t msg[] = "client nonce || server nonce";
    uint8_t sig[KFS_RSA_SIG_SIZE], bad[sizeof(msg)];

    CHECK_EQ(kfs_identity_sign(alice, msg, sizeof(msg), sig), KFS_OK);
    CHECK_EQ(kfs_identity_verify(alice, msg, sizeof(msg), sig), KFS_OK);

    memcpy(bad, msg, sizeof(msg));
    bad[0] ^= 1;
    CHECK_EQ(kfs_identity_verify(alice, bad, sizeof(bad), sig), KFS_E_AUTH);
    CHECK_EQ(kfs_identity_verify(bob, msg, sizeof(msg), sig), KFS_E_AUTH);
    sig[100] ^= 1;
    CHECK_EQ(kfs_identity_verify(alice, msg, sizeof(msg), sig), KFS_E_AUTH);
}

static void test_save_load_roundtrip(void)
{
    static const uint8_t msg[] = "transcript";
    char key_path[KFS_PATH_MAX + 64], pub_path[KFS_PATH_MAX + 64], err[256];
    uint8_t fp_a[KFS_FINGERPRINT_SIZE], fp_b[KFS_FINGERPRINT_SIZE], sig[KFS_RSA_SIG_SIZE];
    kfs_identity *priv = NULL, *pub = NULL;

    snprintf(key_path, sizeof(key_path), "%s", tmp("alice.key.pem"));
    snprintf(pub_path, sizeof(pub_path), "%s", tmp("alice.pub.pem"));
    CHECK_EQ(kfs_identity_save_private(alice, key_path), KFS_OK);
    CHECK_EQ(kfs_identity_save_public(alice, pub_path), KFS_OK);
    CHECK_EQ(kfs_identity_save_private(alice, key_path), KFS_E_IO); /* never overwrite */

    CHECK_EQ(kfs_identity_load_private(key_path, &priv, err, sizeof(err)), KFS_OK);
    CHECK_EQ(kfs_identity_load_public(pub_path, &pub, err, sizeof(err)), KFS_OK);
    if (priv == NULL || pub == NULL)
        goto out;

    CHECK_EQ(kfs_identity_fingerprint(alice, fp_a), KFS_OK);
    CHECK_EQ(kfs_identity_fingerprint(pub, fp_b), KFS_OK);
    CHECK(memcmp(fp_a, fp_b, sizeof(fp_a)) == 0);

    CHECK_EQ(kfs_identity_sign(priv, msg, sizeof(msg), sig), KFS_OK);
    CHECK_EQ(kfs_identity_verify(pub, msg, sizeof(msg), sig), KFS_OK);
    CHECK_EQ(kfs_identity_sign(pub, msg, sizeof(msg), sig), KFS_E_INVAL);
    CHECK_EQ(kfs_identity_save_private(pub, tmp("pub-as-priv.pem")), KFS_E_INVAL);
out:
    kfs_identity_free(priv);
    kfs_identity_free(pub);
}

static void test_peer_lookup(void)
{
    kfs_identity *peer = NULL;
    char err[256] = "";

    CHECK_EQ(kfs_identity_save_public(bob, tmp("42.pub.pem")), KFS_OK);
    CHECK_EQ(kfs_identity_load_peer(KFS_TEST_TMPDIR, 42, &peer, err, sizeof(err)), KFS_OK);
    kfs_identity_free(peer);

    tmp("43.pub.pem");
    CHECK_EQ(kfs_identity_load_peer(KFS_TEST_TMPDIR, 43, &peer, err, sizeof(err)), KFS_E_IO);
    CHECK(strstr(err, "43.pub.pem") != NULL);
}

static void test_rejects_wrong_keys(void)
{
    const char *path;
    kfs_identity *id = NULL;
    char err[256] = "";
    EVP_PKEY *weak;
    FILE *fp;

    /* RSA-1024 is well-formed but below policy. */
    path = tmp("weak.pub.pem");
    weak = EVP_RSA_gen(1024);
    CHECK(weak != NULL);
    fp = fopen(path, "wb");
    CHECK(fp != NULL);
    if (weak != NULL && fp != NULL)
        CHECK_EQ(PEM_write_PUBKEY(fp, weak), 1);
    if (fp != NULL)
        fclose(fp);
    EVP_PKEY_free(weak);
    CHECK_EQ(kfs_identity_load_public(path, &id, err, sizeof(err)), KFS_E_CRYPTO);
    CHECK(strstr(err, "not an RSA-2048 key") != NULL);

    path = tmp("garbage.pem");
    fp = fopen(path, "wb");
    CHECK(fp != NULL);
    if (fp != NULL) {
        fputs("not a key\n", fp);
        fclose(fp);
    }
    CHECK_EQ(kfs_identity_load_public(path, &id, err, sizeof(err)), KFS_E_CRYPTO);
    CHECK(strstr(err, "not an unencrypted PEM public key") != NULL);
}

static void test_private_key_permissions(void)
{
#if !defined(_WIN32)
    const char *path = tmp("loose.key.pem");
    kfs_identity *id = NULL;
    char err[256] = "";

    CHECK_EQ(kfs_identity_save_private(alice, path), KFS_OK);
    CHECK_EQ(chmod(path, 0644), 0);
    CHECK_EQ(kfs_identity_load_private(path, &id, err, sizeof(err)), KFS_E_IO);
    CHECK(strstr(err, "chmod 600") != NULL);
#endif
}

static void test_secret_files(void)
{
    uint8_t key[32], back[32], wrong[16];
    const char *path = tmp("cluster.key");
    char err[256] = "";

    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)(i * 3 + 1);
    CHECK_EQ(kfs_secret_write(path, key, sizeof(key)), KFS_OK);
    CHECK_EQ(kfs_secret_write(path, key, sizeof(key)), KFS_E_IO);
    CHECK_EQ(kfs_secret_read(path, back, sizeof(back), err, sizeof(err)), KFS_OK);
    CHECK(memcmp(key, back, sizeof(key)) == 0);
    CHECK_EQ(kfs_secret_read(path, wrong, sizeof(wrong), err, sizeof(err)), KFS_E_CONFIG);
    CHECK(strstr(err, "expected exactly 16 bytes") != NULL);
}

int main(void)
{
    if (kfs_identity_generate(&alice) != KFS_OK || kfs_identity_generate(&bob) != KFS_OK) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }
    RUN(test_sign_verify);
    RUN(test_save_load_roundtrip);
    RUN(test_peer_lookup);
    RUN(test_rejects_wrong_keys);
    RUN(test_private_key_permissions);
    RUN(test_secret_files);
    kfs_identity_free(alice);
    kfs_identity_free(bob);
    TEST_EXIT();
}
