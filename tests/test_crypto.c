/*
 * test_crypto.c - Primitives against published test vectors, plus block
 * sealing, tamper detection and frame / heartbeat authentication.
 */
#include "krypton/krypton_crypto.h"

#include <stdlib.h>

#include "kfs_test.h"

/* Parses a hex string into out; returns the byte count. */
static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;

    while (hex[0] != '\0' && hex[1] != '\0' && n < cap) {
        unsigned v;
        if (sscanf(hex, "%2x", &v) != 1)
            break;
        out[n++] = (uint8_t)v;
        hex += 2;
    }
    return n;
}

static void check_hex(const uint8_t *got, size_t len, const char *expect_hex)
{
    uint8_t expect[128];
    size_t n = unhex(expect_hex, expect, sizeof(expect));

    CHECK_EQ(n, len);
    CHECK(memcmp(got, expect, len) == 0);
}

/* RFC 4231 test case 2. */
static void test_hmac_rfc4231(void)
{
    static const char data[] = "what do ya want for nothing?";
    kfs_buf parts[2] = { { data, 10 }, { data + 10, sizeof(data) - 1 - 10 } };
    uint8_t mac[KFS_HMAC_SIZE];

    CHECK_EQ(kfs_hmac_sha256((const uint8_t *)"Jefe", 4, parts, 2, mac), KFS_OK);
    check_hex(mac, sizeof(mac),
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

/* RFC 5869 test case 1. */
static void test_hkdf_rfc5869(void)
{
    uint8_t ikm[22], salt[13], info[10], okm[42];

    memset(ikm, 0x0b, sizeof(ikm));
    for (size_t i = 0; i < sizeof(salt); i++)
        salt[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(info); i++)
        info[i] = (uint8_t)(0xf0 + i);

    CHECK_EQ(kfs_hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt),
                             info, sizeof(info), okm, sizeof(okm)), KFS_OK);
    check_hex(okm, sizeof(okm),
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
              "34007208d5b887185865");
}

/* RFC 7914 section 11: PBKDF2-HMAC-SHA256, P="passwd", S="salt", c=1. */
static void test_pbkdf2_rfc7914(void)
{
    uint8_t dk[64];

    CHECK_EQ(kfs_pbkdf2_sha256("passwd", 6, (const uint8_t *)"salt", 4, 1,
                               dk, sizeof(dk)), KFS_OK);
    check_hex(dk, sizeof(dk),
              "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
              "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");
    CHECK_EQ(kfs_pbkdf2_sha256("p", 1, (const uint8_t *)"s", 1, 0, dk, 32), KFS_E_INVAL);
}

/* NIST SP 800-38A F.5.5 (CTR-AES256.Encrypt, first block), exercised
 * through seal/open by forcing the vector's key and IV. */
static void test_aes256_ctr_nist(void)
{
    kfs_block_keys keys;
    kfs_envelope_hdr env;
    uint8_t block[16];

    memset(&keys, 0, sizeof(keys));
    unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
          keys.data_key, KFS_KEY_SIZE);
    unhex("6bc1bee22e409f96e93d7e117393172a", block, sizeof(block));

    /* seal picks a random IV, so encrypt via open: CTR is symmetric and
     * open decrypts only after a tag computed over the same bytes. */
    memset(&env, 0, sizeof(env));
    unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", env.iv, KFS_IV_SIZE);
    {
        uint8_t id_be[8], env_wire[KFS_ENVELOPE_HDR_SIZE];
        kfs_buf parts[3];

        kfs_store_be64(id_be, 1);
        kfs_envelope_hdr_encode(&env, env_wire);
        parts[0] = (kfs_buf){ id_be, 8 };
        parts[1] = (kfs_buf){ env_wire, KFS_ENVELOPE_OFF_TAG };
        parts[2] = (kfs_buf){ block, sizeof(block) };
        CHECK_EQ(kfs_hmac_sha256(keys.mac_key, KFS_KEY_SIZE, parts, 3, env.tag), KFS_OK);
    }
    CHECK_EQ(kfs_block_open(&keys, 1, &env, block, sizeof(block)), KFS_OK);
    check_hex(block, sizeof(block), "601ec313775789a5b7a7f504bbf3d228");
}

static void make_keys(kfs_block_keys *keys)
{
    uint8_t volume_key[KFS_KEY_SIZE];

    memset(volume_key, 0x42, sizeof(volume_key));
    CHECK_EQ(kfs_block_keys_derive(volume_key, keys), KFS_OK);
}

static void test_key_separation(void)
{
    kfs_block_keys keys, again;

    make_keys(&keys);
    make_keys(&again);
    CHECK(memcmp(keys.data_key, keys.mac_key, KFS_KEY_SIZE) != 0);
    CHECK(memcmp(&keys, &again, sizeof(keys)) == 0); /* deterministic */
}

static void test_seal_open_roundtrip(void)
{
    kfs_block_keys keys;
    kfs_envelope_hdr env;
    uint8_t *plain = malloc(KFS_BLOCK_SIZE_DEFAULT);
    uint8_t *buf = malloc(KFS_BLOCK_SIZE_DEFAULT);

    CHECK(plain != NULL && buf != NULL);
    if (plain == NULL || buf == NULL)
        goto out;
    make_keys(&keys);
    for (size_t i = 0; i < KFS_BLOCK_SIZE_DEFAULT; i++)
        plain[i] = (uint8_t)(i * 7);
    memcpy(buf, plain, KFS_BLOCK_SIZE_DEFAULT);

    CHECK_EQ(kfs_block_seal(&keys, 99, 5, buf, KFS_BLOCK_SIZE_DEFAULT, &env), KFS_OK);
    CHECK_EQ(env.generation, 5);
    CHECK(memcmp(buf, plain, KFS_BLOCK_SIZE_DEFAULT) != 0);
    CHECK_EQ(kfs_block_open(&keys, 99, &env, buf, KFS_BLOCK_SIZE_DEFAULT), KFS_OK);
    CHECK(memcmp(buf, plain, KFS_BLOCK_SIZE_DEFAULT) == 0);
out:
    free(plain);
    free(buf);
}

static void test_fresh_iv_per_seal(void)
{
    kfs_block_keys keys;
    kfs_envelope_hdr a, b;
    uint8_t x[64] = { 0 }, y[64] = { 0 };

    make_keys(&keys);
    CHECK_EQ(kfs_block_seal(&keys, 1, 1, x, sizeof(x), &a), KFS_OK);
    CHECK_EQ(kfs_block_seal(&keys, 1, 1, y, sizeof(y), &b), KFS_OK);
    CHECK(memcmp(a.iv, b.iv, KFS_IV_SIZE) != 0);
    CHECK(memcmp(x, y, sizeof(x)) != 0); /* same plaintext, different keystream */
}

static void test_open_rejects_tampering(void)
{
    kfs_block_keys keys;
    kfs_envelope_hdr env, bad;
    uint8_t buf[256], sealed[256];

    make_keys(&keys);
    memset(buf, 'A', sizeof(buf));
    CHECK_EQ(kfs_block_seal(&keys, 7, 3, buf, sizeof(buf), &env), KFS_OK);
    memcpy(sealed, buf, sizeof(buf));

    buf[100] ^= 0x01; /* flipped ciphertext bit */
    CHECK_EQ(kfs_block_open(&keys, 7, &env, buf, sizeof(buf)), KFS_E_AUTH);
    CHECK(memcmp(buf + 101, sealed + 101, sizeof(buf) - 101) == 0); /* untouched */
    memcpy(buf, sealed, sizeof(buf));

    CHECK_EQ(kfs_block_open(&keys, 8, &env, buf, sizeof(buf)), KFS_E_AUTH); /* swapped block */

    bad = env;
    bad.generation = 2; /* rolled-back generation number */
    CHECK_EQ(kfs_block_open(&keys, 7, &bad, buf, sizeof(buf)), KFS_E_AUTH);

    bad = env;
    bad.iv[0] ^= 0x80;
    CHECK_EQ(kfs_block_open(&keys, 7, &bad, buf, sizeof(buf)), KFS_E_AUTH);

    bad = env;
    bad.tag[31] ^= 0x01;
    CHECK_EQ(kfs_block_open(&keys, 7, &bad, buf, sizeof(buf)), KFS_E_AUTH);

    CHECK_EQ(kfs_block_open(&keys, 7, &env, buf, sizeof(buf) - 1), KFS_E_AUTH); /* truncated */
    CHECK_EQ(kfs_block_open(&keys, 7, &env, buf, sizeof(buf)), KFS_OK);
}

static void test_frame_mac(void)
{
    uint8_t key[KFS_KEY_SIZE], payload[16];
    kfs_frame_hdr hdr = { .opcode = KFS_OP_BLOCK_WRITE, .block_id = 5, .payload_len = sizeof(payload) };

    memset(key, 0x11, sizeof(key));
    memset(payload, 0x22, sizeof(payload));
    CHECK_EQ(kfs_frame_mac(key, &hdr, 0, payload, hdr.hmac), KFS_OK);
    CHECK_EQ(kfs_frame_verify(key, &hdr, 0, payload), KFS_OK);

    CHECK_EQ(kfs_frame_verify(key, &hdr, 1, payload), KFS_E_AUTH); /* replayed or reordered */
    payload[0] ^= 1;
    CHECK_EQ(kfs_frame_verify(key, &hdr, 0, payload), KFS_E_AUTH);
    payload[0] ^= 1;
    hdr.block_id = 6;
    CHECK_EQ(kfs_frame_verify(key, &hdr, 0, payload), KFS_E_AUTH);
    hdr.block_id = 5;
    key[0] ^= 1;
    CHECK_EQ(kfs_frame_verify(key, &hdr, 0, payload), KFS_E_AUTH);

    hdr.payload_len = 4;
    CHECK_EQ(kfs_frame_mac(key, &hdr, 0, NULL, hdr.hmac), KFS_E_INVAL);
    hdr.payload_len = 0;
    CHECK_EQ(kfs_frame_mac(key, &hdr, 0, NULL, hdr.hmac), KFS_OK);
}

static void test_heartbeat_mac(void)
{
    uint8_t key[KFS_KEY_SIZE], wire[KFS_HB_SIZE];
    kfs_heartbeat hb = { .type = KFS_HB_BEAT, .state = KFS_NODE_UP, .node_id = 3, .seq = 10,
                         .disk_total = 100, .disk_used = 50 };

    memset(key, 0x33, sizeof(key));
    kfs_heartbeat_encode(&hb, wire);
    CHECK_EQ(kfs_heartbeat_sign(key, wire), KFS_OK);
    CHECK_EQ(kfs_heartbeat_verify(key, wire), KFS_OK);

    wire[KFS_HB_OFF_STATE] = KFS_NODE_DRAINING; /* forged state change */
    CHECK_EQ(kfs_heartbeat_verify(key, wire), KFS_E_AUTH);
}

static void test_helpers(void)
{
    uint8_t a[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, b[8];

    memcpy(b, a, sizeof(a));
    CHECK(kfs_ct_equal(a, b, sizeof(a)));
    b[7] = 0;
    CHECK(!kfs_ct_equal(a, b, sizeof(a)));
    kfs_wipe(a, sizeof(a));
    for (size_t i = 0; i < sizeof(a); i++)
        CHECK_EQ(a[i], 0);
}

int main(void)
{
    RUN(test_hmac_rfc4231);
    RUN(test_hkdf_rfc5869);
    RUN(test_pbkdf2_rfc7914);
    RUN(test_aes256_ctr_nist);
    RUN(test_key_separation);
    RUN(test_seal_open_roundtrip);
    RUN(test_fresh_iv_per_seal);
    RUN(test_open_rejects_tampering);
    RUN(test_frame_mac);
    RUN(test_heartbeat_mac);
    RUN(test_helpers);
    TEST_EXIT();
}
