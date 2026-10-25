/*
 * krypton_crypto.c - OpenSSL 3 implementation of krypton_crypto.h.
 */
#include "krypton/krypton_crypto.h"

#include <limits.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

/* HKDF labels: one per derived key, versioned so a future scheme cannot
 * collide with this one. */
static const char LABEL_DATA[] = "kryptonfs v1 block data key";
static const char LABEL_MAC[] = "kryptonfs v1 block mac key";

kfs_status kfs_random_bytes(uint8_t *buf, size_t len)
{
    if (len > INT_MAX)
        return KFS_E_INVAL;
    return RAND_bytes(buf, (int)len) == 1 ? KFS_OK : KFS_E_CRYPTO;
}

void kfs_wipe(void *buf, size_t len)
{
    OPENSSL_cleanse(buf, len);
}

bool kfs_ct_equal(const void *a, const void *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

kfs_status kfs_pbkdf2_sha256(const char *pass, size_t pass_len,
                             const uint8_t *salt, size_t salt_len,
                             uint32_t iterations,
                             uint8_t *out, size_t out_len)
{
    if (pass_len > INT_MAX || salt_len > INT_MAX || out_len > INT_MAX ||
        iterations == 0 || iterations > INT_MAX)
        return KFS_E_INVAL;
    return PKCS5_PBKDF2_HMAC(pass, (int)pass_len, salt, (int)salt_len,
                             (int)iterations, EVP_sha256(),
                             (int)out_len, out) == 1 ? KFS_OK : KFS_E_CRYPTO;
}

kfs_status kfs_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                           const uint8_t *salt, size_t salt_len,
                           const uint8_t *info, size_t info_len,
                           uint8_t *out, size_t out_len)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_HKDF, NULL);
    EVP_KDF_CTX *ctx = kdf != NULL ? EVP_KDF_CTX_new(kdf) : NULL;
    OSSL_PARAM params[5], *p = params;
    kfs_status st = KFS_E_CRYPTO;

    if (ctx == NULL)
        goto out;

    /* OSSL_PARAM takes non-const pointers but only reads these inputs. */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)(uintptr_t)ikm, ikm_len);
    if (salt_len > 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)(uintptr_t)salt, salt_len);
    if (info_len > 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)(uintptr_t)info, info_len);
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, out, out_len, params) == 1)
        st = KFS_OK;
out:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return st;
}

kfs_status kfs_block_keys_derive(const uint8_t volume_key[KFS_KEY_SIZE],
                                 kfs_block_keys *keys)
{
    kfs_status st;

    st = kfs_hkdf_sha256(volume_key, KFS_KEY_SIZE, NULL, 0,
                         (const uint8_t *)LABEL_DATA, sizeof(LABEL_DATA) - 1,
                         keys->data_key, KFS_KEY_SIZE);
    if (st == KFS_OK)
        st = kfs_hkdf_sha256(volume_key, KFS_KEY_SIZE, NULL, 0,
                             (const uint8_t *)LABEL_MAC, sizeof(LABEL_MAC) - 1,
                             keys->mac_key, KFS_KEY_SIZE);
    if (st != KFS_OK)
        kfs_wipe(keys, sizeof(*keys));
    return st;
}

kfs_status kfs_hmac_sha256(const uint8_t *key, size_t key_len,
                           const kfs_buf *parts, size_t nparts,
                           uint8_t out[KFS_HMAC_SIZE])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    EVP_MAC_CTX *ctx = mac != NULL ? EVP_MAC_CTX_new(mac) : NULL;
    OSSL_PARAM params[2];
    size_t out_len = 0;
    kfs_status st = KFS_E_CRYPTO;

    if (ctx == NULL)
        goto out;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
        goto out;
    for (size_t i = 0; i < nparts; i++) {
        if (parts[i].len > 0 && EVP_MAC_update(ctx, parts[i].data, parts[i].len) != 1)
            goto out;
    }
    if (EVP_MAC_final(ctx, out, &out_len, KFS_HMAC_SIZE) == 1 && out_len == KFS_HMAC_SIZE)
        st = KFS_OK;
out:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return st;
}

/* AES-256-CTR is its own inverse: the same call encrypts and decrypts. */
static kfs_status aes256_ctr_xor(const uint8_t key[KFS_KEY_SIZE],
                                 const uint8_t iv[KFS_IV_SIZE],
                                 uint8_t *data, size_t len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0;
    kfs_status st = KFS_E_CRYPTO;

    if (ctx != NULL &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) == 1 &&
        EVP_EncryptUpdate(ctx, data, &out_len, data, (int)len) == 1 &&
        (size_t)out_len == len)
        st = KFS_OK;
    EVP_CIPHER_CTX_free(ctx);
    return st;
}

static kfs_status block_tag(const kfs_block_keys *keys, uint64_t block_id,
                            const kfs_envelope_hdr *env,
                            const uint8_t *data, size_t len,
                            uint8_t tag[KFS_HMAC_SIZE])
{
    uint8_t id_be[8], env_wire[KFS_ENVELOPE_HDR_SIZE];
    kfs_buf parts[3];

    kfs_store_be64(id_be, block_id);
    kfs_envelope_hdr_encode(env, env_wire);
    parts[0] = (kfs_buf){ id_be, sizeof(id_be) };
    parts[1] = (kfs_buf){ env_wire, KFS_ENVELOPE_OFF_TAG }; /* generation || iv */
    parts[2] = (kfs_buf){ data, len };
    return kfs_hmac_sha256(keys->mac_key, KFS_KEY_SIZE, parts, 3, tag);
}

kfs_status kfs_block_seal(const kfs_block_keys *keys, uint64_t block_id,
                          uint64_t generation, uint8_t *data, size_t len,
                          kfs_envelope_hdr *env)
{
    kfs_status st;

    if (len > KFS_BLOCK_SIZE_MAX)
        return KFS_E_INVAL;

    env->generation = generation;
    st = kfs_random_bytes(env->iv, KFS_IV_SIZE);
    if (st == KFS_OK)
        st = aes256_ctr_xor(keys->data_key, env->iv, data, len);
    if (st == KFS_OK)
        st = block_tag(keys, block_id, env, data, len, env->tag);
    return st;
}

kfs_status kfs_block_open(const kfs_block_keys *keys, uint64_t block_id,
                          const kfs_envelope_hdr *env,
                          uint8_t *data, size_t len)
{
    uint8_t tag[KFS_HMAC_SIZE];
    kfs_status st;

    if (len > KFS_BLOCK_SIZE_MAX)
        return KFS_E_INVAL;

    st = block_tag(keys, block_id, env, data, len, tag);
    if (st != KFS_OK)
        return st;
    if (!kfs_ct_equal(tag, env->tag, KFS_HMAC_SIZE))
        return KFS_E_AUTH;
    return aes256_ctr_xor(keys->data_key, env->iv, data, len);
}

kfs_status kfs_frame_mac(const uint8_t session_key[KFS_KEY_SIZE],
                         const kfs_frame_hdr *hdr, uint64_t seq,
                         const uint8_t *payload, uint8_t out[KFS_HMAC_SIZE])
{
    uint8_t prefix[KFS_FRAME_MAC_PREFIX_SIZE];
    kfs_buf parts[2];

    if (hdr->payload_len > KFS_FRAME_MAX_PAYLOAD ||
        (hdr->payload_len > 0 && payload == NULL))
        return KFS_E_INVAL;

    kfs_frame_mac_prefix(hdr, seq, prefix);
    parts[0] = (kfs_buf){ prefix, sizeof(prefix) };
    parts[1] = (kfs_buf){ payload, hdr->payload_len };
    return kfs_hmac_sha256(session_key, KFS_KEY_SIZE, parts, 2, out);
}

kfs_status kfs_frame_verify(const uint8_t session_key[KFS_KEY_SIZE],
                            const kfs_frame_hdr *hdr, uint64_t seq,
                            const uint8_t *payload)
{
    uint8_t mac[KFS_HMAC_SIZE];
    kfs_status st = kfs_frame_mac(session_key, hdr, seq, payload, mac);

    if (st != KFS_OK)
        return st;
    return kfs_ct_equal(mac, hdr->hmac, KFS_HMAC_SIZE) ? KFS_OK : KFS_E_AUTH;
}

kfs_status kfs_heartbeat_sign(const uint8_t cluster_key[KFS_KEY_SIZE],
                              uint8_t wire[KFS_HB_SIZE])
{
    kfs_buf part = { wire, KFS_HB_OFF_HMAC };

    return kfs_hmac_sha256(cluster_key, KFS_KEY_SIZE, &part, 1,
                           wire + KFS_HB_OFF_HMAC);
}

kfs_status kfs_heartbeat_verify(const uint8_t cluster_key[KFS_KEY_SIZE],
                                const uint8_t wire[KFS_HB_SIZE])
{
    uint8_t mac[KFS_HMAC_SIZE];
    kfs_buf part = { wire, KFS_HB_OFF_HMAC };
    kfs_status st = kfs_hmac_sha256(cluster_key, KFS_KEY_SIZE, &part, 1, mac);

    if (st != KFS_OK)
        return st;
    return kfs_ct_equal(mac, wire + KFS_HB_OFF_HMAC, KFS_HMAC_SIZE) ? KFS_OK : KFS_E_AUTH;
}
