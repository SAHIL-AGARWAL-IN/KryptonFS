/*
 * rpc_handshake.c - Mutual RSA-2048 authentication with ephemeral X25519
 * key agreement (see the protocol description in krypton_rpc.h).
 */
#include "krypton/krypton_rpc.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>

static const char T_LABEL[] = "kryptonfs v1 handshake";
static const char S_LABEL[] = "kryptonfs v1 server";
static const char C_LABEL[] = "kryptonfs v1 client";
static const char K_LABEL[] = "kryptonfs v1 session";

#define T_MAX   (sizeof(T_LABEL) - 1 + KFS_HELLO_REQ_SIZE + 4 + KFS_NONCE_SIZE + KFS_X25519_SIZE)
#define MSG_MAX (sizeof(C_LABEL) + T_MAX)

typedef struct ephemeral {
    EVP_PKEY *key;
    uint8_t   pub[KFS_X25519_SIZE];
} ephemeral;

static kfs_status eph_new(ephemeral *e)
{
    size_t n = KFS_X25519_SIZE;

    e->key = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (e->key == NULL || EVP_PKEY_get_raw_public_key(e->key, e->pub, &n) != 1 ||
        n != KFS_X25519_SIZE) {
        ERR_clear_error();
        return KFS_E_CRYPTO;
    }
    return KFS_OK;
}

static kfs_status eph_derive(const ephemeral *e, const uint8_t peer_pub[KFS_X25519_SIZE],
                             uint8_t shared[KFS_X25519_SIZE])
{
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, peer_pub,
                                                    KFS_X25519_SIZE);
    EVP_PKEY_CTX *ctx = peer != NULL ? EVP_PKEY_CTX_new_from_pkey(NULL, e->key, NULL) : NULL;
    size_t len = KFS_X25519_SIZE;
    uint8_t acc = 0;
    kfs_status st = KFS_E_AUTH;

    if (ctx != NULL && EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
        EVP_PKEY_derive(ctx, shared, &len) == 1 && len == KFS_X25519_SIZE) {
        /* An all-zero secret means a low-order peer point: refuse it. */
        for (size_t i = 0; i < KFS_X25519_SIZE; i++)
            acc |= shared[i];
        st = acc != 0 ? KFS_OK : KFS_E_AUTH;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    ERR_clear_error();
    return st;
}

static size_t transcript(uint8_t t[T_MAX], const uint8_t hello[KFS_HELLO_REQ_SIZE],
                         uint32_t server_id, const uint8_t nonce_s[KFS_NONCE_SIZE],
                         const uint8_t pub_s[KFS_X25519_SIZE])
{
    size_t n = 0;

    memcpy(t + n, T_LABEL, sizeof(T_LABEL) - 1);
    n += sizeof(T_LABEL) - 1;
    memcpy(t + n, hello, KFS_HELLO_REQ_SIZE);
    n += KFS_HELLO_REQ_SIZE;
    kfs_store_be32(t + n, server_id);
    n += 4;
    memcpy(t + n, nonce_s, KFS_NONCE_SIZE);
    n += KFS_NONCE_SIZE;
    memcpy(t + n, pub_s, KFS_X25519_SIZE);
    n += KFS_X25519_SIZE;
    return n;
}

static size_t labeled(uint8_t msg[MSG_MAX], const char *label, const uint8_t *t, size_t tlen)
{
    size_t l = strlen(label);

    memcpy(msg, label, l);
    memcpy(msg + l, t, tlen);
    return l + tlen;
}

static kfs_status sign_labeled(const kfs_identity *id, const char *label, const uint8_t *t,
                               size_t tlen, uint8_t sig[KFS_RSA_SIG_SIZE])
{
    uint8_t msg[MSG_MAX];

    return kfs_identity_sign(id, msg, labeled(msg, label, t, tlen), sig);
}

static kfs_status verify_labeled(const kfs_identity *id, const char *label, const uint8_t *t,
                                 size_t tlen, const uint8_t sig[KFS_RSA_SIG_SIZE])
{
    uint8_t msg[MSG_MAX];

    return kfs_identity_verify(id, msg, labeled(msg, label, t, tlen), sig);
}

static kfs_status session_keys(kfs_conn *c, const uint8_t shared[KFS_X25519_SIZE],
                               const uint8_t *t, size_t tlen, bool client)
{
    uint8_t th[32], okm[2 * KFS_KEY_SIZE];
    unsigned th_len = 0;
    kfs_status st = KFS_E_CRYPTO;

    if (EVP_Digest(t, tlen, th, &th_len, EVP_sha256(), NULL) == 1 && th_len == sizeof(th))
        st = kfs_hkdf_sha256(shared, KFS_X25519_SIZE, th, sizeof(th),
                             (const uint8_t *)K_LABEL, sizeof(K_LABEL) - 1, okm, sizeof(okm));
    if (st == KFS_OK) {
        memcpy(client ? c->key_tx : c->key_rx, okm, KFS_KEY_SIZE);              /* c2s */
        memcpy(client ? c->key_rx : c->key_tx, okm + KFS_KEY_SIZE, KFS_KEY_SIZE); /* s2c */
    }
    kfs_wipe(okm, sizeof(okm));
    return st;
}

kfs_status kfs_conn_handshake_client(kfs_conn *c, const kfs_identity *self,
                                     uint32_t self_id, const kfs_identity *server,
                                     uint32_t server_id)
{
    uint8_t hello[KFS_HELLO_REQ_SIZE], t[T_MAX], sig[KFS_RSA_SIG_SIZE], shared[KFS_X25519_SIZE];
    ephemeral e = { NULL, { 0 } };
    kfs_frame_hdr hdr;
    const uint8_t *p;
    kfs_buf part;
    size_t tlen;
    kfs_status st;

    st = eph_new(&e);
    kfs_store_be32(hello, self_id);
    if (st == KFS_OK)
        st = kfs_random_bytes(hello + 4, KFS_NONCE_SIZE);
    memcpy(hello + 4 + KFS_NONCE_SIZE, e.pub, KFS_X25519_SIZE);
    part = (kfs_buf){ hello, sizeof(hello) };
    if (st == KFS_OK)
        st = kfs_conn_send(c, KFS_OP_HELLO, 0, &part, 1);
    if (st == KFS_OK)
        st = kfs_conn_recv(c, &hdr, &p);
    if (st != KFS_OK)
        goto out;

    if (hdr.opcode != (KFS_OP_HELLO | KFS_OP_REPLY) || hdr.payload_len != KFS_HELLO_REP_SIZE) {
        st = KFS_E_PROTO;
        goto out;
    }
    /* status | server_id | nonce_s | x25519_s | sig_s */
    if (kfs_load_be32(p) != KFS_OK || kfs_load_be32(p + 4) != server_id) {
        st = KFS_E_AUTH; /* answered by a node other than the one we dialled */
        goto out;
    }
    tlen = transcript(t, hello, server_id, p + 8, p + 8 + KFS_NONCE_SIZE);
    st = verify_labeled(server, S_LABEL, t, tlen, p + 8 + KFS_NONCE_SIZE + KFS_X25519_SIZE);
    if (st == KFS_OK)
        st = eph_derive(&e, p + 8 + KFS_NONCE_SIZE, shared);
    if (st == KFS_OK)
        st = session_keys(c, shared, t, tlen, true);
    if (st == KFS_OK)
        st = sign_labeled(self, C_LABEL, t, tlen, sig);
    part = (kfs_buf){ sig, sizeof(sig) };
    if (st == KFS_OK)
        st = kfs_conn_send(c, KFS_OP_AUTH, 0, &part, 1);
    if (st != KFS_OK)
        goto out;

    /* The server's reply is the first MAC'd frame: key confirmation. */
    c->mac_rx = true;
    st = kfs_conn_recv(c, &hdr, &p);
    if (st == KFS_OK && (hdr.opcode != (KFS_OP_AUTH | KFS_OP_REPLY) || hdr.payload_len != 4 ||
                         kfs_load_be32(p) != KFS_OK))
        st = KFS_E_AUTH;
    if (st == KFS_OK) {
        c->mac_tx = true;
        c->peer_id = server_id;
    }
out:
    kfs_wipe(shared, sizeof(shared));
    EVP_PKEY_free(e.key);
    if (st != KFS_OK)
        c->mac_rx = c->mac_tx = false;
    return st;
}

kfs_status kfs_conn_handshake_server(kfs_conn *c, const kfs_identity *self,
                                     uint32_t self_id, const char *trusted_dir)
{
    uint8_t hello[KFS_HELLO_REQ_SIZE], t[T_MAX], sig[KFS_RSA_SIG_SIZE], shared[KFS_X25519_SIZE];
    uint8_t nonce_s[KFS_NONCE_SIZE], id_be[4];
    ephemeral e = { NULL, { 0 } };
    kfs_identity *client = NULL;
    kfs_frame_hdr hdr;
    const uint8_t *p;
    uint32_t client_id;
    size_t tlen;
    kfs_status st;

    st = kfs_conn_recv(c, &hdr, &p);
    if (st != KFS_OK)
        goto out;
    if (hdr.opcode != KFS_OP_HELLO || hdr.payload_len != KFS_HELLO_REQ_SIZE) {
        st = KFS_E_PROTO;
        goto out;
    }
    memcpy(hello, p, sizeof(hello));
    client_id = kfs_load_be32(hello);
    /* Unknown identities are dropped without an answer. */
    if (client_id == 0 ||
        kfs_identity_load_peer(trusted_dir, client_id, &client, NULL, 0) != KFS_OK) {
        st = KFS_E_AUTH;
        goto out;
    }

    st = eph_new(&e);
    if (st == KFS_OK)
        st = kfs_random_bytes(nonce_s, sizeof(nonce_s));
    tlen = transcript(t, hello, self_id, nonce_s, e.pub);
    if (st == KFS_OK)
        st = sign_labeled(self, S_LABEL, t, tlen, sig);
    if (st == KFS_OK) {
        kfs_buf body[4] = { { id_be, 4 }, { nonce_s, KFS_NONCE_SIZE },
                            { e.pub, KFS_X25519_SIZE }, { sig, KFS_RSA_SIG_SIZE } };

        kfs_store_be32(id_be, self_id);
        st = kfs_conn_reply(c, KFS_OP_HELLO, 0, KFS_OK, body, 4);
    }
    if (st == KFS_OK)
        st = kfs_conn_recv(c, &hdr, &p);
    if (st != KFS_OK)
        goto out;
    if (hdr.opcode != KFS_OP_AUTH || hdr.payload_len != KFS_RSA_SIG_SIZE) {
        st = KFS_E_PROTO;
        goto out;
    }
    st = verify_labeled(client, C_LABEL, t, tlen, p);
    if (st == KFS_OK)
        st = eph_derive(&e, hello + 4 + KFS_NONCE_SIZE, shared);
    if (st == KFS_OK)
        st = session_keys(c, shared, t, tlen, false);
    if (st != KFS_OK)
        goto out;

    c->mac_tx = true;
    st = kfs_conn_reply(c, KFS_OP_AUTH, 0, KFS_OK, NULL, 0);
    if (st == KFS_OK) {
        c->mac_rx = true;
        c->peer_id = client_id;
    }
out:
    kfs_wipe(shared, sizeof(shared));
    EVP_PKEY_free(e.key);
    kfs_identity_free(client);
    if (st != KFS_OK)
        c->mac_rx = c->mac_tx = false;
    return st;
}
