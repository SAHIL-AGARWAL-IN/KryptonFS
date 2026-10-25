/*
 * krypton_rpc.h - Authenticated block-RPC connections (Linux).
 *
 * Frames are those of krypton_protocol.h. A connection starts with a
 * mutually authenticated handshake, then every frame in both directions
 * carries an HMAC under a per-direction session key and implicit sequence
 * number.
 *
 * Handshake
 * ---------
 *   client -> HELLO        client_id u32 | nonce_c[32] | x25519_c[32]
 *   server -> HELLO|REPLY  status u32 | server_id u32 | nonce_s[32] |
 *                          x25519_s[32] | sig_s[256]
 *   client -> AUTH         sig_c[256]
 *   server -> AUTH|REPLY   status u32                  (first MAC'd frame)
 *
 *   T     = "kryptonfs v1 handshake" || HELLO payload || server_id ||
 *           nonce_s || x25519_s
 *   sig_s = RSA-PSS(server key, "kryptonfs v1 server" || T)
 *   sig_c = RSA-PSS(client key, "kryptonfs v1 client" || T)
 *   keys  = HKDF-SHA256(X25519(eph_c, eph_s), salt = SHA-256(T),
 *                       info = "kryptonfs v1 session") -> c2s || s2c
 *
 * Both public keys are pinned: the client knows which node it dialled
 * and the server looks the client up in trusted_keys by client_id, so an
 * unknown or substituted key fails the signature check. The ephemeral
 * X25519 exchange gives forward secrecy, the distinct signature labels
 * stop a signature being reflected back, and the server's MAC'd
 * AUTH reply proves it derived the same keys.
 *
 * Request / reply payloads after the handshake (every reply starts with a
 * u32 kfs_status, then the body shown):
 *
 *   BLOCK_READ    (empty)            -> envelope bytes
 *   BLOCK_WRITE   envelope bytes     -> copies u32   (replicas now holding it)
 *   BLOCK_DELETE  (empty)            -> (empty)
 *   BLOCK_STAT    (empty)            -> size u32 | generation u64
 *   REPLICATE     envelope bytes     -> (empty)      (node to node only)
 *
 * Connections are not thread-safe; any error leaves one unusable (the
 * sequence numbers can no longer agree), so callers close and redial.
 */
#ifndef KRYPTON_RPC_H
#define KRYPTON_RPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "krypton_common.h"
#include "krypton_crypto.h"
#include "krypton_keystore.h"
#include "krypton_protocol.h"

#define KFS_NONCE_SIZE      32u
#define KFS_X25519_SIZE     32u
#define KFS_HELLO_REQ_SIZE  (4u + KFS_NONCE_SIZE + KFS_X25519_SIZE)
#define KFS_HELLO_REP_SIZE  (4u + 4u + KFS_NONCE_SIZE + KFS_X25519_SIZE + KFS_RSA_SIG_SIZE)

/* Largest object a node stores: an envelope around a maximal block. */
#define KFS_OBJECT_MAX      (KFS_ENVELOPE_HDR_SIZE + KFS_BLOCK_SIZE_MAX)

typedef struct kfs_conn {
    int      fd;
    uint32_t peer_id;       /* authenticated identity of the other end */
    bool     mac_tx;
    bool     mac_rx;
    uint8_t  key_tx[KFS_KEY_SIZE];
    uint8_t  key_rx[KFS_KEY_SIZE];
    uint64_t seq_tx;
    uint64_t seq_rx;
    uint8_t *rx;            /* one frame payload, KFS_FRAME_MAX_PAYLOAD */
    uint8_t *tx;            /* header + payload */
} kfs_conn;

/* Takes ownership of fd and applies timeout_ms to every send and recv. */
kfs_status kfs_conn_init(kfs_conn *c, int fd, uint32_t timeout_ms);
void kfs_conn_close(kfs_conn *c);

static inline bool kfs_conn_ready(const kfs_conn *c)
{
    return c->fd >= 0 && c->mac_tx && c->mac_rx;
}

kfs_status kfs_conn_handshake_client(kfs_conn *c, const kfs_identity *self,
                                     uint32_t self_id, const kfs_identity *server,
                                     uint32_t server_id);
kfs_status kfs_conn_handshake_server(kfs_conn *c, const kfs_identity *self,
                                     uint32_t self_id, const char *trusted_dir);

/* Sends one frame whose payload is the concatenation of parts. */
kfs_status kfs_conn_send(kfs_conn *c, uint16_t opcode, uint64_t block_id,
                         const kfs_buf *parts, size_t nparts);

/* Receives one frame; *payload points into the connection's buffer and
 * stays valid until the next recv. KFS_E_TIMEOUT, KFS_E_IO (closed or
 * failed), KFS_E_PROTO (malformed or out-of-phase) or KFS_E_AUTH (MAC). */
kfs_status kfs_conn_recv(kfs_conn *c, kfs_frame_hdr *hdr, const uint8_t **payload);

/* Sends a reply: status, then body. */
kfs_status kfs_conn_reply(kfs_conn *c, uint16_t request_op, uint64_t block_id,
                          kfs_status status, const kfs_buf *body, size_t nbody);

/*
 * One request/reply round trip. On KFS_OK, *remote holds the peer's
 * status and *body / *body_len the rest of the reply (valid until the
 * next recv). Any other return means the connection is unusable.
 */
kfs_status kfs_conn_call(kfs_conn *c, uint16_t opcode, uint64_t block_id,
                         const kfs_buf *parts, size_t nparts, kfs_status *remote,
                         const uint8_t **body, size_t *body_len);

/* TCP helpers; IPv4 or IPv6 by name resolution. */
kfs_status kfs_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms, int *fd);
kfs_status kfs_tcp_listen(const char *bind_addr, uint16_t port, int backlog, int *fd);

#endif /* KRYPTON_RPC_H */
