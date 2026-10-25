/*
 * krypton_protocol.h - KryptonFS wire formats.
 *
 * Block RPC (TCP)
 * ---------------
 * Every message is a fixed 50-byte header followed by payload_len bytes:
 *
 *   0        4        6                 14            18                 50
 *   +--------+--------+-----------------+-------------+------------------+
 *   | magic  | opcode |    block_id     | payload_len |   hmac_sha256    |
 *   |   4B   |   2B   |       8B        |     4B      |       32B        |
 *   +--------+--------+-----------------+-------------+------------------+
 *
 * Integers are big-endian. The magic's last byte is the protocol version,
 * so an incompatible peer fails the magic check instead of misparsing.
 *
 * A reply carries the request's opcode with KFS_OP_REPLY set and echoes
 * its block_id. Every reply payload starts with a 4-byte big-endian
 * kfs_status; any body follows it.
 *
 * Frame authentication. After the handshake each peer holds a 32-byte
 * session key and one 64-bit sequence counter per direction, starting at 0
 * and incremented per frame sent. The counter is never transmitted; it is
 * bound into the MAC instead:
 *
 *   hmac = HMAC-SHA256(session_key, seq_be64 || header[0..18) || payload)
 *
 * TCP delivers in order, so a replayed, dropped or reordered frame leaves
 * the receiver expecting a different seq and the MAC fails: replay
 * protection at zero header cost. kfs_frame_mac_prefix() builds the first
 * 26 bytes of that input. Handshake frames carry an all-zero hmac; they are
 * authenticated by RSA-2048 signatures over the handshake transcript.
 *
 * Heartbeats (UDP)
 * ----------------
 * Fixed 76-byte datagrams laid out at KFS_HB_OFF_*, authenticated with the
 * cluster key. See kfs_heartbeat.
 *
 * The structs in this file are host-side representations. Never memcpy
 * them to or from the wire; the encode/decode functions fix byte order and
 * are immune to padding and alignment.
 */
#ifndef KRYPTON_PROTOCOL_H
#define KRYPTON_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>

#include "krypton_common.h"

#define KFS_PROTO_VERSION    1u
#define KFS_HMAC_SIZE        32u
#define KFS_IV_SIZE          16u

#define KFS_DEFAULT_RPC_PORT 7400u
#define KFS_DEFAULT_HB_PORT  7401u

/* ---------------------------------------------------------------------
 * Block RPC frame header
 * ------------------------------------------------------------------- */

#define KFS_FRAME_MAGIC           0x4B465301u /* 'K' 'F' 'S' v1 */
#define KFS_FRAME_HDR_SIZE        50u
#define KFS_FRAME_OFF_MAGIC       0u
#define KFS_FRAME_OFF_OPCODE      4u
#define KFS_FRAME_OFF_BLOCK_ID    6u
#define KFS_FRAME_OFF_PAYLOAD_LEN 14u
#define KFS_FRAME_OFF_HMAC        18u
#define KFS_FRAME_MAC_PREFIX_SIZE (8u + KFS_FRAME_OFF_HMAC)

/* Upper bound on payload_len, enforced by kfs_frame_hdr_decode() before
 * the receiver allocates anything. */
#define KFS_FRAME_MAX_PAYLOAD     (128u * 1024u)

#define KFS_OP_REPLY 0x8000u

typedef enum kfs_opcode {
    /* Handshake: opcodes below 0x0010, hmac all-zero, RSA-signed. */
    KFS_OP_HELLO        = 0x0001, /* client nonce + key share -> server nonce, key share, signature */
    KFS_OP_AUTH         = 0x0002, /* client signature over transcript -> status */

    /* Block operations, client -> node. */
    KFS_OP_BLOCK_READ   = 0x0010, /* (empty) -> envelope */
    KFS_OP_BLOCK_WRITE  = 0x0011, /* envelope -> status */
    KFS_OP_BLOCK_DELETE = 0x0012, /* (empty) -> status */
    KFS_OP_BLOCK_STAT   = 0x0013, /* (empty) -> generation + envelope length */

    /* Replication, node -> node. */
    KFS_OP_REPLICATE    = 0x0020  /* envelope -> status */
} kfs_opcode;

typedef struct kfs_frame_hdr {
    uint16_t opcode;
    uint64_t block_id;
    uint32_t payload_len;
    uint8_t  hmac[KFS_HMAC_SIZE];
} kfs_frame_hdr;

/* True for any known request opcode, with or without KFS_OP_REPLY. */
bool kfs_opcode_is_valid(uint16_t opcode);

static inline bool kfs_opcode_is_handshake(uint16_t opcode)
{
    return (opcode & ~KFS_OP_REPLY) < 0x0010u;
}

void kfs_frame_hdr_encode(const kfs_frame_hdr *hdr,
                          uint8_t out[KFS_FRAME_HDR_SIZE]);

/* Rejects a bad magic, an unknown opcode or payload_len above
 * KFS_FRAME_MAX_PAYLOAD with KFS_E_PROTO, leaving *hdr untouched. */
kfs_status kfs_frame_hdr_decode(const uint8_t in[KFS_FRAME_HDR_SIZE],
                                kfs_frame_hdr *hdr);

/* Writes seq_be64 || header[0..18): the MAC input preceding the payload. */
void kfs_frame_mac_prefix(const kfs_frame_hdr *hdr, uint64_t seq,
                          uint8_t out[KFS_FRAME_MAC_PREFIX_SIZE]);

/* ---------------------------------------------------------------------
 * Block envelope
 *
 * The unit storage nodes persist and replicate. Nodes never hold volume
 * keys; to them an envelope is opaque bytes plus a generation number.
 *
 *   0            8              24                56
 *   +------------+--------------+-----------------+----------------------+
 *   | generation |      iv      |       tag       | ciphertext (n bytes) |
 *   |     8B     |     16B      |       32B       |                      |
 *   +------------+--------------+-----------------+----------------------+
 *
 *   ciphertext = AES-256-CTR(data_key, iv, plaintext)
 *   tag        = HMAC-SHA256(mac_key, block_id_be64 || envelope[0..24)
 *                                     || ciphertext)
 *
 * The iv is fresh random per write, so rewriting a block never reuses a
 * CTR keystream. Binding block_id into the tag stops a node from answering
 * a read of block A with block B's validly tagged envelope. generation
 * grows on every write; replicas use it to pick the newest copy.
 * ------------------------------------------------------------------- */

#define KFS_ENVELOPE_HDR_SIZE       56u
#define KFS_ENVELOPE_OFF_GENERATION 0u
#define KFS_ENVELOPE_OFF_IV         8u
#define KFS_ENVELOPE_OFF_TAG        24u

typedef struct kfs_envelope_hdr {
    uint64_t generation;
    uint8_t  iv[KFS_IV_SIZE];
    uint8_t  tag[KFS_HMAC_SIZE];
} kfs_envelope_hdr;

void kfs_envelope_hdr_encode(const kfs_envelope_hdr *env,
                             uint8_t out[KFS_ENVELOPE_HDR_SIZE]);
void kfs_envelope_hdr_decode(const uint8_t in[KFS_ENVELOPE_HDR_SIZE],
                             kfs_envelope_hdr *env);

/* ---------------------------------------------------------------------
 * Heartbeat datagram (UDP)
 *
 *   off  size  field
 *     0     4  magic         'K' 'F' 'H' v1
 *     4     1  type          kfs_hb_type
 *     5     1  state         sender's kfs_node_state
 *     6     2  reserved      zero
 *     8     4  node_id       sender, nonzero
 *    12     8  seq           strictly increasing per sender
 *    20     8  timestamp_ns  sender's monotonic clock; PONG echoes the PING
 *    28     8  disk_total    bytes
 *    36     8  disk_used     bytes
 *    44    32  hmac          HMAC-SHA256(cluster_key, datagram[0..44))
 *
 * Receivers verify hmac over the raw datagram before acting on any field
 * and drop seq <= the last value seen from that node_id. Senders seed seq
 * from the realtime clock at startup so a restarted node does not repeat
 * old values.
 * ------------------------------------------------------------------- */

#define KFS_HB_MAGIC          0x4B464801u /* 'K' 'F' 'H' v1 */
#define KFS_HB_SIZE           76u
#define KFS_HB_OFF_MAGIC      0u
#define KFS_HB_OFF_TYPE       4u
#define KFS_HB_OFF_STATE      5u
#define KFS_HB_OFF_RESERVED   6u
#define KFS_HB_OFF_NODE_ID    8u
#define KFS_HB_OFF_SEQ        12u
#define KFS_HB_OFF_TIMESTAMP  20u
#define KFS_HB_OFF_DISK_TOTAL 28u
#define KFS_HB_OFF_DISK_USED  36u
#define KFS_HB_OFF_HMAC       44u

typedef enum kfs_hb_type {
    KFS_HB_BEAT = 1, /* periodic liveness + capacity broadcast */
    KFS_HB_PING = 2, /* latency probe; the receiver answers with PONG */
    KFS_HB_PONG = 3  /* echoes the PING's timestamp_ns: RTT on the prober's clock */
} kfs_hb_type;

typedef enum kfs_node_state {
    KFS_NODE_UNKNOWN  = 0, /* observer-side: no heartbeat seen yet */
    KFS_NODE_UP       = 1,
    KFS_NODE_DEGRADED = 2, /* serving reads, refusing writes (e.g. disk full) */
    KFS_NODE_DRAINING = 3, /* shutting down; route no new I/O here */
    KFS_NODE_DOWN     = 4  /* observer-side: heartbeat timeout expired */
} kfs_node_state;

typedef struct kfs_heartbeat {
    uint8_t  type;  /* kfs_hb_type */
    uint8_t  state; /* kfs_node_state: UP, DEGRADED or DRAINING on the wire */
    uint32_t node_id;
    uint64_t seq;
    uint64_t timestamp_ns;
    uint64_t disk_total;
    uint64_t disk_used;
    uint8_t  hmac[KFS_HMAC_SIZE];
} kfs_heartbeat;

void kfs_heartbeat_encode(const kfs_heartbeat *hb, uint8_t out[KFS_HB_SIZE]);

/* Structural checks only (magic, type, state, reserved, node_id, disk
 * figures); KFS_E_PROTO on failure, leaving *hb untouched. The caller
 * still verifies hmac. */
kfs_status kfs_heartbeat_decode(const uint8_t in[KFS_HB_SIZE],
                                kfs_heartbeat *hb);

_Static_assert(KFS_FRAME_OFF_HMAC + KFS_HMAC_SIZE == KFS_FRAME_HDR_SIZE,
               "frame header layout");
_Static_assert(KFS_ENVELOPE_OFF_TAG + KFS_HMAC_SIZE == KFS_ENVELOPE_HDR_SIZE,
               "envelope header layout");
_Static_assert(KFS_HB_OFF_HMAC + KFS_HMAC_SIZE == KFS_HB_SIZE,
               "heartbeat layout");
_Static_assert(4u + KFS_ENVELOPE_HDR_SIZE + KFS_BLOCK_SIZE_MAX <= KFS_FRAME_MAX_PAYLOAD,
               "largest BLOCK_READ reply must fit in one frame");

#endif /* KRYPTON_PROTOCOL_H */
