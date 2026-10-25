/*
 * krypton_protocol.c - Encoding and structural validation of KryptonFS
 * wire formats. MAC computation and verification live in the crypto
 * layer; this file only fixes byte layout.
 */
#include "krypton/krypton_protocol.h"

#include <string.h>

bool kfs_opcode_is_valid(uint16_t opcode)
{
    switch ((uint16_t)(opcode & ~KFS_OP_REPLY)) {
    case KFS_OP_HELLO:
    case KFS_OP_AUTH:
    case KFS_OP_BLOCK_READ:
    case KFS_OP_BLOCK_WRITE:
    case KFS_OP_BLOCK_DELETE:
    case KFS_OP_BLOCK_STAT:
    case KFS_OP_REPLICATE:
        return true;
    default:
        return false;
    }
}

void kfs_frame_hdr_encode(const kfs_frame_hdr *hdr,
                          uint8_t out[KFS_FRAME_HDR_SIZE])
{
    kfs_store_be32(out + KFS_FRAME_OFF_MAGIC, KFS_FRAME_MAGIC);
    kfs_store_be16(out + KFS_FRAME_OFF_OPCODE, hdr->opcode);
    kfs_store_be64(out + KFS_FRAME_OFF_BLOCK_ID, hdr->block_id);
    kfs_store_be32(out + KFS_FRAME_OFF_PAYLOAD_LEN, hdr->payload_len);
    memcpy(out + KFS_FRAME_OFF_HMAC, hdr->hmac, KFS_HMAC_SIZE);
}

kfs_status kfs_frame_hdr_decode(const uint8_t in[KFS_FRAME_HDR_SIZE],
                                kfs_frame_hdr *hdr)
{
    uint16_t opcode = kfs_load_be16(in + KFS_FRAME_OFF_OPCODE);
    uint32_t payload_len = kfs_load_be32(in + KFS_FRAME_OFF_PAYLOAD_LEN);

    if (kfs_load_be32(in + KFS_FRAME_OFF_MAGIC) != KFS_FRAME_MAGIC ||
        !kfs_opcode_is_valid(opcode) ||
        payload_len > KFS_FRAME_MAX_PAYLOAD)
        return KFS_E_PROTO;

    hdr->opcode = opcode;
    hdr->block_id = kfs_load_be64(in + KFS_FRAME_OFF_BLOCK_ID);
    hdr->payload_len = payload_len;
    memcpy(hdr->hmac, in + KFS_FRAME_OFF_HMAC, KFS_HMAC_SIZE);
    return KFS_OK;
}

void kfs_frame_mac_prefix(const kfs_frame_hdr *hdr, uint64_t seq,
                          uint8_t out[KFS_FRAME_MAC_PREFIX_SIZE])
{
    uint8_t wire[KFS_FRAME_HDR_SIZE];

    kfs_frame_hdr_encode(hdr, wire);
    kfs_store_be64(out, seq);
    memcpy(out + 8, wire, KFS_FRAME_OFF_HMAC);
}

void kfs_envelope_hdr_encode(const kfs_envelope_hdr *env,
                             uint8_t out[KFS_ENVELOPE_HDR_SIZE])
{
    kfs_store_be64(out + KFS_ENVELOPE_OFF_GENERATION, env->generation);
    memcpy(out + KFS_ENVELOPE_OFF_IV, env->iv, KFS_IV_SIZE);
    memcpy(out + KFS_ENVELOPE_OFF_TAG, env->tag, KFS_HMAC_SIZE);
}

void kfs_envelope_hdr_decode(const uint8_t in[KFS_ENVELOPE_HDR_SIZE],
                             kfs_envelope_hdr *env)
{
    env->generation = kfs_load_be64(in + KFS_ENVELOPE_OFF_GENERATION);
    memcpy(env->iv, in + KFS_ENVELOPE_OFF_IV, KFS_IV_SIZE);
    memcpy(env->tag, in + KFS_ENVELOPE_OFF_TAG, KFS_HMAC_SIZE);
}

void kfs_heartbeat_encode(const kfs_heartbeat *hb, uint8_t out[KFS_HB_SIZE])
{
    kfs_store_be32(out + KFS_HB_OFF_MAGIC, KFS_HB_MAGIC);
    out[KFS_HB_OFF_TYPE] = hb->type;
    out[KFS_HB_OFF_STATE] = hb->state;
    kfs_store_be16(out + KFS_HB_OFF_RESERVED, 0);
    kfs_store_be32(out + KFS_HB_OFF_NODE_ID, hb->node_id);
    kfs_store_be64(out + KFS_HB_OFF_SEQ, hb->seq);
    kfs_store_be64(out + KFS_HB_OFF_TIMESTAMP, hb->timestamp_ns);
    kfs_store_be64(out + KFS_HB_OFF_DISK_TOTAL, hb->disk_total);
    kfs_store_be64(out + KFS_HB_OFF_DISK_USED, hb->disk_used);
    memcpy(out + KFS_HB_OFF_HMAC, hb->hmac, KFS_HMAC_SIZE);
}

kfs_status kfs_heartbeat_decode(const uint8_t in[KFS_HB_SIZE],
                                kfs_heartbeat *hb)
{
    uint8_t type = in[KFS_HB_OFF_TYPE];
    uint8_t state = in[KFS_HB_OFF_STATE];
    uint32_t node_id = kfs_load_be32(in + KFS_HB_OFF_NODE_ID);
    uint64_t disk_total = kfs_load_be64(in + KFS_HB_OFF_DISK_TOTAL);
    uint64_t disk_used = kfs_load_be64(in + KFS_HB_OFF_DISK_USED);

    if (kfs_load_be32(in + KFS_HB_OFF_MAGIC) != KFS_HB_MAGIC ||
        type < KFS_HB_BEAT || type > KFS_HB_PONG ||
        state < KFS_NODE_UP || state > KFS_NODE_DRAINING ||
        kfs_load_be16(in + KFS_HB_OFF_RESERVED) != 0 ||
        node_id == 0 ||
        disk_used > disk_total)
        return KFS_E_PROTO;

    hb->type = type;
    hb->state = state;
    hb->node_id = node_id;
    hb->seq = kfs_load_be64(in + KFS_HB_OFF_SEQ);
    hb->timestamp_ns = kfs_load_be64(in + KFS_HB_OFF_TIMESTAMP);
    hb->disk_total = disk_total;
    hb->disk_used = disk_used;
    memcpy(hb->hmac, in + KFS_HB_OFF_HMAC, KFS_HMAC_SIZE);
    return KFS_OK;
}
