/*
 * test_protocol.c - Byte-exact layout and validation of the wire formats.
 */
#include "krypton/krypton_protocol.h"

#include "kfs_test.h"

static void test_frame_golden_bytes(void)
{
    static const uint8_t expect[KFS_FRAME_OFF_HMAC] = {
        'K', 'F', 'S', 0x01,                            /* magic */
        0x00, 0x11,                                     /* opcode */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* block_id */
        0x00, 0x00, 0x12, 0x34,                         /* payload_len */
    };
    kfs_frame_hdr hdr = {
        .opcode = KFS_OP_BLOCK_WRITE,
        .block_id = 0x0102030405060708u,
        .payload_len = 0x1234,
    };
    uint8_t wire[KFS_FRAME_HDR_SIZE];

    memset(hdr.hmac, 0xAB, sizeof(hdr.hmac));
    kfs_frame_hdr_encode(&hdr, wire);
    CHECK(memcmp(wire, expect, sizeof(expect)) == 0);
    for (size_t i = KFS_FRAME_OFF_HMAC; i < KFS_FRAME_HDR_SIZE; i++)
        CHECK_EQ(wire[i], 0xAB);
}

static void test_frame_roundtrip(void)
{
    kfs_frame_hdr in = {
        .opcode = KFS_OP_BLOCK_READ | KFS_OP_REPLY,
        .block_id = UINT64_MAX,
        .payload_len = KFS_FRAME_MAX_PAYLOAD,
    };
    kfs_frame_hdr out;
    uint8_t wire[KFS_FRAME_HDR_SIZE];

    for (size_t i = 0; i < KFS_HMAC_SIZE; i++)
        in.hmac[i] = (uint8_t)i;
    kfs_frame_hdr_encode(&in, wire);
    CHECK_EQ(kfs_frame_hdr_decode(wire, &out), KFS_OK);
    CHECK_EQ(out.opcode, in.opcode);
    CHECK_EQ(out.block_id, in.block_id);
    CHECK_EQ(out.payload_len, in.payload_len);
    CHECK(memcmp(out.hmac, in.hmac, KFS_HMAC_SIZE) == 0);
}

static void test_frame_rejects_malformed(void)
{
    kfs_frame_hdr hdr = { .opcode = KFS_OP_BLOCK_WRITE, .payload_len = 16 };
    kfs_frame_hdr out, sentinel;
    uint8_t wire[KFS_FRAME_HDR_SIZE], bad[KFS_FRAME_HDR_SIZE];

    memset(&sentinel, 0x5A, sizeof(sentinel));
    kfs_frame_hdr_encode(&hdr, wire);

    memcpy(bad, wire, sizeof(bad));
    bad[KFS_FRAME_OFF_MAGIC + 3] = 0x02; /* future protocol version */
    out = sentinel;
    CHECK_EQ(kfs_frame_hdr_decode(bad, &out), KFS_E_PROTO);
    CHECK(memcmp(&out, &sentinel, sizeof(out)) == 0);

    memcpy(bad, wire, sizeof(bad));
    kfs_store_be16(bad + KFS_FRAME_OFF_OPCODE, 0x0099);
    CHECK_EQ(kfs_frame_hdr_decode(bad, &out), KFS_E_PROTO);

    memcpy(bad, wire, sizeof(bad));
    kfs_store_be32(bad + KFS_FRAME_OFF_PAYLOAD_LEN, KFS_FRAME_MAX_PAYLOAD + 1);
    CHECK_EQ(kfs_frame_hdr_decode(bad, &out), KFS_E_PROTO);
}

static void test_opcodes(void)
{
    CHECK(kfs_opcode_is_valid(KFS_OP_HELLO));
    CHECK(kfs_opcode_is_valid(KFS_OP_REPLICATE | KFS_OP_REPLY));
    CHECK(!kfs_opcode_is_valid(0x0000));
    CHECK(!kfs_opcode_is_valid(0x7FFF));
    CHECK(kfs_opcode_is_handshake(KFS_OP_AUTH | KFS_OP_REPLY));
    CHECK(!kfs_opcode_is_handshake(KFS_OP_BLOCK_READ));
}

static void test_mac_prefix(void)
{
    kfs_frame_hdr hdr = { .opcode = KFS_OP_BLOCK_STAT, .block_id = 42, .payload_len = 0 };
    uint8_t wire[KFS_FRAME_HDR_SIZE], prefix[KFS_FRAME_MAC_PREFIX_SIZE];

    memset(hdr.hmac, 0xFF, sizeof(hdr.hmac));
    kfs_frame_hdr_encode(&hdr, wire);
    kfs_frame_mac_prefix(&hdr, 0x1122334455667788u, prefix);

    CHECK_EQ(kfs_load_be64(prefix), 0x1122334455667788u);
    CHECK(memcmp(prefix + 8, wire, KFS_FRAME_OFF_HMAC) == 0);
}

static void test_envelope_roundtrip(void)
{
    kfs_envelope_hdr in = { .generation = 0x0A0B0C0D0E0F1011u }, out;
    uint8_t wire[KFS_ENVELOPE_HDR_SIZE];

    memset(in.iv, 0x11, sizeof(in.iv));
    memset(in.tag, 0x22, sizeof(in.tag));
    kfs_envelope_hdr_encode(&in, wire);

    CHECK_EQ(wire[0], 0x0A);
    CHECK_EQ(wire[7], 0x11);
    CHECK_EQ(wire[KFS_ENVELOPE_OFF_IV], 0x11);
    CHECK_EQ(wire[KFS_ENVELOPE_OFF_TAG], 0x22);

    kfs_envelope_hdr_decode(wire, &out);
    CHECK_EQ(out.generation, in.generation);
    CHECK(memcmp(out.iv, in.iv, KFS_IV_SIZE) == 0);
    CHECK(memcmp(out.tag, in.tag, KFS_HMAC_SIZE) == 0);
}

static kfs_heartbeat sample_heartbeat(void)
{
    kfs_heartbeat hb = {
        .type = KFS_HB_PONG,
        .state = KFS_NODE_DEGRADED,
        .node_id = 7,
        .seq = 1000,
        .timestamp_ns = 123456789,
        .disk_total = 1ull << 40,
        .disk_used = 1ull << 39,
    };
    memset(hb.hmac, 0xC3, sizeof(hb.hmac));
    return hb;
}

static void test_heartbeat_roundtrip(void)
{
    kfs_heartbeat in = sample_heartbeat(), out;
    uint8_t wire[KFS_HB_SIZE];

    kfs_heartbeat_encode(&in, wire);
    CHECK_EQ(kfs_load_be32(wire), KFS_HB_MAGIC);
    CHECK_EQ(kfs_load_be32(wire + KFS_HB_OFF_NODE_ID), 7);
    CHECK_EQ(wire[KFS_HB_OFF_HMAC], 0xC3);

    CHECK_EQ(kfs_heartbeat_decode(wire, &out), KFS_OK);
    CHECK_EQ(out.type, in.type);
    CHECK_EQ(out.state, in.state);
    CHECK_EQ(out.node_id, in.node_id);
    CHECK_EQ(out.seq, in.seq);
    CHECK_EQ(out.timestamp_ns, in.timestamp_ns);
    CHECK_EQ(out.disk_total, in.disk_total);
    CHECK_EQ(out.disk_used, in.disk_used);
    CHECK(memcmp(out.hmac, in.hmac, KFS_HMAC_SIZE) == 0);
}

static void test_heartbeat_rejects_malformed(void)
{
    kfs_heartbeat hb, out;
    uint8_t wire[KFS_HB_SIZE];

    hb = sample_heartbeat();
    hb.type = 0;
    kfs_heartbeat_encode(&hb, wire);
    CHECK_EQ(kfs_heartbeat_decode(wire, &out), KFS_E_PROTO);

    hb = sample_heartbeat();
    hb.state = KFS_NODE_DOWN; /* observer-only state */
    kfs_heartbeat_encode(&hb, wire);
    CHECK_EQ(kfs_heartbeat_decode(wire, &out), KFS_E_PROTO);

    hb = sample_heartbeat();
    hb.node_id = 0;
    kfs_heartbeat_encode(&hb, wire);
    CHECK_EQ(kfs_heartbeat_decode(wire, &out), KFS_E_PROTO);

    hb = sample_heartbeat();
    hb.disk_used = hb.disk_total + 1;
    kfs_heartbeat_encode(&hb, wire);
    CHECK_EQ(kfs_heartbeat_decode(wire, &out), KFS_E_PROTO);

    hb = sample_heartbeat();
    kfs_heartbeat_encode(&hb, wire);
    wire[KFS_HB_OFF_RESERVED] = 1;
    CHECK_EQ(kfs_heartbeat_decode(wire, &out), KFS_E_PROTO);
}

int main(void)
{
    RUN(test_frame_golden_bytes);
    RUN(test_frame_roundtrip);
    RUN(test_frame_rejects_malformed);
    RUN(test_opcodes);
    RUN(test_mac_prefix);
    RUN(test_envelope_roundtrip);
    RUN(test_heartbeat_roundtrip);
    RUN(test_heartbeat_rejects_malformed);
    TEST_EXIT();
}
