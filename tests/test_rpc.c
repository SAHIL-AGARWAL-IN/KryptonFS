/*
 * test_rpc.c - Handshake and authenticated framing over socket pairs:
 * mutual authentication, key pinning, impostors, tampering and replay.
 */
#define _GNU_SOURCE /* mkdtemp */

#include "krypton/krypton_rpc.h"

#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "kfs_test.h"

#define SERVER_ID 10u
#define CLIENT_ID 20u
#define TIMEOUT   5000u

static kfs_identity *server_key, *client_key, *mallory_key;
static char trusted[] = "/tmp/kfs-trusted-XXXXXX";

typedef struct server_run {
    kfs_conn   conn;
    kfs_status handshake;
    int        echoes; /* requests to answer after the handshake */
} server_run;

static void *serve(void *arg)
{
    server_run *s = arg;

    s->handshake = kfs_conn_handshake_server(&s->conn, server_key, SERVER_ID, trusted);
    if (s->handshake != KFS_OK)
        shutdown(s->conn.fd, SHUT_RDWR); /* hang up, as kfs-noded does */
    for (int i = 0; s->handshake == KFS_OK && i < s->echoes; i++) {
        kfs_frame_hdr hdr;
        const uint8_t *p;
        kfs_buf body;

        if (kfs_conn_recv(&s->conn, &hdr, &p) != KFS_OK)
            break;
        body = (kfs_buf){ p, hdr.payload_len };
        kfs_conn_reply(&s->conn, hdr.opcode, hdr.block_id, KFS_OK, &body, 1);
    }
    return NULL;
}

/* Runs a handshake between a client (claiming client_id with ckey and
 * pinning pinned_server as server expect_id) and the test server. */
static kfs_status attempt(uint32_t client_id, const kfs_identity *ckey,
                          const kfs_identity *pinned_server, uint32_t expect_id,
                          int echoes, kfs_conn *client, server_run *srv)
{
    int sv[2];
    pthread_t t;
    kfs_status st;

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return KFS_E_IO;
    kfs_conn_init(client, sv[0], TIMEOUT);
    kfs_conn_init(&srv->conn, sv[1], TIMEOUT);
    srv->echoes = echoes;
    pthread_create(&t, NULL, serve, srv);
    st = kfs_conn_handshake_client(client, ckey, client_id, pinned_server, expect_id);
    if (st != KFS_OK)
        shutdown(sv[0], SHUT_RDWR); /* unblock a server still waiting */
    if (echoes == 0)
        pthread_join(t, NULL);
    else
        pthread_detach(t);
    return st;
}

static void finish(kfs_conn *client, server_run *srv)
{
    kfs_conn_close(client);
    kfs_conn_close(&srv->conn);
}

static void test_mutual_auth_and_calls(void)
{
    static const uint8_t payload[] = "envelope bytes";
    static server_run srv;
    kfs_conn client;
    kfs_status remote;
    const uint8_t *body;
    size_t body_len;
    kfs_buf part = { payload, sizeof(payload) };

    CHECK_EQ(attempt(CLIENT_ID, client_key, server_key, SERVER_ID, 3, &client, &srv), KFS_OK);
    CHECK(kfs_conn_ready(&client));
    CHECK_EQ(client.peer_id, SERVER_ID);
    for (int i = 0; i < 3; i++) {
        CHECK_EQ(kfs_conn_call(&client, KFS_OP_BLOCK_WRITE, 77 + (uint64_t)i, &part, 1,
                               &remote, &body, &body_len), KFS_OK);
        CHECK_EQ(remote, KFS_OK);
        CHECK_EQ(body_len, sizeof(payload));
        CHECK(memcmp(body, payload, sizeof(payload)) == 0);
    }
    CHECK_EQ(srv.handshake, KFS_OK);
    CHECK_EQ(srv.conn.peer_id, CLIENT_ID);
    CHECK(memcmp(client.key_tx, srv.conn.key_rx, KFS_KEY_SIZE) == 0);
    CHECK(memcmp(client.key_tx, client.key_rx, KFS_KEY_SIZE) != 0); /* per-direction keys */
    finish(&client, &srv);
}

static void test_rejections(void)
{
    server_run srv;
    kfs_conn client;

    /* Mallory claims the client's id but holds a different key. */
    CHECK(attempt(CLIENT_ID, mallory_key, server_key, SERVER_ID, 0, &client, &srv) != KFS_OK);
    CHECK_EQ(srv.handshake, KFS_E_AUTH);
    finish(&client, &srv);

    /* An identity absent from trusted_keys is dropped. */
    CHECK(attempt(99, client_key, server_key, SERVER_ID, 0, &client, &srv) != KFS_OK);
    CHECK_EQ(srv.handshake, KFS_E_AUTH);
    finish(&client, &srv);

    /* The client dialled node 11 but node 10 answered. */
    CHECK_EQ(attempt(CLIENT_ID, client_key, server_key, 11, 0, &client, &srv), KFS_E_AUTH);
    finish(&client, &srv);

    /* The client pinned a different key for node 10 (impersonated server). */
    CHECK_EQ(attempt(CLIENT_ID, client_key, mallory_key, SERVER_ID, 0, &client, &srv), KFS_E_AUTH);
    finish(&client, &srv);
}

static bool read_exact(int fd, uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = read(fd, buf, len);

        if (n <= 0)
            return false;
        buf += n;
        len -= (size_t)n;
    }
    return true;
}

/* Captures one raw frame the client sends after the handshake. */
static size_t capture_frame(int fd, uint8_t *buf, size_t cap)
{
    kfs_frame_hdr h;

    if (cap < KFS_FRAME_HDR_SIZE || !read_exact(fd, buf, KFS_FRAME_HDR_SIZE) ||
        kfs_frame_hdr_decode(buf, &h) != KFS_OK ||
        h.payload_len > cap - KFS_FRAME_HDR_SIZE ||
        !read_exact(fd, buf + KFS_FRAME_HDR_SIZE, h.payload_len))
        return 0;
    return KFS_FRAME_HDR_SIZE + h.payload_len;
}

/* Feeds raw bytes to a copy of the server connection's state. */
static kfs_status deliver(const kfs_conn *state, const uint8_t *frame, size_t len, kfs_conn *view)
{
    int sv[2];
    kfs_frame_hdr hdr;
    const uint8_t *p;
    kfs_status st;

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return KFS_E_IO;
    if (write(sv[0], frame, len) != (ssize_t)len)
        return KFS_E_IO;
    close(sv[0]);
    view->fd = sv[1];
    st = kfs_conn_recv(view, &hdr, &p);
    close(sv[1]);
    (void)state;
    return st;
}

static void test_tamper_and_replay(void)
{
    static uint8_t frame[KFS_FRAME_HDR_SIZE + 64], bad[sizeof(frame)];
    static server_run srv;
    kfs_conn client, view;
    kfs_buf part = { "block", 5 };
    size_t len;

    CHECK_EQ(attempt(CLIENT_ID, client_key, server_key, SERVER_ID, 0, &client, &srv), KFS_OK);
    CHECK_EQ(kfs_conn_send(&client, KFS_OP_BLOCK_WRITE, 5, &part, 1), KFS_OK);
    len = capture_frame(srv.conn.fd, frame, sizeof(frame));
    CHECK(len > 0);

    /* The server's view after the handshake: same keys, next seq 0. */
    view = srv.conn;
    view.rx = malloc(KFS_FRAME_MAX_PAYLOAD);
    if (view.rx == NULL)
        return;

    memcpy(bad, frame, len);
    bad[len - 1] ^= 0x01; /* one payload bit */
    CHECK_EQ(deliver(&srv.conn, bad, len, &view), KFS_E_AUTH);

    memcpy(bad, frame, len);
    kfs_store_be64(bad + KFS_FRAME_OFF_BLOCK_ID, 6); /* redirected to another block */
    CHECK_EQ(deliver(&srv.conn, bad, len, &view), KFS_E_AUTH);

    CHECK_EQ(deliver(&srv.conn, frame, len, &view), KFS_OK);    /* genuine: accepted ... */
    CHECK_EQ(deliver(&srv.conn, frame, len, &view), KFS_E_AUTH); /* ... once */

    free(view.rx);
    finish(&client, &srv);
}

static void test_data_before_handshake(void)
{
    int sv[2];
    kfs_conn a, b;
    kfs_frame_hdr hdr;
    const uint8_t *p;
    kfs_buf part = { "x", 1 };

    CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv), 0);
    kfs_conn_init(&a, sv[0], TIMEOUT);
    kfs_conn_init(&b, sv[1], TIMEOUT);
    CHECK_EQ(kfs_conn_send(&a, KFS_OP_BLOCK_READ, 1, &part, 1), KFS_OK);
    CHECK_EQ(kfs_conn_recv(&b, &hdr, &p), KFS_E_PROTO);
    kfs_conn_close(&a);
    kfs_conn_close(&b);
}

static void test_timeout(void)
{
    int sv[2];
    kfs_conn a;
    kfs_frame_hdr hdr;
    const uint8_t *p;

    CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv), 0);
    kfs_conn_init(&a, sv[0], 100);
    CHECK_EQ(kfs_conn_recv(&a, &hdr, &p), KFS_E_TIMEOUT);
    kfs_conn_close(&a);
    close(sv[1]);
}

static bool save_pub(const kfs_identity *id, uint32_t node)
{
    char path[128];

    snprintf(path, sizeof(path), "%s/%u.pub.pem", trusted, node);
    return kfs_identity_save_public(id, path) == KFS_OK;
}

int main(void)
{
    if (mkdtemp(trusted) == NULL ||
        kfs_identity_generate(&server_key) != KFS_OK ||
        kfs_identity_generate(&client_key) != KFS_OK ||
        kfs_identity_generate(&mallory_key) != KFS_OK ||
        !save_pub(server_key, SERVER_ID) || !save_pub(client_key, CLIENT_ID)) {
        fprintf(stderr, "setup failed\n");
        return 1;
    }

    RUN(test_mutual_auth_and_calls);
    RUN(test_rejections);
    RUN(test_tamper_and_replay);
    RUN(test_data_before_handshake);
    RUN(test_timeout);

    {
        char path[128];

        snprintf(path, sizeof(path), "%s/%u.pub.pem", trusted, SERVER_ID);
        unlink(path);
        snprintf(path, sizeof(path), "%s/%u.pub.pem", trusted, CLIENT_ID);
        unlink(path);
        rmdir(trusted);
    }
    kfs_identity_free(server_key);
    kfs_identity_free(client_key);
    kfs_identity_free(mallory_key);
    TEST_EXIT();
}
