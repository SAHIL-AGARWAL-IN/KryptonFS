/*
 * rpc_conn.c - Frame I/O with per-direction MACs, and TCP helpers.
 */
#define _GNU_SOURCE /* SOCK_CLOEXEC, SOCK_NONBLOCK */

#include "krypton/krypton_rpc.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

kfs_status kfs_conn_init(kfs_conn *c, int fd, uint32_t timeout_ms)
{
    struct timeval tv = { (time_t)(timeout_ms / 1000), (suseconds_t)(timeout_ms % 1000) * 1000 };
    int one = 1;

    memset(c, 0, sizeof(*c));
    c->fd = fd;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); /* fails harmlessly off TCP */
    c->rx = malloc(KFS_FRAME_MAX_PAYLOAD);
    c->tx = malloc(KFS_FRAME_HDR_SIZE + KFS_FRAME_MAX_PAYLOAD);
    if (c->rx == NULL || c->tx == NULL) {
        kfs_conn_close(c);
        return KFS_E_NOMEM;
    }
    return KFS_OK;
}

void kfs_conn_close(kfs_conn *c)
{
    if (c->fd >= 0)
        close(c->fd);
    if (c->rx != NULL) {
        kfs_wipe(c->rx, KFS_FRAME_MAX_PAYLOAD);
        free(c->rx);
    }
    free(c->tx);
    kfs_wipe(c, sizeof(*c));
    c->fd = -1;
}

static kfs_status send_all(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);

        if (n > 0) {
            buf += n;
            len -= (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return KFS_E_TIMEOUT;
        } else {
            return KFS_E_IO;
        }
    }
    return KFS_OK;
}

static kfs_status recv_all(int fd, uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = recv(fd, buf, len, 0);

        if (n > 0) {
            buf += n;
            len -= (size_t)n;
        } else if (n == 0) {
            return KFS_E_IO; /* peer closed */
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return KFS_E_TIMEOUT;
        } else {
            return KFS_E_IO;
        }
    }
    return KFS_OK;
}

kfs_status kfs_conn_send(kfs_conn *c, uint16_t opcode, uint64_t block_id,
                         const kfs_buf *parts, size_t nparts)
{
    uint8_t *payload = c->tx + KFS_FRAME_HDR_SIZE;
    kfs_frame_hdr hdr;
    size_t total = 0;
    kfs_status st;

    for (size_t i = 0; i < nparts; i++) {
        if (parts[i].len > KFS_FRAME_MAX_PAYLOAD - total)
            return KFS_E_INVAL;
        memcpy(payload + total, parts[i].data, parts[i].len);
        total += parts[i].len;
    }
    memset(&hdr, 0, sizeof(hdr));
    hdr.opcode = opcode;
    hdr.block_id = block_id;
    hdr.payload_len = (uint32_t)total;
    if (c->mac_tx) {
        st = kfs_frame_mac(c->key_tx, &hdr, c->seq_tx, payload, hdr.hmac);
        if (st != KFS_OK)
            return st;
    }
    kfs_frame_hdr_encode(&hdr, c->tx);
    st = send_all(c->fd, c->tx, KFS_FRAME_HDR_SIZE + total);
    if (st == KFS_OK && c->mac_tx)
        c->seq_tx++;
    return st;
}

kfs_status kfs_conn_recv(kfs_conn *c, kfs_frame_hdr *hdr, const uint8_t **payload)
{
    uint8_t wire[KFS_FRAME_HDR_SIZE];
    kfs_status st = recv_all(c->fd, wire, sizeof(wire));

    if (st != KFS_OK)
        return st;
    /* decode bounds payload_len before anything is read into rx. */
    st = kfs_frame_hdr_decode(wire, hdr);
    if (st != KFS_OK)
        return st;
    st = recv_all(c->fd, c->rx, hdr->payload_len);
    if (st != KFS_OK)
        return st;
    if (c->mac_rx) {
        st = kfs_frame_verify(c->key_rx, hdr, c->seq_rx, c->rx);
        if (st != KFS_OK)
            return st;
        c->seq_rx++;
        /* Once authenticated, only the server's AUTH reply may still be
         * a handshake frame. */
        if (kfs_opcode_is_handshake(hdr->opcode) && hdr->opcode != (KFS_OP_AUTH | KFS_OP_REPLY))
            return KFS_E_PROTO;
    } else if (!kfs_opcode_is_handshake(hdr->opcode)) {
        return KFS_E_PROTO; /* data before the handshake finished */
    }
    *payload = c->rx;
    return KFS_OK;
}

kfs_status kfs_conn_reply(kfs_conn *c, uint16_t request_op, uint64_t block_id,
                          kfs_status status, const kfs_buf *body, size_t nbody)
{
    uint8_t st_be[4];
    kfs_buf parts[5];

    if (nbody > 4)
        return KFS_E_INVAL;
    kfs_store_be32(st_be, (uint32_t)status);
    parts[0] = (kfs_buf){ st_be, sizeof(st_be) };
    for (size_t i = 0; i < nbody; i++)
        parts[i + 1] = body[i];
    return kfs_conn_send(c, (uint16_t)(request_op | KFS_OP_REPLY), block_id, parts, nbody + 1);
}

kfs_status kfs_conn_call(kfs_conn *c, uint16_t opcode, uint64_t block_id,
                         const kfs_buf *parts, size_t nparts, kfs_status *remote,
                         const uint8_t **body, size_t *body_len)
{
    kfs_frame_hdr hdr;
    const uint8_t *p;
    uint32_t status;
    kfs_status st = kfs_conn_send(c, opcode, block_id, parts, nparts);

    if (st == KFS_OK)
        st = kfs_conn_recv(c, &hdr, &p);
    if (st != KFS_OK)
        return st;
    if (hdr.opcode != (uint16_t)(opcode | KFS_OP_REPLY) || hdr.block_id != block_id ||
        hdr.payload_len < 4)
        return KFS_E_PROTO;
    status = kfs_load_be32(p);
    if (status > KFS_E_CONFIG)
        return KFS_E_PROTO;
    *remote = (kfs_status)status;
    *body = p + 4;
    *body_len = hdr.payload_len - 4;
    return KFS_OK;
}

static struct addrinfo *resolve(const char *host, uint16_t port, bool passive)
{
    struct addrinfo hints, *res = NULL;
    char port_str[8];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = passive ? AI_PASSIVE : 0;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    return getaddrinfo(host, port_str, &hints, &res) == 0 ? res : NULL;
}

kfs_status kfs_tcp_connect(const char *host, uint16_t port, uint32_t timeout_ms, int *out)
{
    struct addrinfo *res = resolve(host, port, false), *ai;
    kfs_status st = KFS_E_UNAVAILABLE;

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK,
                        ai->ai_protocol);
        struct pollfd pfd;
        int err = 0;
        socklen_t len = sizeof(err);

        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            if (errno != EINPROGRESS) {
                close(fd);
                continue;
            }
            pfd.fd = fd;
            pfd.events = POLLOUT;
            if (poll(&pfd, 1, (int)timeout_ms) != 1 ||
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
                close(fd);
                st = KFS_E_TIMEOUT;
                continue;
            }
        }
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
        *out = fd;
        st = KFS_OK;
        break;
    }
    if (res != NULL)
        freeaddrinfo(res);
    return st;
}

kfs_status kfs_tcp_listen(const char *bind_addr, uint16_t port, int backlog, int *out)
{
    struct addrinfo *res = resolve(bind_addr, port, true), *ai;

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        int one = 1;

        if (fd < 0)
            continue;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, backlog) == 0) {
            freeaddrinfo(res);
            *out = fd;
            return KFS_OK;
        }
        close(fd);
    }
    if (res != NULL)
        freeaddrinfo(res);
    return KFS_E_IO;
}
