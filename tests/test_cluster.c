/*
 * test_cluster.c - Rendezvous placement properties, the health table, and
 * live heartbeat services on localhost.
 */
#define _POSIX_C_SOURCE 200809L

#include "krypton/krypton_cluster.h"

#include <time.h>

#include "kfs_test.h"

static void add_peer(kfs_cluster_config *cl, uint32_t id, uint16_t hb_port)
{
    kfs_peer *p = &cl->peers[cl->peer_count++];

    p->node_id = id;
    snprintf(p->host, sizeof(p->host), "127.0.0.1");
    p->rpc_port = 7400;
    p->hb_port = hb_port;
}

static void test_placement_is_deterministic(void)
{
    kfs_cluster_config a, b;
    uint32_t ra[3], rb[3];

    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    add_peer(&a, 1, 1);
    add_peer(&a, 2, 1);
    add_peer(&a, 3, 1);
    /* Same peers, listed in another order. */
    add_peer(&b, 3, 1);
    add_peer(&b, 1, 1);
    add_peer(&b, 2, 1);
    for (uint64_t id = 0; id < 500; id++) {
        CHECK_EQ(kfs_placement(&a, id, ra, 2), 2);
        CHECK_EQ(kfs_placement(&b, id, rb, 2), 2);
        CHECK(ra[0] != ra[1]);
        CHECK_EQ(a.peers[ra[0]].node_id, b.peers[rb[0]].node_id);
        CHECK_EQ(a.peers[ra[1]].node_id, b.peers[rb[1]].node_id);
    }
    CHECK_EQ(kfs_placement(&a, 9, ra, 5), 3); /* capped at the peer count */
}

static void test_placement_balance_and_stability(void)
{
    enum { BLOCKS = 6000 };
    kfs_cluster_config cl, grown;
    unsigned load[4] = { 0, 0, 0, 0 }, moved = 0;

    memset(&cl, 0, sizeof(cl));
    for (uint32_t id = 1; id <= 3; id++)
        add_peer(&cl, id, 1);
    grown = cl;
    add_peer(&grown, 4, 1);

    for (uint64_t b = 0; b < BLOCKS; b++) {
        uint32_t r3[2], r4[2];

        kfs_placement(&cl, b * 2654435761u, r3, 2);
        kfs_placement(&grown, b * 2654435761u, r4, 2);
        load[r3[0]]++;
        load[r3[1]]++;
        /* Adding node 4 only ever moves a replica onto node 4. */
        for (int k = 0; k < 2; k++) {
            uint32_t now = grown.peers[r4[k]].node_id;

            if (now != cl.peers[r3[0]].node_id && now != cl.peers[r3[1]].node_id) {
                CHECK_EQ(now, 4);
                moved++;
            }
        }
    }
    /* Each of 3 nodes holds about 2/3 of the 6000 blocks. */
    for (int i = 0; i < 3; i++)
        CHECK(load[i] > 3600 && load[i] < 4400);
    /* Node 4 takes about half the replicas (2 of 4 slots). */
    CHECK(moved > 2400 && moved < 3600);
}

static void test_health_table(void)
{
    kfs_cluster_config cl;
    kfs_health *h;
    kfs_heartbeat hb;
    kfs_peer_health snap[4];
    int64_t t0 = kfs_mono_ns();

    memset(&cl, 0, sizeof(cl));
    cl.heartbeat_interval_ms = 100;
    cl.heartbeat_timeout_ms = 300;
    add_peer(&cl, 1, 1);
    add_peer(&cl, 2, 1);
    h = kfs_health_new(&cl);
    CHECK(h != NULL);
    if (h == NULL)
        return;

    CHECK(kfs_health_usable(h, 1)); /* unknown: worth trying */
    memset(&hb, 0, sizeof(hb));
    hb.type = KFS_HB_BEAT;
    hb.state = KFS_NODE_UP;
    hb.node_id = 1;
    hb.seq = 50;
    hb.disk_total = 1000;
    hb.disk_used = 250;
    CHECK_EQ(kfs_health_observe(h, &hb, t0), KFS_OK);
    CHECK_EQ(kfs_health_observe(h, &hb, t0), KFS_E_AUTH); /* replay */
    hb.seq = 49;
    CHECK_EQ(kfs_health_observe(h, &hb, t0), KFS_E_AUTH); /* older */
    hb.node_id = 9;
    hb.seq = 100;
    CHECK_EQ(kfs_health_observe(h, &hb, t0), KFS_E_NOT_FOUND);

    kfs_health_set_rtt(h, 1, 12345);
    CHECK_EQ(kfs_health_snapshot(h, snap, 4), 2);
    CHECK_EQ(snap[0].state, KFS_NODE_UP);
    CHECK_EQ(snap[0].rtt_ns, 12345);
    CHECK_EQ(snap[0].disk_used, 250);
    CHECK_EQ(snap[1].state, KFS_NODE_UNKNOWN);

    kfs_health_expire(h, t0 + 200 * 1000000ll);
    CHECK(kfs_health_usable(h, 1));
    kfs_health_expire(h, t0 + 1000 * 1000000ll);
    CHECK(!kfs_health_usable(h, 1));
    CHECK(!kfs_health_usable(h, 2)); /* never heard from at all */
    kfs_health_free(h);
}

static bool wait_until(kfs_health *h, uint32_t node, kfs_node_state want, int64_t *rtt)
{
    struct timespec tick = { 0, 20 * 1000 * 1000 };

    for (int i = 0; i < 150; i++) {
        kfs_peer_health snap[KFS_MAX_PEERS];
        size_t n = kfs_health_snapshot(h, snap, KFS_MAX_PEERS);

        for (size_t k = 0; k < n; k++) {
            if (snap[k].node_id == node && snap[k].state == want &&
                (rtt == NULL || snap[k].rtt_ns > 0)) {
                if (rtt != NULL)
                    *rtt = snap[k].rtt_ns;
                return true;
            }
        }
        nanosleep(&tick, NULL);
    }
    return false;
}

static void test_live_heartbeats(void)
{
    uint8_t key[KFS_KEY_SIZE], wrong[KFS_KEY_SIZE];
    kfs_cluster_config cl;
    kfs_health *h1, *h2, *hc, *h3;
    kfs_heartbeat_svc *n1 = NULL, *n2 = NULL, *client = NULL, *rogue = NULL;
    kfs_heartbeat_opts o;
    int64_t rtt = 0;

    memset(key, 0x42, sizeof(key));
    memset(wrong, 0x43, sizeof(wrong));
    memset(&cl, 0, sizeof(cl));
    cl.heartbeat_interval_ms = 50;
    cl.heartbeat_timeout_ms = 400;
    add_peer(&cl, 1, 17401);
    add_peer(&cl, 2, 17402);
    add_peer(&cl, 3, 17403); /* runs with the wrong cluster key */
    h1 = kfs_health_new(&cl);
    h2 = kfs_health_new(&cl);
    h3 = kfs_health_new(&cl);
    hc = kfs_health_new(&cl);

    memset(&o, 0, sizeof(o));
    o.role = KFS_ROLE_NODE;
    o.cluster = &cl;
    o.cluster_key = key;
    o.bind_addr = "127.0.0.1";
    o.data_dir = "/";
    o.self_id = 1;
    o.port = 17401;
    CHECK_EQ(kfs_heartbeat_start(&o, h1, &n1), KFS_OK);
    o.self_id = 2;
    o.port = 17402;
    CHECK_EQ(kfs_heartbeat_start(&o, h2, &n2), KFS_OK);
    o.self_id = 3;
    o.port = 17403;
    o.cluster_key = wrong;
    CHECK_EQ(kfs_heartbeat_start(&o, h3, &rogue), KFS_OK);

    o.role = KFS_ROLE_CLIENT;
    o.cluster_key = key;
    o.self_id = 100;
    o.port = 0;
    o.data_dir = NULL;
    CHECK_EQ(kfs_heartbeat_start(&o, hc, &client), KFS_OK);

    CHECK(wait_until(h1, 2, KFS_NODE_UP, NULL));
    CHECK(wait_until(h2, 1, KFS_NODE_UP, NULL));
    CHECK(wait_until(hc, 1, KFS_NODE_UP, &rtt));
    CHECK(rtt > 0 && rtt < 1000000000);
    CHECK(wait_until(hc, 2, KFS_NODE_UP, NULL));
    /* Node 3's datagrams fail verification everywhere. */
    CHECK(wait_until(hc, 3, KFS_NODE_DOWN, NULL));
    CHECK(wait_until(h1, 3, KFS_NODE_DOWN, NULL));

    /* Stop node 2: the others notice within the timeout. */
    kfs_heartbeat_stop(n2);
    n2 = NULL;
    CHECK(wait_until(h1, 2, KFS_NODE_DOWN, NULL));
    CHECK(wait_until(hc, 2, KFS_NODE_DOWN, NULL));
    CHECK(kfs_health_usable(hc, 1));

    kfs_heartbeat_stop(client);
    kfs_heartbeat_stop(rogue);
    kfs_heartbeat_stop(n1);
    kfs_health_free(h1);
    kfs_health_free(h2);
    kfs_health_free(h3);
    kfs_health_free(hc);
}

int main(void)
{
    RUN(test_placement_is_deterministic);
    RUN(test_placement_balance_and_stability);
    RUN(test_health_table);
    RUN(test_live_heartbeats);
    TEST_EXIT();
}
