/*
 * test_config.c - Defaults, parsing, error reporting and role validation.
 */
#include "krypton/krypton_config.h"

#include <stdlib.h>

#include "kfs_test.h"

static kfs_config cfg;
static char err[512];

static kfs_status parse(const char *text)
{
    err[0] = '\0';
    return kfs_config_parse(&cfg, text, strlen(text), err, sizeof(err));
}

static void reset(void)
{
    kfs_config_defaults(&cfg);
}

/* Smallest addition to the defaults that satisfies each role. */
static const char MINIMAL[] =
    "[volume]\n"
    "mountpoint = /mnt/k\n"
    "[cluster]\n"
    "peer = 1 node1 7400 7401\n"
    "peer = 2 node2 7400 7401\n"
    "[node]\n"
    "id = 2\n";

static void test_defaults_need_role_settings(void)
{
    reset();
    CHECK_EQ(kfs_config_validate(&cfg, KFS_ROLE_CLIENT, err, sizeof(err)), KFS_E_CONFIG);
    CHECK_EQ(kfs_config_validate(&cfg, KFS_ROLE_NODE, err, sizeof(err)), KFS_E_CONFIG);

    CHECK_EQ(parse(MINIMAL), KFS_OK);
    CHECK_EQ(kfs_config_validate(&cfg, KFS_ROLE_CLIENT, err, sizeof(err)), KFS_OK);
    CHECK_EQ(kfs_config_validate(&cfg, KFS_ROLE_NODE, err, sizeof(err)), KFS_OK);
}

static void test_parse_values(void)
{
    reset();
    CHECK_EQ(parse("\xEF\xBB\xBF# leading BOM and comment\r\n"
                   "[volume]\r\n"
                   "  name = \"secret vault\"  \r\n"
                   "; another comment\n"
                   "[cache]\n"
                   "size = 1G\n"
                   "lock_memory = Off\n"
                   "[scanner]\n"
                   "action = LOG\n"
                   "signatures =\n"
                   "[node]\n"
                   "rpc_port = 65535\n"
                   "[cluster]\n"
                   "peer =  9   [fd00::9]   9000   9001  \n"
                   "replication = 1"), /* no trailing newline */
             KFS_OK);
    CHECK_STR(cfg.volume.name, "secret vault");
    CHECK_EQ(cfg.cache.size_bytes, 1ull << 30);
    CHECK(!cfg.cache.lock_memory);
    CHECK_EQ(cfg.scanner.action, KFS_SCAN_LOG);
    CHECK_STR(cfg.scanner.signatures, "");
    CHECK_EQ(cfg.node.rpc_port, 65535);
    CHECK_EQ(cfg.cluster.peer_count, 1);
    CHECK_EQ(cfg.cluster.peers[0].node_id, 9);
    CHECK_STR(cfg.cluster.peers[0].host, "[fd00::9]");
    CHECK_EQ(cfg.cluster.peers[0].rpc_port, 9000);
    CHECK_EQ(cfg.cluster.peers[0].hb_port, 9001);
    CHECK_EQ(cfg.cluster.replication, 1);
}

static void expect_parse_error(const char *text, const char *fragment)
{
    reset();
    CHECK_EQ(parse(text), KFS_E_CONFIG);
    if (strstr(err, fragment) == NULL) {
        fprintf(stderr, "error \"%s\" lacks \"%s\"\n", err, fragment);
        kfs_test_failures++;
    }
}

static void test_parse_errors(void)
{
    expect_parse_error("[bogus]\n", "line 1: unknown section [bogus]");
    expect_parse_error("\n\n[node]\nport = 1\n", "line 4: unknown key 'port' in [node]");
    expect_parse_error("id = 1\n", "before any [section]");
    expect_parse_error("[node\n", "malformed section header");
    expect_parse_error("[node]\nid\n", "expected 'key = value'");
    expect_parse_error("[sandbox]\nuid = 0\n", "uid = 0 is outside");
    expect_parse_error("[node]\nrpc_port = 65536\n", "outside");
    expect_parse_error("[node]\nid = -1\n", "not a valid number");
    expect_parse_error("[node]\nid = 12abc\n", "not a valid number");
    expect_parse_error("[node]\nid = 99999999999999999999999\n", "not a valid number");
    expect_parse_error("[cache]\nsize = 16T\n", "not a valid size");
    expect_parse_error("[cache]\nlock_memory = maybe\n", "not a boolean");
    expect_parse_error("[scanner]\naction = quarantine\n", "expected 'reject' or 'log'");
    expect_parse_error("[cluster]\npeer = 1 host 7400\n", "peer expects");
    expect_parse_error("[cluster]\npeer = 1 host 7400 7401 extra\n", "peer expects");
    expect_parse_error("[cluster]\npeer = 0 host 7400 7401\n", "peer expects");
}

static void test_long_values(void)
{
    char *text = malloc(2 * KFS_PATH_MAX);
    int n;

    CHECK(text != NULL);
    if (text == NULL)
        return;
    n = snprintf(text, 2 * KFS_PATH_MAX, "[node]\ndata_dir = /");
    memset(text + n, 'a', KFS_PATH_MAX);
    text[n + KFS_PATH_MAX] = '\0';
    expect_parse_error(text, "exceeds 511 characters");
    free(text);

    reset();
    {
        char line[2048];
        memset(line, ' ', sizeof(line));
        line[sizeof(line) - 1] = '\0';
        CHECK_EQ(parse(line), KFS_E_CONFIG);
        CHECK(strstr(err, "longer than") != NULL);
    }
}

static void test_too_many_peers(void)
{
    char *text = malloc(8192);
    size_t off = 0;

    CHECK(text != NULL);
    if (text == NULL)
        return;
    off += (size_t)snprintf(text, 8192, "[cluster]\n");
    for (int i = 1; i <= KFS_MAX_PEERS + 1; i++)
        off += (size_t)snprintf(text + off, 8192 - off, "peer = %d h 1 2\n", i);
    expect_parse_error(text, "more than 64 peers");
    CHECK_EQ(cfg.cluster.peer_count, KFS_MAX_PEERS);
    free(text);
}

static void expect_invalid(kfs_role role, const char *extra, const char *fragment)
{
    reset();
    CHECK_EQ(parse(MINIMAL), KFS_OK);
    CHECK_EQ(parse(extra), KFS_OK);
    CHECK_EQ(kfs_config_validate(&cfg, role, err, sizeof(err)), KFS_E_CONFIG);
    if (strstr(err, fragment) == NULL) {
        fprintf(stderr, "error \"%s\" lacks \"%s\"\n", err, fragment);
        kfs_test_failures++;
    }
}

static void test_validation(void)
{
    expect_invalid(KFS_ROLE_CLIENT, "[cluster]\nreplication = 3\n", "replication (3) exceeds peer count (2)");
    expect_invalid(KFS_ROLE_CLIENT, "[cluster]\npeer = 1 dup 1 2\n", "duplicate peer id 1");
    expect_invalid(KFS_ROLE_CLIENT, "[cluster]\nheartbeat_timeout_ms = 1500\n", "at least twice");
    expect_invalid(KFS_ROLE_CLIENT, "[sandbox]\nchroot_dir = /\n", "chroot_dir");
    expect_invalid(KFS_ROLE_CLIENT, "[sandbox]\nchroot_dir = jail\n", "chroot_dir");
    expect_invalid(KFS_ROLE_CLIENT, "[volume]\nmountpoint = mnt\n", "mountpoint");
    expect_invalid(KFS_ROLE_CLIENT, "[crypto]\nnode_key =\n", "node_key is required");
    expect_invalid(KFS_ROLE_CLIENT, "[telemetry]\nsocket = \"\"\n", "socket is required");
    expect_invalid(KFS_ROLE_NODE, "[node]\nid = 5\n", "id 5 does not appear");
    expect_invalid(KFS_ROLE_NODE, "[node]\ndata_dir = data\n", "data_dir");

    /* Settings irrelevant to a role do not block it. */
    reset();
    CHECK_EQ(parse(MINIMAL), KFS_OK);
    CHECK_EQ(parse("[sandbox]\nchroot_dir = /\n"), KFS_OK);
    CHECK_EQ(kfs_config_validate(&cfg, KFS_ROLE_NODE, err, sizeof(err)), KFS_OK);
}

static void test_example_config(void)
{
    reset();
    CHECK_EQ(kfs_config_load(&cfg, KFS_EXAMPLE_CONFIG, err, sizeof(err)), KFS_OK);
    if (err[0] != '\0')
        fprintf(stderr, "%s\n", err);
    CHECK_EQ(kfs_config_validate(&cfg, KFS_ROLE_CLIENT, err, sizeof(err)), KFS_OK);
    CHECK_EQ(kfs_config_validate(&cfg, KFS_ROLE_NODE, err, sizeof(err)), KFS_OK);
    CHECK_EQ(cfg.cluster.peer_count, 3);
    CHECK_EQ(cfg.cache.size_bytes, 256ull << 20);
}

static void test_load_missing_file(void)
{
    reset();
    CHECK_EQ(kfs_config_load(&cfg, "/nonexistent/kryptonfs.conf", err, sizeof(err)), KFS_E_IO);
    CHECK(strstr(err, "/nonexistent/kryptonfs.conf") != NULL);
}

int main(void)
{
    RUN(test_defaults_need_role_settings);
    RUN(test_parse_values);
    RUN(test_parse_errors);
    RUN(test_long_values);
    RUN(test_too_many_peers);
    RUN(test_validation);
    RUN(test_example_config);
    RUN(test_load_missing_file);
    TEST_EXIT();
}
