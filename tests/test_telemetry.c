/*
 * test_telemetry.c - The telemetry socket as a dashboard sees it.
 */
#define _GNU_SOURCE /* mkdtemp */

#include "krypton/krypton_telemetry.h"

#include <dirent.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "kfs_test.h"

#define BS 4096u

static char dir[] = "/tmp/kfs-tel-XXXXXX";
static char sock_path[100]; /* must fit sockaddr_un.sun_path (108) */

static int connect_unix(const char *path)
{
    struct sockaddr_un addr;
    struct timeval tv = { 3, 0 };
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* Reads one '\n'-terminated line into a growing heap buffer. */
static char *read_line(int fd)
{
    size_t cap = 4096, len = 0;
    char *s = malloc(cap);

    while (s != NULL) {
        char c;

        if (read(fd, &c, 1) != 1) {
            free(s);
            return NULL;
        }
        if (c == '\n') {
            s[len] = '\0';
            return s;
        }
        if (len + 1 == cap) {
            char *t = realloc(s, cap *= 2);

            if (t == NULL) {
                free(s);
                return NULL;
            }
            s = t;
        }
        s[len++] = c;
    }
    return NULL;
}

/* Next line whose type is `type` (skipping others). */
static char *next_of(int fd, const char *type)
{
    char want[64];

    snprintf(want, sizeof(want), "{\"type\":\"%s\"", type);
    for (int i = 0; i < 20; i++) {
        char *line = read_line(fd);

        if (line == NULL)
            return NULL;
        if (strncmp(line, want, strlen(want)) == 0)
            return line;
        free(line);
    }
    return NULL;
}

int main(void)
{
    uint8_t volume_key[KFS_KEY_SIZE];
    kfs_block_keys keys;
    kfs_cipher cipher;
    kfs_backend *backend;
    kfs_blockio io;
    kfs_fs_opts fo;
    kfs_fs *fs;
    kfs_cluster_config cl;
    kfs_health *health;
    kfs_heartbeat hb;
    kfs_telemetry_sources src;
    kfs_telemetry *tel = NULL;
    struct stat st;
    char *line;
    int fd;

    if (mkdtemp(dir) == NULL)
        return 1;
    memset(volume_key, 1, sizeof(volume_key));
    kfs_block_keys_derive(volume_key, &keys);
    kfs_cipher_local(&cipher, &keys);
    memset(&fo, 0, sizeof(fo));
    fo.block_size = BS;
    fo.cache_bytes = 32 * BS;
    fo.format_if_empty = true;
    if (kfs_backend_open_local(dir, &backend) != KFS_OK ||
        kfs_blockio_init(&io, &cipher, backend) != KFS_OK ||
        kfs_fs_open(&io, &fo, &fs) != KFS_OK)
        return 1;
    kfs_fs_mkdir(fs, "/docs", 0755, 0, 0);
    kfs_fs_create(fs, "/docs/report.txt", 0644, 0, 0);
    kfs_fs_write(fs, "/docs/report.txt", (const uint8_t *)"hello", 5, 0);
    /* Hostile names must still produce valid JSON. */
    kfs_fs_create(fs, "/quote\"back\\slash\nnewline", 0644, 0, 0);
    kfs_fs_create(fs, "/bad-utf8-\xff\xfe", 0644, 0, 0);

    memset(&cl, 0, sizeof(cl));
    cl.peer_count = 1;
    cl.peers[0].node_id = 7;
    cl.heartbeat_timeout_ms = 60000;
    health = kfs_health_new(&cl);
    memset(&hb, 0, sizeof(hb));
    hb.node_id = 7;
    hb.state = KFS_NODE_UP;
    hb.seq = 1;
    hb.disk_total = 1000;
    hb.disk_used = 400;
    kfs_health_observe(health, &hb, kfs_mono_ns());
    kfs_health_set_rtt(health, 7, 2500000);

    memset(&src, 0, sizeof(src));
    src.fs = fs;
    src.health = health;
    src.volume_name = "vault";
    src.mountpoint = "/mnt/vault";
    src.backend = "cluster";
    src.block_size = BS;
    src.kdf_iterations = 600000;
    snprintf(sock_path, sizeof(sock_path), "%s/run/telemetry.sock", dir);

    CHECK_EQ(kfs_telemetry_start(sock_path, 100, &src, &tel), KFS_OK);
    if (tel == NULL)
        return 1;
    kfs_telemetry_event(tel, KFS_EV_ALERT, "scanner", "blocked write to %s", "/x \"quoted\"");
    kfs_telemetry_event(NULL, KFS_EV_INFO, "noop", "NULL handle is ignored");

    CHECK_EQ(stat(sock_path, &st), 0);
    CHECK_EQ(st.st_mode & 0777, 0600); /* carries decrypted names: owner only */

    fd = connect_unix(sock_path);
    CHECK(fd >= 0);
    if (fd < 0)
        return 1;

    line = next_of(fd, "events");
    CHECK(line != NULL && strstr(line, "\"level\":\"alert\",\"kind\":\"scanner\"") != NULL);
    CHECK(line != NULL && strstr(line, "blocked write to /x \\\"quoted\\\"") != NULL);
    free(line);

    line = next_of(fd, "tree");
    CHECK(line != NULL);
    if (line != NULL) {
        CHECK(strstr(line, "{\"path\":\"/\",\"dir\":true,\"size\":0,\"depth\":0}") != NULL);
        CHECK(strstr(line, "{\"path\":\"/docs/report.txt\",\"dir\":false,\"size\":5,\"depth\":2}") != NULL);
        CHECK(strstr(line, "/quote\\\"back\\\\slash\\u000anewline") != NULL);
        CHECK(strstr(line, "/bad-utf8-\\ufffd\\ufffd") != NULL);
        CHECK(strstr(line, "\"truncated\":false") != NULL);
        free(line);
    }

    kfs_telemetry_io(tel, false, 4096, 200000, true);
    kfs_telemetry_io(tel, false, 4096, 400000, true);
    kfs_telemetry_io(tel, true, 100, 1000000, true);
    kfs_telemetry_io(tel, true, 0, 0, false);
    line = next_of(fd, "snapshot");
    CHECK(line != NULL);
    if (line != NULL) {
        CHECK(strstr(line, "\"volume\":{\"name\":\"vault\",\"mountpoint\":\"/mnt/vault\","
                           "\"backend\":\"cluster\",\"block_size\":4096}") != NULL);
        CHECK(strstr(line, "\"read_ops\":2,\"write_ops\":1,\"read_bytes\":8192,\"write_bytes\":100") != NULL);
        CHECK(strstr(line, "\"read_lat_us\":300,\"write_lat_us\":1000,\"read_lat_max_us\":400") != NULL);
        CHECK(strstr(line, "\"errors\":1") != NULL);
        CHECK(strstr(line, "\"usage\":{\"files\":3,\"dirs\":2") != NULL);
        CHECK(strstr(line, "{\"id\":7,\"state\":\"up\",\"rtt_us\":2500,\"disk_total\":1000,\"disk_used\":400") != NULL);
        CHECK(strstr(line, "\"kdf_iterations\":600000") != NULL);
        CHECK(strstr(line, "\"kind\":\"cluster\",\"msg\":\"node 7 is up\"") != NULL);
        free(line);
    }
    /* Counters are per interval: the next snapshot starts from zero. */
    line = next_of(fd, "snapshot");
    CHECK(line != NULL && strstr(line, "\"read_ops\":0,\"write_ops\":0") != NULL);
    free(line);

    close(fd);
    kfs_telemetry_stop(tel);
    CHECK(access(sock_path, F_OK) != 0); /* removed on stop */
    kfs_health_free(health);
    kfs_fs_close(fs);
    kfs_blockio_destroy(&io);
    kfs_backend_close(backend);
    printf("%s test_telemetry\n", kfs_test_failures == 0 ? "PASS" : "FAIL");
    TEST_EXIT();
}
