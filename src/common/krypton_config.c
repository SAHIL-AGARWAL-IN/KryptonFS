/*
 * krypton_config.c - Defaults, INI parsing and validation for kfs_config.
 *
 * Parsing is table-driven: FIELDS maps each (section, key) to a typed
 * member of kfs_config with inclusive bounds, so a new setting is one
 * table row plus a default.
 */
#include "krypton/krypton_config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "krypton/krypton_ipc.h"
#include "krypton/krypton_protocol.h"

#define CFG_LINE_MAX 1024
#define CFG_FILE_MAX (1024u * 1024u)

#define KIB 1024ull
#define MIB (1024ull * KIB)
#define GIB (1024ull * MIB)

typedef enum field_type {
    T_STR,
    T_U16,
    T_U32,
    T_SIZE,
    T_BOOL,
    T_ACTION,
    T_PEER
} field_type;

typedef struct field_spec {
    const char *section;
    const char *key;
    field_type  type;
    size_t      offset;
    size_t      size;     /* T_STR: buffer capacity */
    uint64_t    min, max; /* numeric types: inclusive bounds */
} field_spec;

#define MEMBER_SIZE(m) sizeof(((kfs_config *)0)->m)

/* offsetof(kfs_config, m), but fails to compile unless m is sizeof(T)
 * bytes: a row with the wrong type macro would otherwise overrun m. */
#define CHECKED_OFFSET(m, T) \
    (offsetof(kfs_config, m) + 0 * sizeof(char[MEMBER_SIZE(m) == sizeof(T) ? 1 : -1]))

#define F_STR(s, k, m)          { s, k, T_STR,    offsetof(kfs_config, m), MEMBER_SIZE(m), 0, 0 }
#define F_U16(s, k, m, lo, hi)  { s, k, T_U16,    CHECKED_OFFSET(m, uint16_t), 0, lo, hi }
#define F_U32(s, k, m, lo, hi)  { s, k, T_U32,    CHECKED_OFFSET(m, uint32_t), 0, lo, hi }
#define F_SIZE(s, k, m, lo, hi) { s, k, T_SIZE,   CHECKED_OFFSET(m, uint64_t), 0, lo, hi }
#define F_BOOL(s, k, m)         { s, k, T_BOOL,   CHECKED_OFFSET(m, bool), 0, 0, 0 }
#define F_ACTION(s, k, m)       { s, k, T_ACTION, CHECKED_OFFSET(m, kfs_scan_action), 0, 0, 0 }
#define F_PEER(s, k)            { s, k, T_PEER,   0, 0, 0, 0 }

static const field_spec FIELDS[] = {
    F_STR   ("volume",    "name",                  volume.name),
    F_STR   ("volume",    "mountpoint",            volume.mountpoint),

    F_STR   ("crypto",    "node_key",              crypto.node_key),
    F_STR   ("crypto",    "trusted_keys",          crypto.trusted_keys),
    F_STR   ("crypto",    "cluster_key",           crypto.cluster_key),

    F_U32   ("sandbox",   "scan_workers",          sandbox.scan_workers, 1, 64),
    F_U32   ("sandbox",   "crypto_workers",        sandbox.crypto_workers, 1, 64),
    F_U32   ("sandbox",   "ipc_slots",             sandbox.ipc_slots, 1, KFS_IPC_MAX_SLOTS),
    F_STR   ("sandbox",   "chroot_dir",            sandbox.chroot_dir),
    F_U32   ("sandbox",   "uid",                   sandbox.uid, 1, UINT32_MAX - 1),
    F_U32   ("sandbox",   "gid",                   sandbox.gid, 1, UINT32_MAX - 1),

    F_SIZE  ("cache",     "size",                  cache.size_bytes, 1 * MIB, 64 * GIB),
    F_U32   ("cache",     "writeback_ms",          cache.writeback_ms, 10, 60000),
    F_BOOL  ("cache",     "lock_memory",           cache.lock_memory),

    F_PEER  ("cluster",   "peer"),
    F_U32   ("cluster",   "replication",           cluster.replication, 1, KFS_MAX_PEERS),
    F_U32   ("cluster",   "heartbeat_interval_ms", cluster.heartbeat_interval_ms, 50, 60000),
    F_U32   ("cluster",   "heartbeat_timeout_ms",  cluster.heartbeat_timeout_ms, 100, 600000),
    F_U32   ("cluster",   "rpc_timeout_ms",        cluster.rpc_timeout_ms, 100, 600000),

    F_U32   ("node",      "id",                    node.node_id, 1, UINT32_MAX),
    F_STR   ("node",      "bind",                  node.bind_addr),
    F_U16   ("node",      "rpc_port",              node.rpc_port, 1, UINT16_MAX),
    F_U16   ("node",      "hb_port",               node.hb_port, 1, UINT16_MAX),
    F_STR   ("node",      "data_dir",              node.data_dir),
    F_U32   ("node",      "io_threads",            node.io_threads, 1, 256),
    F_U32   ("node",      "max_connections",       node.max_connections, 1, 65535),

    F_BOOL  ("scanner",   "enabled",               scanner.enabled),
    F_BOOL  ("scanner",   "block_elf",             scanner.block_elf),
    F_STR   ("scanner",   "signatures",            scanner.signatures),
    F_ACTION("scanner",   "action",                scanner.action),

    F_BOOL  ("telemetry", "enabled",               telemetry.enabled),
    F_STR   ("telemetry", "socket",                telemetry.socket_path),
    F_U32   ("telemetry", "interval_ms",           telemetry.interval_ms, 50, 60000),
};

static void set_err(char *err, size_t errlen, const char *fmt, ...) KFS_PRINTF_FMT(3, 4);

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL || errlen == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static void set_str(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);

    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

#define SET_STR(member, src) set_str(member, sizeof(member), src)

static bool is_blank(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

static char lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* ASCII case-insensitive string equality. */
static bool ieq(const char *a, const char *b)
{
    while (*a != '\0' && lower(*a) == lower(*b)) {
        a++;
        b++;
    }
    return lower(*a) == lower(*b);
}

static char *trim(char *s)
{
    char *end;

    while (is_blank(*s))
        s++;
    end = s + strlen(s);
    while (end > s && is_blank(end[-1]))
        end--;
    *end = '\0';
    return s;
}

/* Plain decimal: no sign, no leading whitespace, no trailing junk. */
static bool parse_u64(const char *s, uint64_t *out)
{
    char *end;
    unsigned long long v;

    if (*s < '0' || *s > '9')
        return false;
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno == ERANGE || *end != '\0')
        return false;
    *out = (uint64_t)v;
    return true;
}

/* Decimal with an optional K, M or G suffix (powers of 1024). */
static bool parse_size(const char *s, uint64_t *out)
{
    char digits[32];
    size_t n = strlen(s);
    unsigned shift = 0;
    uint64_t v;

    if (n == 0 || n >= sizeof(digits))
        return false;
    memcpy(digits, s, n + 1);
    switch (lower(digits[n - 1])) {
    case 'k': shift = 10; break;
    case 'm': shift = 20; break;
    case 'g': shift = 30; break;
    default:  break;
    }
    if (shift != 0)
        digits[n - 1] = '\0';
    if (!parse_u64(digits, &v) || v > (UINT64_MAX >> shift))
        return false;
    *out = v << shift;
    return true;
}

static bool parse_bool(const char *s, bool *out)
{
    static const char *const yes[] = { "true", "yes", "on", "1" };
    static const char *const no[] = { "false", "no", "off", "0" };

    for (size_t i = 0; i < KFS_ARRAY_LEN(yes); i++) {
        if (ieq(s, yes[i])) {
            *out = true;
            return true;
        }
        if (ieq(s, no[i])) {
            *out = false;
            return true;
        }
    }
    return false;
}

/* "<node_id> <host> <rpc_port> <hb_port>", whitespace separated. */
static bool parse_peer(char *s, kfs_peer *peer)
{
    char *tok[4];
    size_t n = 0;
    uint64_t id, rpc, hb;

    while (n < KFS_ARRAY_LEN(tok)) {
        while (is_blank(*s))
            s++;
        if (*s == '\0')
            break;
        tok[n++] = s;
        while (*s != '\0' && !is_blank(*s))
            s++;
        if (*s != '\0')
            *s++ = '\0';
    }
    if (n != KFS_ARRAY_LEN(tok) || *trim(s) != '\0')
        return false;

    if (!parse_u64(tok[0], &id) || id == 0 || id > UINT32_MAX ||
        strlen(tok[1]) >= sizeof(peer->host) ||
        !parse_u64(tok[2], &rpc) || rpc == 0 || rpc > UINT16_MAX ||
        !parse_u64(tok[3], &hb) || hb == 0 || hb > UINT16_MAX)
        return false;

    peer->node_id = (uint32_t)id;
    SET_STR(peer->host, tok[1]);
    peer->rpc_port = (uint16_t)rpc;
    peer->hb_port = (uint16_t)hb;
    return true;
}

static const field_spec *find_field(const char *section, const char *key)
{
    for (size_t i = 0; i < KFS_ARRAY_LEN(FIELDS); i++) {
        if (strcmp(FIELDS[i].section, section) == 0 &&
            strcmp(FIELDS[i].key, key) == 0)
            return &FIELDS[i];
    }
    return NULL;
}

static bool section_known(const char *section)
{
    for (size_t i = 0; i < KFS_ARRAY_LEN(FIELDS); i++) {
        if (strcmp(FIELDS[i].section, section) == 0)
            return true;
    }
    return false;
}

static kfs_status apply_field(kfs_config *cfg, const field_spec *f,
                              char *value, unsigned lineno,
                              char *err, size_t errlen)
{
    unsigned char *dst = (unsigned char *)cfg + f->offset;
    uint64_t num;

    switch (f->type) {
    case T_STR: {
        size_t n = strlen(value);

        if (n >= 2 && value[0] == '"' && value[n - 1] == '"') {
            value[n - 1] = '\0';
            value++;
            n -= 2;
        }
        if (n >= f->size) {
            set_err(err, errlen, "line %u: [%s] %s exceeds %zu characters",
                    lineno, f->section, f->key, f->size - 1);
            return KFS_E_CONFIG;
        }
        memcpy(dst, value, n + 1);
        return KFS_OK;
    }

    case T_U16:
    case T_U32:
    case T_SIZE:
        if (!(f->type == T_SIZE ? parse_size(value, &num)
                                : parse_u64(value, &num))) {
            set_err(err, errlen, "line %u: [%s] %s: '%s' is not a valid %s",
                    lineno, f->section, f->key, value,
                    f->type == T_SIZE ? "size" : "number");
            return KFS_E_CONFIG;
        }
        if (num < f->min || num > f->max) {
            set_err(err, errlen, "line %u: [%s] %s = %llu is outside [%llu, %llu]",
                    lineno, f->section, f->key, (unsigned long long)num,
                    (unsigned long long)f->min, (unsigned long long)f->max);
            return KFS_E_CONFIG;
        }
        if (f->type == T_U16) {
            uint16_t v = (uint16_t)num;
            memcpy(dst, &v, sizeof(v));
        } else if (f->type == T_U32) {
            uint32_t v = (uint32_t)num;
            memcpy(dst, &v, sizeof(v));
        } else {
            memcpy(dst, &num, sizeof(num));
        }
        return KFS_OK;

    case T_BOOL: {
        bool v;

        if (!parse_bool(value, &v)) {
            set_err(err, errlen, "line %u: [%s] %s: '%s' is not a boolean",
                    lineno, f->section, f->key, value);
            return KFS_E_CONFIG;
        }
        memcpy(dst, &v, sizeof(v));
        return KFS_OK;
    }

    case T_ACTION: {
        kfs_scan_action v;

        if (ieq(value, "reject")) {
            v = KFS_SCAN_REJECT;
        } else if (ieq(value, "log")) {
            v = KFS_SCAN_LOG;
        } else {
            set_err(err, errlen, "line %u: [%s] %s: expected 'reject' or 'log'",
                    lineno, f->section, f->key);
            return KFS_E_CONFIG;
        }
        memcpy(dst, &v, sizeof(v));
        return KFS_OK;
    }

    case T_PEER: {
        kfs_cluster_config *cl = &cfg->cluster;

        if (cl->peer_count == KFS_MAX_PEERS) {
            set_err(err, errlen, "line %u: more than %d peers", lineno, KFS_MAX_PEERS);
            return KFS_E_CONFIG;
        }
        if (!parse_peer(value, &cl->peers[cl->peer_count])) {
            set_err(err, errlen,
                    "line %u: [cluster] peer expects '<node_id> <host> <rpc_port> <hb_port>'",
                    lineno);
            return KFS_E_CONFIG;
        }
        cl->peer_count++;
        return KFS_OK;
    }
    }
    return KFS_E_CONFIG;
}

void kfs_config_defaults(kfs_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    SET_STR(cfg->volume.name, "krypton");

    SET_STR(cfg->crypto.node_key, "/etc/kryptonfs/keys/node.key.pem");
    SET_STR(cfg->crypto.trusted_keys, "/etc/kryptonfs/keys/trusted");
    SET_STR(cfg->crypto.cluster_key, "/etc/kryptonfs/keys/cluster.key");

    cfg->sandbox.scan_workers = 2;
    cfg->sandbox.crypto_workers = 2;
    cfg->sandbox.ipc_slots = 64;
    SET_STR(cfg->sandbox.chroot_dir, "/var/empty/kryptonfs");
    cfg->sandbox.uid = 65534; /* nobody */
    cfg->sandbox.gid = 65534;

    cfg->cache.size_bytes = 256 * MIB;
    cfg->cache.writeback_ms = 500;
    cfg->cache.lock_memory = true;

    cfg->cluster.replication = 2;
    cfg->cluster.heartbeat_interval_ms = 1000;
    cfg->cluster.heartbeat_timeout_ms = 3000;
    cfg->cluster.rpc_timeout_ms = 5000;

    SET_STR(cfg->node.bind_addr, "0.0.0.0");
    cfg->node.rpc_port = KFS_DEFAULT_RPC_PORT;
    cfg->node.hb_port = KFS_DEFAULT_HB_PORT;
    SET_STR(cfg->node.data_dir, "/var/lib/kryptonfs");
    cfg->node.io_threads = 8;
    cfg->node.max_connections = 256;

    cfg->scanner.enabled = true;
    cfg->scanner.block_elf = true;
    cfg->scanner.action = KFS_SCAN_REJECT;

    cfg->telemetry.enabled = true;
    SET_STR(cfg->telemetry.socket_path, "/run/kryptonfs/telemetry.sock");
    cfg->telemetry.interval_ms = 500;
}

kfs_status kfs_config_parse(kfs_config *cfg, const char *text, size_t len,
                            char *err, size_t errlen)
{
    char section[KFS_NAME_MAX] = "";
    char line[CFG_LINE_MAX];
    unsigned lineno = 0;
    size_t pos = 0;

    /* Tolerate the UTF-8 byte-order mark some editors prepend. */
    if (len >= 3 && memcmp(text, "\xEF\xBB\xBF", 3) == 0)
        pos = 3;

    while (pos < len) {
        const char *nl = memchr(text + pos, '\n', len - pos);
        size_t n = (nl != NULL ? (size_t)(nl - text) : len) - pos;
        char *s, *eq, *key, *value;
        const field_spec *f;
        kfs_status st;

        lineno++;
        if (n >= sizeof(line)) {
            set_err(err, errlen, "line %u: longer than %d characters",
                    lineno, CFG_LINE_MAX - 1);
            return KFS_E_CONFIG;
        }
        memcpy(line, text + pos, n);
        line[n] = '\0';
        pos += n + 1;
        if (strlen(line) != n) {
            set_err(err, errlen, "line %u: contains a NUL byte", lineno);
            return KFS_E_CONFIG;
        }

        s = trim(line);
        if (*s == '\0' || *s == '#' || *s == ';')
            continue;

        if (*s == '[') {
            size_t sl = strlen(s);

            if (s[sl - 1] != ']') {
                set_err(err, errlen, "line %u: malformed section header", lineno);
                return KFS_E_CONFIG;
            }
            s[sl - 1] = '\0';
            s = trim(s + 1);
            if (!section_known(s)) {
                set_err(err, errlen, "line %u: unknown section [%s]", lineno, s);
                return KFS_E_CONFIG;
            }
            SET_STR(section, s);
            continue;
        }

        eq = strchr(s, '=');
        if (eq == NULL) {
            set_err(err, errlen, "line %u: expected 'key = value'", lineno);
            return KFS_E_CONFIG;
        }
        *eq = '\0';
        key = trim(s);
        value = trim(eq + 1);

        if (section[0] == '\0') {
            set_err(err, errlen, "line %u: '%s' appears before any [section]",
                    lineno, key);
            return KFS_E_CONFIG;
        }
        f = find_field(section, key);
        if (f == NULL) {
            set_err(err, errlen, "line %u: unknown key '%s' in [%s]",
                    lineno, key, section);
            return KFS_E_CONFIG;
        }
        st = apply_field(cfg, f, value, lineno, err, errlen);
        if (st != KFS_OK)
            return st;
    }
    return KFS_OK;
}

kfs_status kfs_config_load(kfs_config *cfg, const char *path,
                           char *err, size_t errlen)
{
    char detail[512];
    FILE *fp;
    char *buf;
    size_t n;
    kfs_status st;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        set_err(err, errlen, "%s: %s", path, strerror(errno));
        return KFS_E_IO;
    }
    buf = malloc(CFG_FILE_MAX + 1);
    if (buf == NULL) {
        fclose(fp);
        return KFS_E_NOMEM;
    }
    n = fread(buf, 1, CFG_FILE_MAX + 1, fp);
    if (ferror(fp)) {
        set_err(err, errlen, "%s: read failed", path);
        st = KFS_E_IO;
    } else if (n > CFG_FILE_MAX) {
        set_err(err, errlen, "%s: larger than %u bytes", path, CFG_FILE_MAX);
        st = KFS_E_CONFIG;
    } else {
        st = kfs_config_parse(cfg, buf, n, detail, sizeof(detail));
        if (st != KFS_OK)
            set_err(err, errlen, "%s: %s", path, detail);
    }
    fclose(fp);
    free(buf);
    return st;
}

#define REQUIRE(cond, ...)                     \
    do {                                       \
        if (!(cond)) {                         \
            set_err(err, errlen, __VA_ARGS__); \
            return KFS_E_CONFIG;               \
        }                                      \
    } while (0)

static bool is_abs_path(const char *p)
{
    return p[0] == '/';
}

kfs_status kfs_config_validate(const kfs_config *cfg, kfs_role role,
                               char *err, size_t errlen)
{
    const kfs_cluster_config *cl = &cfg->cluster;

    /* Both roles authenticate RPC peers and heartbeats. */
    REQUIRE(cfg->crypto.node_key[0] != '\0', "[crypto] node_key is required");
    REQUIRE(cfg->crypto.trusted_keys[0] != '\0', "[crypto] trusted_keys is required");
    REQUIRE(cfg->crypto.cluster_key[0] != '\0', "[crypto] cluster_key is required");

    for (uint32_t i = 0; i < cl->peer_count; i++) {
        const kfs_peer *p = &cl->peers[i];

        REQUIRE(p->node_id != 0 && p->host[0] != '\0' &&
                p->rpc_port != 0 && p->hb_port != 0,
                "[cluster] peer %u is incomplete", i + 1);
        for (uint32_t j = 0; j < i; j++)
            REQUIRE(cl->peers[j].node_id != p->node_id,
                    "[cluster] duplicate peer id %u", p->node_id);
    }
    REQUIRE(cl->replication >= 1, "[cluster] replication must be at least 1");
    REQUIRE(cl->peer_count == 0 || cl->replication <= cl->peer_count,
            "[cluster] replication (%u) exceeds peer count (%u)",
            cl->replication, cl->peer_count);
    REQUIRE(cl->heartbeat_interval_ms > 0 &&
            (uint64_t)cl->heartbeat_interval_ms * 2 <= cl->heartbeat_timeout_ms,
            "[cluster] heartbeat_timeout_ms (%u) must be at least twice heartbeat_interval_ms (%u)",
            cl->heartbeat_timeout_ms, cl->heartbeat_interval_ms);
    REQUIRE(!cfg->telemetry.enabled || cfg->telemetry.socket_path[0] != '\0',
            "[telemetry] socket is required when telemetry is enabled");

    if (role == KFS_ROLE_CLIENT) {
        const kfs_sandbox_config *sb = &cfg->sandbox;

        REQUIRE(is_abs_path(cfg->volume.mountpoint),
                "[volume] mountpoint must be an absolute path");
        REQUIRE(cfg->node.node_id != 0,
                "[node] id is required: it is this client's identity in handshakes");
        REQUIRE(cl->peer_count > 0, "[cluster] at least one peer is required");
        REQUIRE(is_abs_path(sb->chroot_dir) && strcmp(sb->chroot_dir, "/") != 0,
                "[sandbox] chroot_dir must be an absolute path other than /");
        REQUIRE(sb->uid != 0 && sb->gid != 0,
                "[sandbox] workers must not run as uid or gid 0");
        REQUIRE(sb->scan_workers > 0 && sb->crypto_workers > 0,
                "[sandbox] each worker pool needs at least one worker");
        REQUIRE(sb->ipc_slots > 0 && sb->ipc_slots <= KFS_IPC_MAX_SLOTS,
                "[sandbox] ipc_slots must be 1..%u", KFS_IPC_MAX_SLOTS);
    } else {
        const kfs_node_config *nd = &cfg->node;
        bool listed = cl->peer_count == 0;

        REQUIRE(nd->node_id != 0, "[node] id is required");
        REQUIRE(nd->bind_addr[0] != '\0', "[node] bind is required");
        REQUIRE(nd->rpc_port != 0 && nd->hb_port != 0,
                "[node] rpc_port and hb_port are required");
        REQUIRE(is_abs_path(nd->data_dir), "[node] data_dir must be an absolute path");
        REQUIRE(nd->io_threads > 0 && nd->max_connections > 0,
                "[node] io_threads and max_connections must be nonzero");
        for (uint32_t i = 0; i < cl->peer_count; i++)
            listed = listed || cl->peers[i].node_id == nd->node_id;
        REQUIRE(listed, "[node] id %u does not appear in [cluster] peers", nd->node_id);
    }
    return KFS_OK;
}
