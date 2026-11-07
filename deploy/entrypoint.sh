#!/usr/bin/env bash
# entrypoint.sh - KryptonFS on one server: three storage nodes, the client
# daemon and the Krypton Console (production mode), with all state in
# /var/lib/kryptonfs. See deploy/DEPLOY.md.
#
#   init            create keys and configs, then the encrypted volume
#                   (asks for the new volume passphrase twice)
#   serve           run everything (the default); the volume stays locked
#                   until someone unlocks it from the console
#   hash-password   print a KFS_WEB_PASSWORD_HASH value for .env
#
# The volume passphrase is never stored here: it only passes through the
# console when someone unlocks the volume, straight to the daemon's stdin.
set -euo pipefail

K=/opt/kryptonfs
W=/var/lib/kryptonfs
MNT=/mnt/krypton
PY=$K/venv/bin/python
NODES=(1 2 3)
CLIENT=100
export PYTHONPATH=$K/python

log() { echo "[kryptonfs] $*"; }
die() { echo "[kryptonfs] $*" >&2; exit 1; }

rpc_port() { echo $((7400 + $1 * 10)); }
hb_port() { echo $((7401 + $1 * 10)); }

conf() { # <id> <telemetry socket>
    local self=$(( $1 % 10 ))
    cat <<EOF
[volume]
name = krypton
mountpoint = $MNT
[crypto]
node_key = $W/keys$1/node.key.pem
trusted_keys = $W/trusted
cluster_key = $W/cluster.key
[sandbox]
chroot_dir = $W/jail
[cache]
size = 64M
[cluster]
$(for n in "${NODES[@]}"; do echo "peer = $n 127.0.0.1 $(rpc_port "$n") $(hb_port "$n")"; done)
replication = 2
[node]
id = $1
bind = 127.0.0.1
rpc_port = $(rpc_port $self)
hb_port = $(hb_port $self)
data_dir = $W/data$1
io_threads = 4
[telemetry]
socket = $2
EOF
}

start_nodes() {
    for n in "${NODES[@]}"; do
        "$K/src/node/kfs-noded" -c "$W/node$n.conf" >>"$W/node$n.log" 2>&1 &
        echo $! >"$W/node$n.pid"
    done
    sleep 1
    for n in "${NODES[@]}"; do
        kill -0 "$(cat "$W/node$n.pid")" 2>/dev/null || { tail -5 "$W/node$n.log"; die "node $n did not start"; }
    done
    log "storage nodes ${NODES[*]} are up"
}

stop_nodes() {
    for n in "${NODES[@]}"; do
        [ -f "$W/node$n.pid" ] && kill "$(cat "$W/node$n.pid")" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}

# On docker stop: unmount first, so the client writes its cache back to
# the nodes, and only then stop the nodes.
shutdown() {
    [ -n "${console:-}" ] && kill "$console" 2>/dev/null || true
    if mountpoint -q "$MNT"; then
        fusermount3 -u "$MNT" 2>/dev/null || fusermount3 -uz "$MNT" 2>/dev/null || true
        for _ in $(seq 100); do
            kill -0 "$(cat "$W/client.pid" 2>/dev/null)" 2>/dev/null || break
            sleep 0.1
        done
    fi
    stop_nodes
}

init() {
    [ -f "$W/client.conf" ] && die "already initialised ($W/client.conf exists); nothing to do"
    umask 077
    mkdir -p "$W/trusted" "$W/jail"
    chmod 755 "$W" "$W/jail"
    for id in "${NODES[@]}" $CLIENT; do
        mkdir -p "$W/keys$id"
        "$K/tools/kfs-keygen" node "$id" "$W/keys$id" >/dev/null
        cp "$W/keys$id/$id.pub.pem" "$W/trusted/"
    done
    "$K/tools/kfs-keygen" cluster "$W/cluster.key" >/dev/null
    for n in "${NODES[@]}"; do conf "$n" "$W/node$n.sock" >"$W/node$n.conf"; done
    conf $CLIENT /run/kryptonfs/telemetry.sock >"$W/client.conf.new"
    log "keys and configs created in $W"

    start_nodes
    trap stop_nodes EXIT
    log "choose the volume passphrase: a long one, kept somewhere safe; it cannot be recovered"
    "$K/tools/kfs-mkvol" -c "$W/client.conf.new" --owner 0:0
    mv "$W/client.conf.new" "$W/client.conf"
    log "volume created. Start the service with: docker compose up -d"
}

serve() {
    [ -f "$W/client.conf" ] || die "not initialised: run  docker compose run --rm kryptonfs init"
    [ -n "${KFS_WEB_PASSWORD_HASH:-}" ] || die "KFS_WEB_PASSWORD_HASH is not set (see DEPLOY.md)"
    mkdir -p "$MNT" /run/kryptonfs
    start_nodes
    trap shutdown EXIT
    trap 'exit 143' TERM INT
    export KFS_WEB_MODE=production KFS_WEB_DEMO=$W KFS_WEB_BIN=$K KFS_WEB_STATIC=$K/web \
           KFS_WEB_CLIENT_CONF=$W/client.conf KFS_WEB_NODES=1,2,3
    log "console listening on port 8080; unlock the volume from its Cluster page"
    "$PY" -m kryptonfs_web serve --host 0.0.0.0 --port 8080 &
    console=$!
    wait "$console"
}

case "${1:-serve}" in
    init) init ;;
    serve) serve ;;
    hash-password) exec "$PY" -m kryptonfs_web hash-password ;;
    *) sed -n '6,13p' "$0"; exit 2 ;;
esac
