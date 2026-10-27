#!/usr/bin/env bash
# demo-cluster.sh - A complete KryptonFS demo in one Linux environment:
# three storage nodes, a client mounting an encrypted volume at
# /mnt/krypton with sample files and light activity, and the dashboard in
# tmux session "dash". Runs until stopped. Normally started by run.cmd /
# run.sh, which run it inside the dev container as root.
#
# Demo only: every key is generated fresh in /demo and the passphrase is
# fixed (KRYPTONFS_DEMO_PASSPHRASE, default below). Never use this setup
# for real data.
set -uo pipefail

SRC=$(cd "$(dirname "$0")/.." && pwd)
B=$SRC/build-linux
W=/demo
MNT=/mnt/krypton
export KRYPTONFS_PASSPHRASE=${KRYPTONFS_DEMO_PASSPHRASE:-krypton demo passphrase}
log() { echo "[demo] $*"; }
fail() { echo "[demo] FAILED: $*"; exit 1; }

log "building KryptonFS"
make -C "$SRC" build BUILD_DIR=build-linux >/tmp/build.log 2>&1 || { tail -20 /tmp/build.log; fail "build"; }

rm -rf "$W"
mkdir -p "$W/jail" "$W/trusted" "$MNT" /run/kryptonfs
chmod 755 "$W"

log "creating identities for nodes 1-3 and client 100"
for id in 1 2 3 100; do
    mkdir -p "$W/keys$id"
    "$B/tools/kfs-keygen" node "$id" "$W/keys$id" >/dev/null || fail "keygen $id"
    cp "$W/keys$id/$id.pub.pem" "$W/trusted/"
done
"$B/tools/kfs-keygen" cluster "$W/cluster.key" >/dev/null || fail "cluster key"

rpc_port() { echo $((7400 + $1 * 10)); }
hb_port() { echo $((7401 + $1 * 10)); }

conf() { # <id> <key dir> <telemetry socket>
    cat <<EOF
[volume]
name = krypton
mountpoint = $MNT
[crypto]
node_key = $2/node.key.pem
trusted_keys = $W/trusted
cluster_key = $W/cluster.key
[sandbox]
chroot_dir = $W/jail
[cache]
size = 8M
[cluster]
peer = 1 127.0.0.1 $(rpc_port 1) $(hb_port 1)
peer = 2 127.0.0.1 $(rpc_port 2) $(hb_port 2)
peer = 3 127.0.0.1 $(rpc_port 3) $(hb_port 3)
replication = 2
heartbeat_interval_ms = 300
heartbeat_timeout_ms = 1500
[node]
id = $1
bind = 127.0.0.1
rpc_port = $(rpc_port $(( $1 % 10 )))
hb_port = $(hb_port $(( $1 % 10 )))
data_dir = $W/data$1
io_threads = 4
[telemetry]
socket = $3
interval_ms = 500
EOF
}

for id in 1 2 3; do
    conf "$id" "$W/keys$id" "$W/node$id.sock" >"$W/node$id.conf"
    "$B/src/node/kfs-noded" -c "$W/node$id.conf" >"$W/node$id.log" 2>&1 &
    echo $! >"$W/node$id.pid"
done
conf 100 "$W/keys100" /run/kryptonfs/telemetry.sock >"$W/client.conf"
sleep 1
for id in 1 2 3; do
    kill -0 "$(cat "$W/node$id.pid")" 2>/dev/null || { cat "$W/node$id.log"; fail "node $id"; }
done
log "storage nodes 1, 2 and 3 are up"

"$B/tools/kfs-mkvol" -c "$W/client.conf" --owner 0:0 >/dev/null || fail "kfs-mkvol"
"$B/src/fuse/kryptonfs" -c "$W/client.conf" "$MNT" >"$W/client.log" 2>&1 &
echo $! >"$W/client.pid"
for _ in $(seq 100); do mountpoint -q "$MNT" && break; sleep 0.1; done
mountpoint -q "$MNT" || { cat "$W/client.log"; fail "mount"; }
log "encrypted volume mounted at $MNT"

mkdir -p "$MNT"/{documents,photos,projects/notes}
echo "Welcome to KryptonFS. This file is encrypted on disk." >"$MNT/documents/welcome.txt"
echo "Ideas: an encrypted, replicated filesystem" >"$MNT/projects/notes/ideas.md"
head -c 2000000 /dev/urandom >"$MNT/photos/sample-photo.raw"

# Light, steady activity so the dashboard has something to show, plus a
# harmful-looking write every 30 s that the scanner should block.
(
    i=0
    while mountpoint -q "$MNT"; do
        i=$((i + 1))
        cat "$MNT/photos/sample-photo.raw" >/dev/null 2>&1
        head -c $((RANDOM * 4)) /dev/urandom >"$MNT/projects/scratch.bin" 2>/dev/null
        [ $((i % 60)) -eq 1 ] && printf '\x7fELF\x02\x01\x01' >"$MNT/projects/blocked-sample.elf" 2>/dev/null
        sleep 0.5
    done
) &

tmux new-session -d -s dash -x 160 -y 46 \
    "PYTHONPATH=$SRC/dashboard /opt/dash/bin/python -m kryptonfs_dash; echo; echo 'Dashboard closed. The cluster is still running.'; sleep 3"
log "READY"
sleep infinity
