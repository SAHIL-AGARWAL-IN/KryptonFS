#!/usr/bin/env bash
# cluster_smoke.sh - Three storage nodes and a FUSE client, end to end
# (Linux, as root). Every host has its own RSA identity; replication = 2.
#
#   docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --cap-add IPC_LOCK \
#       -v "$PWD":/src -w /src kryptonfs-dev tests/integration/cluster_smoke.sh build-linux
set -uo pipefail

BUILD=${1:-build}
KRYPTONFS=$BUILD/src/fuse/kryptonfs
NODED=$BUILD/src/node/kfs-noded
MKVOL=$BUILD/tools/kfs-mkvol
KEYGEN=$BUILD/tools/kfs-keygen
WORK=$(mktemp -d /tmp/kfs-cluster-XXXXXX)
MNT=$WORK/mnt
PASS='cluster test passphrase'
declare -A NODE_PID
DPID=
passed=0 failed=0

check() {
    local desc=$1
    shift
    if "$@"; then
        echo "PASS $desc"
        passed=$((passed + 1))
    else
        echo "FAIL $desc"
        failed=$((failed + 1))
    fi
}

rpc_port() { echo $((17400 + $1 * 10)); }
hb_port() { echo $((17401 + $1 * 10)); }

# write_conf <file> <id> <key dir>
write_conf() {
    cat >"$1" <<EOF
[volume]
mountpoint = $MNT
[crypto]
node_key = $3/node.key.pem
trusted_keys = $WORK/trusted
cluster_key = $WORK/cluster.key
[sandbox]
chroot_dir = $WORK/jail
[cache]
size = 1M
[cluster]
peer = 1 127.0.0.1 $(rpc_port 1) $(hb_port 1)
peer = 2 127.0.0.1 $(rpc_port 2) $(hb_port 2)
peer = 3 127.0.0.1 $(rpc_port 3) $(hb_port 3)
replication = 2
heartbeat_interval_ms = 200
heartbeat_timeout_ms = 1000
rpc_timeout_ms = 2000
[node]
id = $2
bind = 127.0.0.1
rpc_port = $(rpc_port "$2")
hb_port = $(hb_port "$2")
data_dir = $WORK/data$2
io_threads = 4
[telemetry]
socket = $WORK/telemetry.sock
EOF
}

start_node() { # id
    "$NODED" -c "$WORK/node$1.conf" >>"$WORK/node$1.log" 2>&1 &
    NODE_PID[$1]=$!
    for _ in $(seq 50); do
        (echo >"/dev/tcp/127.0.0.1/$(rpc_port "$1")") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

mount_fs() { # config
    KRYPTONFS_PASSPHRASE=$PASS "$KRYPTONFS" -c "$1" "$MNT" >>"$WORK/client.log" 2>&1 &
    DPID=$!
    for _ in $(seq 100); do
        mountpoint -q "$MNT" && return 0
        kill -0 "$DPID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

unmount_fs() {
    fusermount3 -u "$MNT" && wait "$DPID"
}

# Every stored object, as "<count> <id>": how many nodes hold it.
replica_counts() {
    for i in 1 2 3; do
        find "$WORK/data$i" -type f ! -name '.tmp.*' -printf '%f\n'
    done | sort | uniq -c
}

cleanup() {
    mountpoint -q "$MNT" && fusermount3 -u "$MNT"
    [ -n "$DPID" ] && wait "$DPID" 2>/dev/null
    for pid in "${NODE_PID[@]}"; do kill "$pid" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$MNT" "$WORK/jail" "$WORK/trusted"
chmod 755 "$WORK"

# --- identities -----------------------------------------------------------
for id in 1 2 3 100; do
    mkdir -p "$WORK/keys$id"
    "$KEYGEN" node "$id" "$WORK/keys$id" >/dev/null
    cp "$WORK/keys$id/$id.pub.pem" "$WORK/trusted/"
done
mkdir -p "$WORK/rogue" && "$KEYGEN" node 100 "$WORK/rogue" >/dev/null # not trusted
"$KEYGEN" cluster "$WORK/cluster.key" >/dev/null
for id in 1 2 3; do write_conf "$WORK/node$id.conf" "$id" "$WORK/keys$id"; done
write_conf "$WORK/client.conf" 100 "$WORK/keys100"
write_conf "$WORK/rogue.conf" 100 "$WORK/rogue"

# --- cluster up, volume created -------------------------------------------
for id in 1 2 3; do check "node $id starts" start_node "$id"; done
check "kfs-mkvol creates a volume on the cluster" \
    env KRYPTONFS_PASSPHRASE="$PASS" "$MKVOL" -c "$WORK/client.conf" --owner 0:0
check "kfs-mkvol refuses to overwrite it" \
    bash -c "! env KRYPTONFS_PASSPHRASE=x '$MKVOL' -c '$WORK/client.conf' 2>/dev/null"
check "client mounts from the cluster" mount_fs "$WORK/client.conf"

# --- data path ------------------------------------------------------------
echo "hello cluster" >"$MNT/hello.txt"
head -c 2000000 /dev/urandom >"$WORK/random.bin"
mkdir "$MNT/dir"
cp "$WORK/random.bin" "$MNT/dir/random.bin"
check "small file round-trips" test "$(cat "$MNT/hello.txt")" = "hello cluster"
check "2 MB file round-trips" cmp -s "$WORK/random.bin" "$MNT/dir/random.bin"
check "telemetry shows 3 healthy nodes with RTT" python3 -I "$(dirname "$0")/telemetry_probe.py" \
    "$WORK/telemetry.sock" 1.5 --expect-nodes 3 --expect-file /dir/random.bin
check "clean unmount" unmount_fs

objects=$(replica_counts | wc -l)
check "objects were stored ($objects)" test "$objects" -gt 400
all_twice() { [ -z "$(replica_counts | awk '$1 != 2')" ]; }
check "every object is on exactly 2 of 3 nodes" all_twice
for i in 1 2 3; do
    check "node $i holds no plaintext" bash -c "! grep -rqa -e 'hello cluster' -e 'random.bin' '$WORK/data$i'"
done

# --- node failure ---------------------------------------------------------
check "remount" mount_fs "$WORK/client.conf"
kill -9 "${NODE_PID[1]}"
wait "${NODE_PID[1]}" 2>/dev/null
sleep 1.5 # past the heartbeat timeout: node 1 is DOWN
check "reads survive a dead node" cmp -s "$WORK/random.bin" "$MNT/dir/random.bin"
echo "written while node 1 was down" >"$MNT/late.txt"
check "writes survive a dead node" sync "$MNT/late.txt"
check "unmount with a dead node" unmount_fs

check "node 1 restarts (now stale)" start_node 1
sleep 1
check "remount with a stale replica back" mount_fs "$WORK/client.conf"
check "stale replica does not hide new data" \
    test "$(cat "$MNT/late.txt")" = "written while node 1 was down"
check "old data still intact" cmp -s "$WORK/random.bin" "$MNT/dir/random.bin"
check "unmount" unmount_fs

# --- a node turns malicious -----------------------------------------------
# Flip a byte inside every object node 2 holds: ciphertext for blocks,
# the wrapped key for the volume header.
find "$WORK/data2" -type f ! -name '.tmp.*' | while read -r obj; do
    printf '\xff' | dd of="$obj" bs=1 seek=60 conv=notrunc status=none
done
check "remount with every object on node 2 corrupted" mount_fs "$WORK/client.conf"
check "data verified and served from honest replicas" cmp -s "$WORK/random.bin" "$MNT/dir/random.bin"
check "metadata too" test "$(cat "$MNT/hello.txt")" = "hello cluster"
check "unmount" unmount_fs

# --- impostor client ------------------------------------------------------
check "client with an unpinned key is refused" bash -c "! KRYPTONFS_PASSPHRASE='$PASS' \
    '$KRYPTONFS' -c '$WORK/rogue.conf' '$MNT' >'$WORK/rogue.log' 2>&1"
check "and nothing is mounted" bash -c "! mountpoint -q '$MNT'"

# --- graceful shutdown ----------------------------------------------------
kill -TERM "${NODE_PID[3]}"
check "node 3 exits cleanly on SIGTERM" wait "${NODE_PID[3]}"
unset 'NODE_PID[3]'

echo
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
