#!/usr/bin/env bash
# fuse_smoke.sh - End-to-end test of a real KryptonFS mount (Linux, as root).
#
#   docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --cap-add IPC_LOCK \
#       -v "$PWD":/src -w /src kryptonfs-dev tests/integration/fuse_smoke.sh build-linux
#
# SYS_ADMIN mounts FUSE; IPC_LOCK lets the daemon mlock its page cache.
set -uo pipefail

BUILD=${1:-build}
KRYPTONFS=$BUILD/src/fuse/kryptonfs
MKVOL=$BUILD/tools/kfs-mkvol
WORK=$(mktemp -d /tmp/kfs-it-XXXXXX)
STORE=$WORK/store MNT=$WORK/mnt JAIL=$WORK/jail CONF=$WORK/kryptonfs.conf SIGS=$WORK/test.sigs
PASS='integration test passphrase'
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

mount_fs() { # passphrase
    KRYPTONFS_PASSPHRASE=$1 "$KRYPTONFS" -c "$CONF" --local-store="$STORE" "$MNT" \
        >"$WORK/daemon.log" 2>&1 &
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

cleanup() {
    mountpoint -q "$MNT" && fusermount3 -u "$MNT"
    [ -n "$DPID" ] && wait "$DPID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$STORE" "$MNT" "$JAIL"
chmod 755 "$WORK" # mktemp makes it 0700; other users must reach the mount
# Placeholder signature: the ASCII bytes of "KFS-TEST-SIG-1".
printf '# harmless test pattern\n100 4b46532d544553542d5349472d31 test-signature\n' >"$SIGS"
sed -e "s|^chroot_dir = .*|chroot_dir = $JAIL|" \
    -e "s|^signatures =.*|signatures = $SIGS|" \
    -e "s|^size = .*|size = 1M|" \
    -e "s|^socket = .*|socket = $WORK/telemetry.sock|" \
    config/kryptonfs.conf.example >"$CONF"

# --- create and mount -----------------------------------------------------
check "kfs-mkvol creates a volume" \
    env KRYPTONFS_PASSPHRASE="$PASS" "$MKVOL" --local-store "$STORE" --owner 1000:1000
check "kfs-mkvol refuses to overwrite it" \
    bash -c "! env KRYPTONFS_PASSPHRASE=x '$MKVOL' --local-store '$STORE' 2>/dev/null"
check "mount succeeds" mount_fs "$PASS"

# --- file operations ------------------------------------------------------
echo "hello krypton" >"$MNT/hello.txt"
check "small file round-trips" test "$(cat "$MNT/hello.txt")" = "hello krypton"

mkdir -p "$MNT/docs/deep"
head -c 3000000 /dev/urandom >"$WORK/random.bin"
cp "$WORK/random.bin" "$MNT/docs/deep/random.bin"
check "3 MB random file round-trips" cmp -s "$WORK/random.bin" "$MNT/docs/deep/random.bin"
check "size is reported" test "$(stat -c %s "$MNT/docs/deep/random.bin")" = 3000000

mv "$MNT/hello.txt" "$MNT/docs/greeting.txt"
check "rename moves the file" test -f "$MNT/docs/greeting.txt" -a ! -e "$MNT/hello.txt"
echo "temp" >"$MNT/temp.txt" && rm "$MNT/temp.txt"
check "unlink removes the file" test ! -e "$MNT/temp.txt"
check "readdir lists entries" test "$(ls "$MNT/docs" | tr '\n' ' ')" = "deep greeting.txt "
check "rmdir refuses a non-empty directory" bash -c "! rmdir '$MNT/docs' 2>/dev/null"
truncate -s 5 "$MNT/docs/greeting.txt"
check "truncate shortens the file" test "$(cat "$MNT/docs/greeting.txt")" = "hello"

# --- permissions (kernel-enforced from stored modes) -------------------------
check "root directory belongs to the volume owner" test "$(stat -c %u:%g "$MNT")" = "1000:1000"
check "owner can write" setpriv --reuid=1000 --regid=1000 --clear-groups \
    bash -c "echo mine >'$MNT/owner.txt'"
check "another user cannot" bash -c "! setpriv --reuid=2000 --regid=2000 --clear-groups \
    bash -c \"echo theirs >'$MNT/intruder.txt'\" 2>/dev/null"

# --- malware scanner ------------------------------------------------------
check "ELF header write is rejected" \
    bash -c "! printf '\\x7fELF\\x02\\x01\\x01\\x00' >'$MNT/payload' 2>/dev/null"
check "rejected file stays empty" test "$(stat -c %s "$MNT/payload")" = 0
check "signature write is rejected" \
    bash -c "! printf 'abc KFS-TEST-SIG-1 xyz' >'$MNT/sig.txt' 2>/dev/null"
check "ELF bytes later in a file are allowed" \
    bash -c "head -c 5000 /dev/zero >'$MNT/later.bin' && printf '\\x7fELF' >>'$MNT/later.bin'"
check "blocked writes are audited" grep -q "blocked write to /payload" "$WORK/daemon.log"

# --- sandbox --------------------------------------------------------------
workers=$(ps -o user=,ppid= -e | awk -v p="$DPID" '$2 == p' | wc -l)
nobody=$(ps -o user=,ppid= -e | awk -v p="$DPID" '$2 == p && $1 == "nobody"' | wc -l)
check "4 sandbox workers run" test "$workers" = 4
check "all workers run as nobody" test "$nobody" = 4

# --- at-rest secrecy ------------------------------------------------------
check "file contents are not in the store" bash -c "! grep -rqa 'hello krypton' '$STORE'"
check "file names are not in the store" bash -c "! grep -rqa 'greeting.txt' '$STORE'"
check "directory names are not in the store" bash -c "! grep -rqa 'deep' '$STORE'"

# --- persistence ----------------------------------------------------------
check "clean unmount" unmount_fs
check "remount succeeds" mount_fs "$PASS"
check "data survives remount" cmp -s "$WORK/random.bin" "$MNT/docs/deep/random.bin"
check "tree survives remount" test "$(cat "$MNT/docs/greeting.txt")" = "hello"

# --- fail closed ----------------------------------------------------------
crypto_pid=$(ps -o pid=,ppid= -e | awk -v p="$DPID" '$2 == p {print $1}' | tail -1)
kill -9 "$crypto_pid"
sleep 0.3
check "reads fail after a worker dies" \
    bash -c "! cat '$MNT/docs/deep/random.bin' >/dev/null 2>&1"
check "unmount after failure" unmount_fs

# --- wrong passphrase -----------------------------------------------------
check "wrong passphrase is refused" bash -c "! KRYPTONFS_PASSPHRASE=wrong \
    '$KRYPTONFS' -c '$CONF' --local-store='$STORE' '$MNT' >'$WORK/wrong.log' 2>&1"
check "and nothing is mounted" bash -c "! mountpoint -q '$MNT'"
check "with a clear message" grep -q "wrong passphrase" "$WORK/wrong.log"

echo
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
