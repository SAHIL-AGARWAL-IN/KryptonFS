#!/usr/bin/env bash
# run.sh - Start the KryptonFS demo on Linux or macOS (needs Docker).
#   ./run.sh              start (or restart) the demo and open the dashboard
#   ./run.sh shell        Linux shell in the running demo (files: /mnt/krypton)
#   ./run.sh dashboard    reopen the dashboard
#   ./run.sh stop         stop the demo
set -euo pipefail
cd "$(dirname "$0")"
NAME=kryptonfs-demo IMAGE=kryptonfs-dev

docker info >/dev/null 2>&1 || { echo "Docker is not running. Start it and try again."; exit 1; }
running() { [ "$(docker ps --filter "name=^$NAME$" --format '{{.Names}}')" = "$NAME" ]; }
dashboard() {
    echo "Opening the dashboard. Press q to close it; the demo keeps running."
    docker exec -it "$NAME" tmux attach -t dash || true
    printf '\nThe demo is still running: ./run.sh dashboard | ./run.sh shell | ./run.sh stop\n'
}

case "${1:-start}" in
    stop) docker rm -f "$NAME" >/dev/null 2>&1 || true; echo "KryptonFS demo stopped."; exit 0 ;;
    shell) running || { echo "Not running; start it with ./run.sh"; exit 1; }
           exec docker exec -it -w /mnt/krypton "$NAME" bash ;;
    dashboard) running || { echo "Not running; start it with ./run.sh"; exit 1; }; dashboard; exit 0 ;;
    start) ;;
    *) sed -n '2,6p' "$0"; exit 2 ;;
esac

echo "Preparing the Linux environment (slow the first time only)..."
docker build -q -f docker/dev.Dockerfile -t "$IMAGE" . >/dev/null
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --device /dev/fuse --cap-add SYS_ADMIN --cap-add IPC_LOCK \
    -v "$PWD:/src" -w /src "$IMAGE" bash scripts/demo-cluster.sh >/dev/null

echo "Building KryptonFS and starting the cluster..."
for _ in $(seq 300); do
    sleep 1
    logs=$(docker logs "$NAME" 2>&1)
    grep -q 'FAILED' <<<"$logs" && { echo "$logs"; exit 1; }
    grep -q '\[demo\] READY' <<<"$logs" && break
    running || { echo "$logs"; exit 1; }
done
grep -v READY <<<"$logs" | sed 's/^/  /'
printf '\nKryptonFS is running: 3 storage nodes, encrypted volume at /mnt/krypton.\n'
[ "${NO_ATTACH:-}" = 1 ] || dashboard
