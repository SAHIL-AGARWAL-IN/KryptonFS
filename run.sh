#!/usr/bin/env bash
# run.sh - Start the KryptonFS demo on Linux or macOS (needs Docker).
#   ./run.sh              start (or restart) the demo and open the console in the browser
#   ./run.sh console      open the console again
#   ./run.sh dashboard    open the terminal dashboard instead
#   ./run.sh shell        Linux shell in the running demo (files: /mnt/krypton)
#   ./run.sh stop         stop the demo
# PORT=8090 ./run.sh publishes the console on another port.
set -euo pipefail
cd "$(dirname "$0")"
NAME=kryptonfs-demo IMAGE=kryptonfs-dev PORT=${PORT:-8080}

docker info >/dev/null 2>&1 || { echo "Docker is not running. Start it and try again."; exit 1; }
running() { [ "$(docker ps --filter "name=^$NAME$" --format '{{.Names}}')" = "$NAME" ]; }
hints() { printf '\nThe demo is running: ./run.sh console | dashboard | shell | stop\n'; }
console() {
    local port token url
    port=$(docker port "$NAME" 8080 | head -1 | sed 's/.*://')
    token=$(docker exec "$NAME" cat /demo/web.token)
    url="http://localhost:$port/?token=$token"
    echo "Krypton Console: http://localhost:$port"
    echo "(The link holds a private access token; it is swapped for a cookie when it opens.)"
    if command -v xdg-open >/dev/null; then xdg-open "$url" >/dev/null 2>&1 || echo "$url"
    elif command -v open >/dev/null; then open "$url"
    else echo "Open: $url"; fi
}
dashboard() {
    echo "Opening the dashboard. Press q to close it; the demo keeps running."
    docker exec -it "$NAME" tmux attach -t dash || true
}

case "${1:-start}" in
    stop) docker rm -f "$NAME" >/dev/null 2>&1 || true; echo "KryptonFS demo stopped."; exit 0 ;;
    shell) running || { echo "Not running; start it with ./run.sh"; exit 1; }
           exec docker exec -it -w /mnt/krypton "$NAME" bash ;;
    dashboard) running || { echo "Not running; start it with ./run.sh"; exit 1; }; dashboard; hints; exit 0 ;;
    console) running || { echo "Not running; start it with ./run.sh"; exit 1; }; console; exit 0 ;;
    start) ;;
    *) sed -n '2,8p' "$0"; exit 2 ;;
esac

echo "Preparing the Linux environment (slow the first time only)..."
docker build -q -f docker/dev.Dockerfile -t "$IMAGE" . >/dev/null
docker rm -f "$NAME" >/dev/null 2>&1 || true
# The console is published on this computer only (127.0.0.1). node_modules
# lives in a named volume, outside the source tree.
docker run -d --init --name "$NAME" --device /dev/fuse --cap-add SYS_ADMIN --cap-add IPC_LOCK \
    -p "127.0.0.1:$PORT:8080" -v "$PWD:/src" \
    -v kryptonfs-node-modules:/src/webui/frontend/node_modules \
    -w /src "$IMAGE" bash scripts/demo-cluster.sh >/dev/null

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
[ "${NO_ATTACH:-}" = 1 ] && exit 0
console
hints
