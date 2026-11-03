#!/usr/bin/env bash
# e2e_smoke.sh - Run e2e_smoke.py against the running demo (run.cmd /
# run.sh), in the official Playwright image on the demo container's network.
# Screenshots land in webui/tests/e2e-shots/ (ignored by git).
set -euo pipefail
cd "$(dirname "$0")"
NAME=kryptonfs-demo
token=$(docker exec "$NAME" cat /demo/web.token)
mkdir -p e2e-shots
docker run --rm --network "container:$NAME" --ipc=host \
    -v "$PWD:/e2e" -w /e2e mcr.microsoft.com/playwright/python:v1.48.0-noble \
    sh -c 'pip install -q --break-system-packages playwright==1.48.0 &&
           python3 e2e_smoke.py http://127.0.0.1:8080 "$1" /e2e/e2e-shots' sh "$token"
