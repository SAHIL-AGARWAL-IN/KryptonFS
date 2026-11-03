# Linux development environment for KryptonFS on non-Linux hosts.
# run.cmd / run.sh build and use it automatically; by hand:
#
#   docker build -f docker/dev.Dockerfile -t kryptonfs-dev .
#   docker run --rm -it --device /dev/fuse --cap-add SYS_ADMIN --cap-add IPC_LOCK \
#       -v "$PWD":/src -w /src kryptonfs-dev

FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential clang cmake ninja-build pkg-config make \
        libfuse3-dev fuse3 libssl-dev \
        python3 python3-venv python3-pip \
        gdb valgrind strace \
 && rm -rf /var/lib/apt/lists/*

# For the demo: tmux hosts the dashboard; its one dependency is baked in so
# starting the demo needs no network. (The dashboard's own code is run
# from the mounted source tree.)
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tmux \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/dash \
 && /opt/dash/bin/pip install --no-cache-dir textual==8.2.8 pytest

# The web console: Node.js (an LTS release, copied from the official image;
# Ubuntu's own is past end of life) builds its frontend, and its Python
# server shares the dashboard's virtualenv.
COPY --from=node:22.12.0-bookworm-slim /usr/local/bin/node /usr/local/bin/node
COPY --from=node:22.12.0-bookworm-slim /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && /opt/dash/bin/pip install --no-cache-dir \
        fastapi==0.115.6 "uvicorn[standard]==0.32.1" httpx==0.28.1

WORKDIR /src
CMD ["bash"]
