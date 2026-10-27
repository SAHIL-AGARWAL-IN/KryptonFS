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

WORKDIR /src
CMD ["bash"]
