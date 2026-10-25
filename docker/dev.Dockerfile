# Linux development environment for KryptonFS on non-Linux hosts.
#
#   docker build -f docker/dev.Dockerfile -t kryptonfs-dev .
#   docker run --rm -it --device /dev/fuse --cap-add SYS_ADMIN \
#       -v "$PWD":/src kryptonfs-dev

FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential clang cmake ninja-build pkg-config make \
        libfuse3-dev fuse3 libssl-dev \
        python3 python3-venv python3-pip \
        gdb valgrind strace \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
CMD ["bash"]
