# Production image: KryptonFS (Release build), the Krypton Console and its
# built frontend, without compilers or Node. Built from the repository
# root by deploy/docker-compose.yml.

FROM ubuntu:24.04 AS build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config libfuse3-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY cmake cmake
COPY include include
COPY src src
COPY tools tools
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DKFS_BUILD_TESTS=OFF \
 && cmake --build build

FROM node:22.12.0-bookworm-slim AS web
WORKDIR /web
COPY webui/frontend/package.json webui/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY webui/frontend ./
RUN npm run build

FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        fuse3 libssl3t64 python3 python3-venv \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/kryptonfs/venv \
 && /opt/kryptonfs/venv/bin/pip install --no-cache-dir \
        fastapi==0.115.6 "uvicorn[standard]==0.32.1"
# The console finds the binaries at the build tree's relative paths.
COPY --from=build /src/build/src/node/kfs-noded /opt/kryptonfs/src/node/
COPY --from=build /src/build/src/fuse/kryptonfs /opt/kryptonfs/src/fuse/
COPY --from=build /src/build/tools/kfs-keygen /src/build/tools/kfs-mkvol /opt/kryptonfs/tools/
COPY --from=web /web/dist /opt/kryptonfs/web
COPY dashboard/kryptonfs_dash /opt/kryptonfs/python/kryptonfs_dash
COPY webui/kryptonfs_web /opt/kryptonfs/python/kryptonfs_web
COPY --chmod=755 deploy/entrypoint.sh /opt/kryptonfs/entrypoint.sh

VOLUME /var/lib/kryptonfs
EXPOSE 8080
ENTRYPOINT ["/opt/kryptonfs/entrypoint.sh"]
CMD ["serve"]
