# KryptonFS

A distributed, encrypted virtual filesystem for Linux. Files are encrypted
per block on the client (AES-256-CTR + HMAC-SHA256) inside sandboxed worker
processes, then replicated as ciphertext across storage nodes over an
authenticated TCP block protocol. A terminal dashboard shows I/O, cluster
health and security events.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design, threat
model and full project layout.

## Status

| Phase | Scope                                              | State   |
|-------|----------------------------------------------------|---------|
| 1     | Scaffolding, wire formats, IPC layout, config      | done    |
| 2     | Cryptography and malware scanner                   | planned |
| 3     | FUSE driver, sandbox workers, IPC                  | planned |
| 4     | Storage node server, replication, heartbeats       | planned |
| 5     | Telemetry and dashboard                            | planned |

## Building

Requirements: CMake 3.20+, a C11 compiler (GCC or Clang). Later phases add
`libfuse3-dev`, `libssl-dev` and Python 3.11+.

```sh
make          # Debug build in build/
make test     # build and run the unit tests
make release  # optimized, fortified build in build-release/, then tests
make asan     # AddressSanitizer + UBSan build in build-asan/, then tests
```

Or with CMake directly:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

### Non-Linux hosts

FUSE, System V IPC and `chroot` are Linux-only. The Phase 1 common library
and its tests also build natively with MinGW on Windows, but from Phase 3 on
you need Linux. The dev container has the full toolchain:

```sh
docker build -f docker/dev.Dockerfile -t kryptonfs-dev .
docker run --rm -it --device /dev/fuse --cap-add SYS_ADMIN \
    -v "$PWD":/src kryptonfs-dev
# inside the container:
make test
```

`--device /dev/fuse` and `SYS_ADMIN` are needed to mount FUSE filesystems.
Docker's default capabilities already cover `chroot` and `setuid`.

## Configuration

One file configures both the client (`kryptonfs`) and storage nodes
(`kfs-noded`). Start from
[config/kryptonfs.conf.example](config/kryptonfs.conf.example), which
documents every key.
