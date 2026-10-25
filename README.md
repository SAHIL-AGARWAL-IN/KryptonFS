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
| 2     | Cryptography, node keys and malware scanner        | done    |
| 3     | FUSE driver, sandbox workers, IPC                  | done    |
| 4     | Storage node server, replication, heartbeats       | done    |
| 5     | Telemetry and dashboard                            | planned |

## Building

Requirements: CMake 3.20+, a C11 compiler (GCC or Clang), OpenSSL 3
(`libssl-dev`) and, on Linux, libfuse 3.10+ (`libfuse3-dev`). Phase 5 adds
Python 3.11+.

```sh
make              # Debug build in build/
make test         # build and run the unit tests
make release      # optimized, fortified build in build-release/, then tests
make asan         # AddressSanitizer + UBSan build in build-asan/, then tests
sudo make integration  # real mounts end to end: local store and a 3-node cluster
```

Or with CMake directly:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

### Non-Linux hosts

FUSE, System V IPC and `chroot` are Linux-only. The common, crypto and
scanner libraries and their tests also build natively with MinGW on
Windows; everything else needs Linux. The dev container has the full
toolchain:

```sh
docker build -f docker/dev.Dockerfile -t kryptonfs-dev .
docker run --rm -it --device /dev/fuse --cap-add SYS_ADMIN --cap-add IPC_LOCK \
    -v "$PWD":/src -w /src kryptonfs-dev
# inside the container:
make test integration
```

`--device /dev/fuse` and `SYS_ADMIN` are needed to mount FUSE filesystems,
and `IPC_LOCK` lets the daemon lock its plaintext cache into RAM. Docker's
default capabilities already cover `chroot` and `setuid`. Add
`--cap-add SYS_PTRACE` to let the sandbox test read the workers' chroot
path (they are non-dumpable, which hides it otherwise).

## Running a cluster

**1. Identities.** Every host (storage node or client) has an RSA-2048
identity and an id, set as `[node] id` in its config. The cluster shares
one heartbeat key:

```sh
kfs-keygen node 1 /etc/kryptonfs/keys               # node.key.pem + 1.pub.pem
kfs-keygen cluster /etc/kryptonfs/keys/cluster.key  # once; copy to every host
```

Copy every host's `<id>.pub.pem` into every other host's `trusted_keys`
directory. Handshakes from keys not pinned there are refused, in both
directions. `kfs-keygen` never overwrites existing files.

**2. Storage nodes.** List every node under `[cluster]` (identical on all
hosts), give each its own `[node]` section, and start:

```sh
kfs-noded -c /etc/kryptonfs/kryptonfs.conf     # foreground; SIGTERM stops it
```

**3. Volume and mount.** From a client host:

```sh
mkdir -p /mnt/krypton /var/empty/kryptonfs
kfs-mkvol -c /etc/kryptonfs/kryptonfs.conf --owner "$(id -u):$(id -g)"
sudo kryptonfs -c /etc/kryptonfs/kryptonfs.conf /mnt/krypton
```

Each block is stored on `replication` nodes chosen by rendezvous hashing.
Reads verify every copy and skip stale or tampered ones, so the volume
stays readable while one replica of each block is up and honest.

For a single machine, `--local-store DIR` on both `kfs-mkvol` and
`kryptonfs` keeps blocks in a local directory instead.

Both tools prompt for the passphrase on the terminal; they also accept it
on stdin or in `$KRYPTONFS_PASSPHRASE` for automation. `kryptonfs` must
start as root so it can jail its workers, stays in the foreground (run it
under systemd or similar), and unmounts cleanly with `fusermount3 -u` or
Ctrl-C. Writes rejected by the malware scanner fail with "Permission
denied" and are logged to syslog.

## Configuration

One file configures both the client (`kryptonfs`) and storage nodes
(`kfs-noded`). Start from
[config/kryptonfs.conf.example](config/kryptonfs.conf.example), which
documents every key.
