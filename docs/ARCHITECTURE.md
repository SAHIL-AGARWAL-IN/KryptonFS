# KryptonFS Architecture

KryptonFS is a FUSE filesystem that encrypts every block on the client and
stores only ciphertext on a cluster of storage nodes. Storage nodes never
hold keys.

## Components

```
 ┌──────────────────────────────── client host ────────────────────────────────┐
 │                                                                             │
 │  application ── VFS ── /dev/fuse ── kryptonfs (FUSE daemon)                 │
 │                                       │  plaintext page cache (mmap, mlock) │
 │                                       │                                     │
 │                       SysV msg queues + shared mmap arena                   │
 │                       ┌───────────────┴────────────────┐                    │
 │               scan workers                      crypto workers              │
 │               parse content, hold no keys       hold keys, never parse      │
 │               chroot + setuid(nobody)           chroot + setuid(nobody)     │
 │                                                                             │
 │  kryptonfs ── Unix socket (JSON lines) ── dashboard (Python / Textual)      │
 └───────────────────────────────────────┬─────────────────────────────────────┘
                 TCP block RPC (HMAC-authenticated frames)  +  UDP heartbeats
            ┌────────────────────────────┼────────────────────────────┐
       kfs-noded #1                 kfs-noded #2                 kfs-noded #3
       stores envelopes             stores envelopes             stores envelopes
```

### Write path

1. `write(2)` reaches the FUSE `write` callback. The new block contents are
   staged in a candidate buffer, copied into an arena slot and sent as
   `SCAN` to the scan pool. A malware match fails the write (`EACCES`) and
   leaves the file untouched, or only raises an audit event, depending on
   `[scanner] action`. Clean contents enter the page cache, dirty.
2. On writeback (eviction, every `writeback_ms`, or `fsync`) the block gets
   a fresh generation and goes as `SEAL` to the crypto pool, which picks a
   random IV, encrypts the slot in place with AES-256-CTR and writes the
   HMAC tag into the slot's envelope header.
3. The daemon sends `BLOCK_WRITE` with the envelope to the first healthy
   node of the block's replica set (rendezvous hashing over all peers).
   That node persists it and forwards `REPLICATE` to the other replicas.
4. Metadata (including the block's new generation) is committed after the
   data it references.

### Read path

The daemon asks the block's replicas one at a time for the envelope. A
copy is accepted only if its tag verifies (`OPEN`, in the crypto pool) and
its generation is the one metadata expects; a stale replica that missed a
write, or a tampered copy, is skipped for the next replica. If no replica
has an acceptable copy, the read fails with `EIO`, never garbage
plaintext.

## Wire formats

Defined byte-for-byte in `include/krypton/krypton_protocol.h`:

| Format         | Size   | Carried over | Authenticated by                                  |
|----------------|--------|--------------|---------------------------------------------------|
| RPC frame head | 50 B   | TCP          | HMAC-SHA256 (session key, implicit sequence no.)  |
| Block envelope | 56 B + data | RPC payload | HMAC-SHA256 tag (volume MAC key, binds block_id) |
| Heartbeat      | 76 B   | UDP          | HMAC-SHA256 (cluster key) + sequence number       |

Shared-memory and message-queue structures are in
`include/krypton/krypton_ipc.h`.

## Keys

```
passphrase ─┐
salt ───────┴─ PBKDF2-HMAC-SHA256 (600k iterations) ─ key-encryption key
                                                            │ unwraps
                                       random 256-bit volume key (in volume header)
                                                            │ HKDF-SHA256
                                              ┌─────────────┴─────────────┐
                                        data key (AES-256)          MAC key (HMAC)
```

The volume header is reserved block 0 on the cluster. It holds the salt,
KDF parameters, block size and the wrapped volume key, so any client with
the passphrase can mount, and changing the passphrase rewraps one key
instead of re-encrypting the volume.

Every host, clients included, has an RSA-2048 key pair and an id
(`[node] id`). Peers' public keys are pinned in `[crypto] trusted_keys`;
the RPC handshake (`include/krypton/krypton_rpc.h`) signs the transcript,
including both sides' nonces and ephemeral X25519 shares, with them, then
derives per-direction session keys.

The header is the only unencrypted object. Its parameters are bound into
the key derivation, so an edited copy fails to unlock; the client tries
each replica's copy until one authenticates.

## Threat model

| Adversary                 | Protection                                                                 |
|---------------------------|----------------------------------------------------------------------------|
| Storage node operator     | Sees only ciphertext. Tags detect tampering; binding `block_id` detects swapped blocks; generations in metadata detect stale copies. A tampered or stale replica is skipped in favour of an honest one. |
| Network attacker          | Mutually authenticated handshake with pinned keys; forward secrecy; per-frame MACs with implicit sequence numbers stop replay, reordering and injection. |
| Rogue client              | Unpinned identities are dropped during the handshake. `REPLICATE` is accepted only from cluster peers. |
| Spoofed heartbeats        | HMAC with the cluster key plus a monotonic sequence number per node. A forged DOWN cannot hide data (replica sets ignore health); it only reorders who is asked first. |
| Malicious file content    | Parsed only in scan workers: no keys, no identity, no passphrase, chrooted, unprivileged. |

### Rollback and crash safety

Metadata records the generation of every data block, and a read whose
authenticated generation differs is refused, so a node cannot serve an
older, validly tagged copy of a block. Generations come from one
volume-wide counter and are never reused.

Every block has two storage copies, selected by generation parity (bit 0
of the block id). A rewrite always targets the copy the *committed*
metadata does not reference, and metadata commits alternate copies the
same way, writing chunks first and the root last. A crash at any point
therefore leaves the previous commit fully readable. Storage freed by
unlink or truncate is deleted only after the next commit lands.

Known limits, to address in later phases:

- **Whole-volume rollback.** Storage can still replace *every* object with
  a complete, older committed state, since the client keeps no local
  record of the latest metadata generation. Pinning the last-seen
  generation on the client (or a signed counter on a quorum of nodes)
  would close this.
- **Access patterns.** Block ids expose inode numbers and block indexes,
  so storage nodes learn file count and approximate sizes (never names or
  contents). Keyed block-id hashing would hide this.
- **No anti-entropy repair.** A replica that was down during a write stays
  stale until that block is rewritten; reads route around it, but the
  block has one fewer good copy meanwhile. A background scrubber
  comparing `BLOCK_STAT` generations across replicas would re-replicate.
- **Writes are best-effort replicated.** A write succeeds once one replica
  stores it; replicas that cannot be reached miss it (and are logged).
- **Heartbeats are IPv4-only.** RPC works over IPv4 and IPv6.
- **Single global lock** in the filesystem core, and one connection per
  peer: correct, but parallel I/O is serialized.
- **Compromised crypto worker.** It holds the keys. Its input is fixed-size
  buffers with no parsing, which keeps that surface small; a seccomp-bpf
  allowlist would shrink it further.
- **Shared arena.** Any worker can write any slot. Each process keeps the
  arena layout in private memory and bounds-checks every index it receives
  (`kfs_ipc_msg_check`).

## Design decisions

Places where the implementation goes beyond the letter of the spec:

| Spec                                  | KryptonFS                                                  | Why |
|---------------------------------------|------------------------------------------------------------|-----|
| SHA-256 key derivation with salt      | PBKDF2-HMAC-SHA256, 600k iterations, random 16-byte salt   | One SHA-256 pass lets a single GPU try billions of passphrases per second. |
| AES-256-CTR                           | AES-256-CTR + HMAC-SHA256 (encrypt-then-MAC), random IV per write | CTR alone is malleable, and reusing an IV on rewrite leaks the XOR of two plaintexts. |
| 50-byte header with no sequence field | Sequence number bound into the HMAC, never sent            | Replay protection without changing the specified header. |
| SysV queues carry block payloads      | Queues carry 48-byte descriptors; bytes live in a shared mmap arena | Default `kernel.msgmnb` is 16 KiB per queue (about three 4 KiB blocks); the arena is also zero-copy. |
| One sandbox for crypto and parsing    | Two pools: scan (no keys) and crypto (no parsing)          | A parser exploit must not reach key material. |
| RSA-2048 node handshake               | RSA-2048 signatures over ephemeral X25519 key exchange     | Forward secrecy: a stolen node key cannot decrypt recorded traffic. |
| Node-to-node authentication           | Clients authenticate the same way, with their own identity | A storage node should only serve hosts it can name. |
| Replication logic on nodes            | Rendezvous placement; the receiving node forwards to the other replicas | Every host computes replica sets alone; adding a node moves only the blocks it wins. |
| C or C++                              | C11 throughout                                             | FUSE, SysV IPC, sockets and OpenSSL are C APIs; one toolchain. |
| Textual TUI or web dashboard          | Textual TUI                                                | Runs over SSH beside the daemon, with no JS build. |

## Project structure

`[P1]`–`[P5]` mark the phase that adds each file.

```
KryptonFS/
├── CMakeLists.txt                     [P1] root build: options, PIE, subdirectories
├── Makefile                           [P1] convenience wrapper around CMake
├── README.md                          [P1]
├── .gitignore                         [P1]
├── cmake/
│   └── KryptonDefaults.cmake          [P1] warnings, hardening, sanitizers
├── config/
│   └── kryptonfs.conf.example         [P1] every key, documented
├── docker/
│   └── dev.Dockerfile                 [P1] Linux toolchain for non-Linux hosts
├── docs/
│   └── ARCHITECTURE.md                [P1] this file
├── include/krypton/                   public headers shared by all components
│   ├── krypton_common.h               [P1] status codes, limits, endian helpers
│   ├── krypton_protocol.h             [P1] RPC frame, envelope, heartbeat formats
│   ├── krypton_ipc.h                  [P1] IPC descriptors, shared arena layout
│   ├── krypton_config.h               [P1] configuration structs + loader API
│   ├── krypton_crypto.h               [P2] AES-CTR, HMAC, PBKDF2/HKDF, frame + heartbeat MACs
│   ├── krypton_keystore.h             [P2] RSA-2048 identities, pinned peers, secret files
│   ├── krypton_scanner.h              [P2] malware signature engine
│   ├── krypton_sandbox.h              [P3] worker pools, privilege drop
│   ├── krypton_volume.h               [P3] volume header, block id layout
│   ├── krypton_backend.h              [P3] block storage interface
│   ├── krypton_blockio.h              [P3] seal/store, fetch/verify/open
│   ├── krypton_meta.h                 [P3] inode table, crash-safe commits
│   ├── krypton_cache.h                [P3] mmap page cache
│   ├── krypton_fs.h                   [P3] filesystem operations
│   ├── krypton_rpc.h                  [P4] handshake, MAC'd framing, payload layouts
│   ├── krypton_pool.h                 [P4] pinned per-peer connections
│   ├── krypton_cluster.h              [P4] placement, health, heartbeats
│   ├── krypton_net_backend.h          [P4] the cluster as a block backend
│   └── krypton_telemetry.h            [P5] metrics and audit events
├── src/
│   ├── common/                        [P1] libkfs_common: portable, no dependencies
│   │   ├── krypton_common.c
│   │   ├── krypton_config.c
│   │   ├── krypton_ipc.c
│   │   └── krypton_protocol.c
│   ├── crypto/                        [P2] libkfs_crypto (OpenSSL 3)
│   │   ├── krypton_crypto.c           block seal/open, key hierarchy, MACs
│   │   └── krypton_keystore.c         RSA-PSS sign/verify, key files, pinning
│   ├── scanner/                       [P2] libkfs_scanner
│   │   └── malware_scanner.c          ELF header check, Aho-Corasick signature matcher
│   ├── sandbox/                       [P3] libkfs_sandbox (Linux)
│   │   └── sandbox_worker.c           worker pools, jail, msg queues, arena, supervisor
│   ├── fs/                            [P3] libkfs_fs (Linux): FUSE-independent core
│   │   ├── krypton_volume.c           header creation, passphrase unlock
│   │   ├── backend_local.c            directory block store (atomic puts)
│   │   ├── krypton_blockio.c          encrypted block I/O
│   │   ├── krypton_meta.c             inode table, serialization, commits
│   │   ├── krypton_cache.c            LRU page cache + writeback
│   │   └── krypton_fs.c               path operations, scan-gated writes
│   ├── fuse/                          [P3] kryptonfs binary
│   │   └── krypton_fuse.c             FUSE callbacks, sandbox wiring, main
│   ├── net/                           [P4] libkfs_net (Linux): shared by client and node
│   │   ├── rpc_conn.c                 framed, MAC'd send/recv, TCP helpers
│   │   ├── rpc_handshake.c            RSA-PSS + X25519 mutual authentication
│   │   ├── pool.c                     per-peer connections, redial on failure
│   │   ├── cluster.c                  rendezvous placement, health table
│   │   ├── heartbeat.c                UDP beat/ping/pong, failure detection
│   │   └── backend_net.c              client backend: replica-ordered I/O
│   ├── node/                          [P4] kfs-noded binary
│   │   └── kfs_noded.c                thread-pool TCP server, storage, replication
│   └── telemetry/                     [P5]
│       └── telemetry_server.c         Unix-socket JSON-lines publisher
├── tools/
│   ├── kfs-keygen.c                   [P2] RSA-2048 key pair + cluster key
│   └── kfs-mkvol.c                    [P3] volume header + empty root directory
├── dashboard/                         [P5] Python 3.11+, Textual
│   ├── pyproject.toml
│   └── kryptonfs_dash/
│       ├── __main__.py
│       ├── app.py
│       ├── telemetry_client.py
│       ├── theme.tcss                 matte black / cyan / neon green / coral
│       └── widgets/
│           ├── iops_panel.py          IOPS, latency, throughput
│           ├── mount_tree.py          virtual mount tree
│           ├── cluster_health.py      node state, RTT, disk usage
│           └── audit_feed.py          sandboxes, key status, scan results
└── tests/
    ├── CMakeLists.txt                 [P1]
    ├── kfs_test.h                     [P1] assertion harness
    ├── test_config.c                  [P1]
    ├── test_ipc.c                     [P1]
    ├── test_protocol.c                [P1]
    ├── test_crypto.c                  [P2] NIST / RFC test vectors, tamper cases
    ├── test_keystore.c                [P2]
    ├── test_scanner.c                 [P2]
    ├── test_sandbox.c                 [P3] jail, fail-closed, concurrency
    ├── test_fs.c                      [P3] crash, rollback, tamper, at-rest secrecy
    ├── test_rpc.c                     [P4] handshake, impostors, tamper, replay
    ├── test_cluster.c                 [P4] placement, health, live heartbeats
    └── integration/
        ├── fuse_smoke.sh              [P3] real mount, end to end
        └── cluster_smoke.sh           [P4] 3 nodes + client: replication, failure, tamper
```
