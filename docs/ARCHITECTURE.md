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

1. `write(2)` reaches the FUSE `write` callback, which updates the plaintext
   page cache and marks the block dirty.
2. On writeback, the daemon takes a free arena slot, copies the plaintext
   into it, and sends `SCAN` to the scan pool. A malware match fails the
   write (`EACCES`) or raises an audit event, depending on `[scanner] action`.
3. It sends `SEAL` to the crypto pool, which picks a random IV, encrypts the
   slot in place with AES-256-CTR and writes the HMAC tag into the slot's
   envelope header.
4. The daemon sends `BLOCK_WRITE` with the envelope to the block's primary
   node, chosen by hashing `block_id` over the healthy peers. The primary
   persists it and forwards `REPLICATE` to the next `replication - 1` peers.

### Read path

`BLOCK_READ` returns the newest envelope; `OPEN` checks the tag before
decrypting, so a tampered or swapped block is an I/O error, never garbage
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

Every host has an RSA-2048 key pair. Peers' public keys are pinned in
`[crypto] trusted_keys`; the RPC handshake signs both sides' nonces and
ephemeral X25519 shares with them, then derives the session key.

## Threat model

| Adversary                 | Protection                                                                 |
|---------------------------|----------------------------------------------------------------------------|
| Storage node operator     | Sees only ciphertext. Tags detect tampering; binding `block_id` detects swapped blocks. |
| Network attacker          | Mutually authenticated handshake with pinned keys; forward secrecy; per-frame MACs with implicit sequence numbers stop replay, reordering and injection. |
| Spoofed heartbeats        | HMAC with the cluster key plus a monotonic sequence number per node.      |
| Malicious file content    | Parsed only in scan workers: no keys, chrooted, unprivileged.             |

Known limits, to address in later phases:

- **Rollback.** A node can serve an *older* validly tagged envelope. The
  client must track each block's latest generation in its metadata.
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
│   ├── krypton_crypto.h               [P2] AES-CTR, HMAC, PBKDF2/HKDF, RSA, X25519
│   ├── krypton_scanner.h              [P2] malware signature engine
│   ├── krypton_sandbox.h              [P3] worker pools, privilege drop
│   ├── krypton_cache.h                [P3] mmap page cache
│   ├── krypton_rpc.h                  [P4] RPC client/server, handshake
│   └── krypton_telemetry.h            [P5] metrics and audit events
├── src/
│   ├── common/                        [P1] libkfs_common: portable, no dependencies
│   │   ├── krypton_common.c
│   │   ├── krypton_config.c
│   │   ├── krypton_ipc.c
│   │   └── krypton_protocol.c
│   ├── crypto/                        [P2] libkfs_crypto (OpenSSL)
│   │   ├── krypton_crypto.c           block seal/open, key hierarchy
│   │   └── krypton_keystore.c         RSA key loading and pinning
│   ├── scanner/                       [P2]
│   │   ├── malware_scanner.c          ELF header + signature inspection
│   │   └── signatures.c               Aho-Corasick multi-pattern matcher
│   ├── sandbox/                       [P3]
│   │   ├── sandbox_worker.c           fork, chroot, setgid/setuid, worker loop
│   │   └── ipc_channel.c              msgget/msgsnd/msgrcv, arena mmap
│   ├── fuse/                          [P3] kryptonfs binary
│   │   ├── main.c
│   │   ├── krypton_fuse.c             FUSE callbacks
│   │   ├── krypton_cache.c            page cache + writeback
│   │   └── krypton_meta.c             encrypted inode/directory tables
│   ├── net/                           [P4] shared by client and node
│   │   ├── rpc_conn.c                 framed, MAC'd send/recv
│   │   ├── rpc_handshake.c
│   │   └── heartbeat.c                UDP beat/ping/pong, failure detection
│   ├── node/                          [P4] kfs-noded binary
│   │   ├── main.c
│   │   ├── rpc_storage_node.c         multithreaded TCP server
│   │   ├── block_store.c              envelope persistence
│   │   └── replication.c              placement + REPLICATE fan-out
│   └── telemetry/                     [P5]
│       └── telemetry_server.c         Unix-socket JSON-lines publisher
├── tools/
│   ├── kfs-keygen.c                   [P2] RSA-2048 key pair + cluster key
│   └── kfs-mkvol.c                    [P3] volume header creation
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
    ├── test_crypto.c                  [P2] includes NIST/RFC test vectors
    ├── test_scanner.c                 [P2]
    ├── test_sandbox.c                 [P3]
    └── integration/                   [P4] multi-node cluster scripts
```
