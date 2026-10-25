"""A synthetic telemetry feed, message-for-message like the real daemon's.

Used by ``kryptonfs-dash --demo`` to preview the dashboard without a
mount, and by the tests to drive the UI deterministically.
"""

from __future__ import annotations

import asyncio
import math
import random
import time
from collections.abc import AsyncIterator
from typing import Any

INTERVAL_MS = 500

TREE = [
    ("/", True, 0, 0),
    ("/finance", True, 0, 1),
    ("/finance/q3-forecast.xlsx", False, 482_113, 2),
    ("/finance/payroll-2026.csv", False, 91_204, 2),
    ("/research", True, 0, 1),
    ("/research/genome-batch-17.fastq", False, 1_843_300_112, 2),
    ("/research/notes", True, 0, 2),
    ("/research/notes/lab-journal.md", False, 18_442, 3),
    ("/backups", True, 0, 1),
    ("/backups/db-2026-10-24.tar.zst", False, 734_003_200, 2),
    ("/keys-escrow.age", False, 3_310, 1),
]

STARTUP = [
    ("info", "keys", "volume unlocked (PBKDF2-HMAC-SHA256, 600000 iterations)"),
    ("info", "sandbox", "2 scan + 2 crypto workers jailed in /var/empty/kryptonfs as uid 65534"),
    ("info", "keys", "volume key handed to the crypto workers and wiped from the daemon"),
    ("info", "cluster", "joined as node 100: 3 peers, replication 2"),
    ("info", "scanner", "malware scanner active (reject mode)"),
    ("info", "volume", "mounted"),
]


class DemoFeed:
    """Generates snapshots with a few scripted incidents along the way."""

    def __init__(self, seed: int = 7) -> None:
        self.rng = random.Random(seed)
        self.seq = 0
        self.tick = 0
        self.node2_down = False
        self.start_ms = int(time.time() * 1000)

    def _event(self, level: str, kind: str, msg: str) -> dict[str, Any]:
        self.seq += 1
        return {"seq": self.seq, "ts_ms": int(time.time() * 1000), "level": level,
                "kind": kind, "msg": msg}

    def startup(self) -> list[dict[str, Any]]:
        return [
            {"type": "events", "events": [self._event(*e) for e in STARTUP]},
            self.tree(),
        ]

    def tree(self) -> dict[str, Any]:
        entries = [{"path": p, "dir": d, "size": s, "depth": depth} for p, d, s, depth in TREE]
        return {"type": "tree", "entries": entries, "truncated": False}

    def snapshot(self) -> dict[str, Any]:
        self.tick += 1
        t = self.tick
        events = []
        if t % 37 == 0:
            events.append(self._event("alert", "scanner",
                                      "blocked write to /research/run.sh: ELF executable header "
                                      "at offset 0"))
        if t % 53 == 20:
            self.node2_down = True
            events.append(self._event("warn", "cluster", "node 2 is down"))
        if t % 53 == 40 and self.node2_down:
            self.node2_down = False
            events.append(self._event("info", "cluster", "node 2 is up"))

        wave = 0.5 + 0.5 * math.sin(t / 9)
        reads = int(40 + 260 * wave + self.rng.randint(0, 40))
        writes = int(15 + 120 * (1 - wave) + self.rng.randint(0, 25))
        per_interval = INTERVAL_MS / 1000
        nodes = []
        for node_id, used in ((1, 0.41), (2, 0.58), (3, 0.37)):
            down = node_id == 2 and self.node2_down
            nodes.append({
                "id": node_id,
                "state": "down" if down else "up",
                "rtt_us": 0 if down else 180 + node_id * 90 + self.rng.randint(0, 120),
                "disk_total": 2_000_000_000_000,
                "disk_used": int(2_000_000_000_000 * (used + t * 1e-5)),
                "last_seen_ms": 4200 if down else self.rng.randint(5, 400),
            })
        return {
            "type": "snapshot",
            "ts_ms": int(time.time() * 1000),
            "interval_ms": INTERVAL_MS,
            "volume": {"name": "krypton", "mountpoint": "/mnt/krypton",
                       "backend": "cluster", "block_size": 4096},
            "io": {
                "read_ops": int(reads * per_interval), "write_ops": int(writes * per_interval),
                "read_bytes": int(reads * per_interval * 4096 * 8),
                "write_bytes": int(writes * per_interval * 4096 * 4),
                "read_lat_us": 300 + self.rng.randint(0, 400),
                "write_lat_us": 1100 + self.rng.randint(0, 900),
                "read_lat_max_us": 2500 + self.rng.randint(0, 3000),
                "write_lat_max_us": 6000 + self.rng.randint(0, 9000),
                "errors": 0,
            },
            "cache": {"frames": 65536, "used": min(65536, 20000 + t * 97), "dirty": 40 + t % 300,
                      "hits": 900_000 + t * 1200, "misses": 31_000 + t * 40, "evictions": t * 12},
            "usage": {"files": 7, "dirs": 4, "data_blocks": 630_420},
            "nodes": nodes,
            "sandbox": {"failed": False, "workers": [
                {"pid": 4101, "kind": "scan", "alive": True},
                {"pid": 4102, "kind": "scan", "alive": True},
                {"pid": 4107, "kind": "crypto", "alive": True},
                {"pid": 4108, "kind": "crypto", "alive": True},
            ]},
            "keys": {"cipher": "AES-256-CTR + HMAC-SHA256", "kdf": "PBKDF2-HMAC-SHA256",
                     "kdf_iterations": 600000,
                     "volume_key": "held by 2 jailed crypto workers; wiped from the daemon",
                     "identity_id": 100},
            "events": events,
        }


async def demo_stream(interval: float = INTERVAL_MS / 1000) -> AsyncIterator[dict[str, Any]]:
    feed = DemoFeed()
    for msg in feed.startup():
        yield msg
    while True:
        yield feed.snapshot()
        await asyncio.sleep(interval)
