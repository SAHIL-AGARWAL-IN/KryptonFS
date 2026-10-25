"""Reading and aggregating the kryptonfs telemetry stream.

The daemon serves newline-delimited JSON on a Unix socket (see
include/krypton/krypton_telemetry.h for the schema). ``TelemetryState``
folds those messages into what the dashboard draws: per-second rates with
a rolling history, the latest cluster and sandbox state, the mount tree
and the event feed.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

HISTORY = 120  # samples kept for sparklines
FEED = 500  # events kept for the audit feed
LINE_LIMIT = 16 * 1024 * 1024  # a tree message for 2000 entries fits easily


@dataclass
class Rates:
    """One interval's I/O, normalised to per-second figures."""

    read_iops: float = 0.0
    write_iops: float = 0.0
    read_bps: float = 0.0
    write_bps: float = 0.0
    read_lat_us: int = 0
    write_lat_us: int = 0
    read_lat_max_us: int = 0
    write_lat_max_us: int = 0
    errors: int = 0


@dataclass
class TelemetryState:
    """Everything the dashboard shows, updated message by message."""

    history: int = HISTORY
    snapshot: dict[str, Any] | None = None
    rates: Rates = field(default_factory=Rates)
    tree: list[dict[str, Any]] = field(default_factory=list)
    tree_truncated: bool = False
    events: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=FEED))
    _seen_seq: int = 0

    def __post_init__(self) -> None:
        self.read_iops: deque[float] = deque(maxlen=self.history)
        self.write_iops: deque[float] = deque(maxlen=self.history)
        self.read_bps: deque[float] = deque(maxlen=self.history)
        self.write_bps: deque[float] = deque(maxlen=self.history)

    def apply(self, msg: dict[str, Any]) -> list[dict[str, Any]]:
        """Folds in one message; returns the events it carried that are new."""
        kind = msg.get("type")
        if kind == "snapshot":
            self._apply_snapshot(msg)
            return self._take_events(msg.get("events", []))
        if kind == "events":
            return self._take_events(msg.get("events", []))
        if kind == "tree":
            self.tree = list(msg.get("entries", []))
            self.tree_truncated = bool(msg.get("truncated", False))
        return []

    def _apply_snapshot(self, msg: dict[str, Any]) -> None:
        io = msg.get("io", {})
        per_s = 1000.0 / max(int(msg.get("interval_ms", 1000)), 1)
        self.rates = Rates(
            read_iops=io.get("read_ops", 0) * per_s,
            write_iops=io.get("write_ops", 0) * per_s,
            read_bps=io.get("read_bytes", 0) * per_s,
            write_bps=io.get("write_bytes", 0) * per_s,
            read_lat_us=io.get("read_lat_us", 0),
            write_lat_us=io.get("write_lat_us", 0),
            read_lat_max_us=io.get("read_lat_max_us", 0),
            write_lat_max_us=io.get("write_lat_max_us", 0),
            errors=io.get("errors", 0),
        )
        self.read_iops.append(self.rates.read_iops)
        self.write_iops.append(self.rates.write_iops)
        self.read_bps.append(self.rates.read_bps)
        self.write_bps.append(self.rates.write_bps)
        self.snapshot = msg

    def _take_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # The backfill on connect can overlap the first snapshot's events.
        fresh = [e for e in events if e.get("seq", 0) > self._seen_seq]
        if fresh:
            self._seen_seq = max(e.get("seq", 0) for e in fresh)
            self.events.extend(fresh)
        return fresh


async def stream(path: str) -> AsyncIterator[dict[str, Any]]:
    """Yields decoded messages until the daemon closes the connection.

    Raises OSError if the socket cannot be reached.
    """
    reader, writer = await asyncio.open_unix_connection(path, limit=LINE_LIMIT)
    try:
        while line := await reader.readline():
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue  # a torn line; the next snapshot supersedes it
    finally:
        writer.close()


def human_bytes(n: float) -> str:
    """1536 -> '1.5 KiB'."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def human_latency(us: float) -> str:
    """850 -> '850 µs', 12500 -> '12.5 ms'."""
    if us < 1000:
        return f"{us:.0f} µs"
    if us < 1_000_000:
        return f"{us / 1000:.1f} ms"
    return f"{us / 1_000_000:.2f} s"
