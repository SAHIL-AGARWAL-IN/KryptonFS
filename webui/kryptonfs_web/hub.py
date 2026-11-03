"""Bridges the daemon's telemetry socket to every connected browser.

The hub keeps one TelemetryState (shared with the terminal dashboard) so a
browser that connects late still gets the latest snapshot, the mount tree
and recent events, then receives every daemon message as it arrives.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from typing import Any

from kryptonfs_dash.telemetry import TelemetryState

Source = Callable[[], AsyncIterator[dict[str, Any]]]
BACKLOG_EVENTS = 100


class TelemetryHub:
    def __init__(self, source: Source, retry_seconds: float = 1.0) -> None:
        self.source = source
        self.retry = retry_seconds
        self.state = TelemetryState()
        self.connected = False
        self.error = ""
        self._clients: set[asyncio.Queue] = set()
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    def status(self) -> dict[str, Any]:
        return {"type": "status", "connected": self.connected, "error": self.error}

    def hello(self) -> list[dict[str, Any]]:
        """Messages that bring a newly connected browser up to date."""
        msgs: list[dict[str, Any]] = [self.status()]
        if self.state.snapshot is not None:
            msgs.append(self.state.snapshot)
        if self.state.tree:
            msgs.append({"type": "tree", "entries": self.state.tree,
                         "truncated": self.state.tree_truncated})
        events = list(self.state.events)[-BACKLOG_EVENTS:]
        if events:
            msgs.append({"type": "events", "events": events})
        return msgs

    def subscribe(self) -> asyncio.Queue:
        # Bounded: a browser that stops reading is dropped, not buffered forever.
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._clients.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._clients.discard(q)

    def publish(self, msg: dict[str, Any]) -> None:
        for q in list(self._clients):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                self._clients.discard(q)
                with contextlib.suppress(asyncio.QueueFull):
                    q.put_nowait({"type": "overflow"})

    def _set_status(self, connected: bool, error: str = "") -> None:
        if (connected, error) != (self.connected, self.error):
            self.connected, self.error = connected, error
            self.publish(self.status())

    async def _run(self) -> None:
        while True:
            try:
                async for msg in self.source():
                    self._set_status(True)
                    self.state.apply(msg)
                    self.publish(msg)
                self._set_status(False, "the daemon closed the telemetry stream")
            except OSError as exc:
                self._set_status(False, exc.strerror or str(exc))
            await asyncio.sleep(self.retry)
