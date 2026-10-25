"""Security audit: sandbox processes, key status and the event feed."""

from __future__ import annotations

import time
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import RichLog, Static

from ..telemetry import TelemetryState

LEVEL_STYLE = {
    "info": ("INFO ", "#00e5ff"),
    "warn": ("WARN ", "#ff6f61"),
    "alert": ("ALERT", "bold reverse #ff6f61"),
}


def format_event(event: dict[str, Any]) -> Text:
    tag, style = LEVEL_STYLE.get(event.get("level", "info"), LEVEL_STYLE["info"])
    clock = time.strftime("%H:%M:%S", time.localtime(event.get("ts_ms", 0) / 1000))
    line = Text(f"{clock} ", style="#7a8a99")
    line.append(tag, style=style)
    line.append(f" {event.get('kind', ''):<8} ", style="bold #c9d4de")
    line.append(event.get("msg", ""), style="#c9d4de")
    return line


def status_text(state: TelemetryState) -> Text:
    """Sandbox processes, where the volume key lives, and the crypto suite."""
    snap = state.snapshot or {}
    sandbox = snap.get("sandbox", {})
    keys = snap.get("keys", {})
    workers = sandbox.get("workers", [])

    text = Text()
    text.append(" SANDBOX  ", style="bold #00e5ff")
    for kind in ("scan", "crypto"):
        text.append(f"{kind} ", style="#c9d4de")
        for w in (w for w in workers if w.get("kind") == kind):
            alive = w.get("alive")
            text.append("● " if alive else "✕ ", style="#39ff14" if alive else "bold #ff6f61")
        text.append(" ")
    if sandbox.get("failed"):
        text.append(" FAILED CLOSED ", style="bold reverse #ff6f61")
    elif workers:
        text.append(" JAILED ", style="bold reverse #39ff14")
    else:
        text.append("no workers", style="#7a8a99")

    held = keys.get("volume_key", "unknown")
    text.append("\n VOLUME KEY ", style="bold #00e5ff")
    text.append(held, style="bold #ff6f61" if "unavailable" in held else "#39ff14")
    text.append("\n CRYPTO   ", style="bold #00e5ff")
    text.append(f"{keys.get('cipher', '?')} · {keys.get('kdf', '?')} "
                f"×{keys.get('kdf_iterations', 0):,}", style="#c9d4de")
    identity = keys.get("identity_id", 0)
    text.append("\n IDENTITY ", style="bold #00e5ff")
    text.append(f"node {identity} · RSA-2048, pinned peers" if identity else "local store",
                style="#c9d4de")
    return text


class SecurityPanel(Vertical):
    def compose(self) -> ComposeResult:
        yield Static(id="security-status")
        # min_width defaults to 78 columns, which forces a horizontal
        # scrollbar in a half-width panel; wrap to the panel instead.
        yield RichLog(id="feed", markup=False, wrap=True, max_lines=500, min_width=20)

    def add_events(self, events: list[dict[str, Any]]) -> None:
        feed = self.query_one("#feed", RichLog)
        for event in events:
            feed.write(format_event(event))

    def clear_feed(self) -> None:
        self.query_one("#feed", RichLog).clear()

    def refresh_from(self, state: TelemetryState) -> None:
        self.query_one("#security-status", Static).update(status_text(state))
