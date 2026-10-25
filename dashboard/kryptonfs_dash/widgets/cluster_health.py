"""Node cluster health: state, ping latency and disk usage per node."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import DataTable

from ..telemetry import TelemetryState, human_bytes, human_latency

STATE_STYLE = {
    "up": "bold #39ff14",
    "degraded": "bold #ff6f61",
    "draining": "#ff6f61",
    "down": "bold reverse #ff6f61",
    "unknown": "#7a8a99",
}


def disk_bar(used: int, total: int, width: int = 12) -> Text:
    """'█████░░░░░░░  41%': green below 80%, coral from 80%, bold from 90%."""
    if total <= 0:
        return Text("n/a", style="#7a8a99")
    frac = min(max(used / total, 0.0), 1.0)
    filled = round(frac * width)
    style = "#39ff14" if frac < 0.8 else "#ff6f61" if frac < 0.9 else "bold #ff6f61"
    bar = Text("█" * filled, style=style)
    bar.append("░" * (width - filled), style="#2a3440")
    bar.append(f" {frac * 100:3.0f}% of {human_bytes(total)}", style="#c9d4de")
    return bar


COLUMNS = ("NODE", "STATE", "RTT", "DISK", "SEEN")


class ClusterPanel(DataTable):
    def on_mount(self) -> None:
        self.cursor_type = "none"
        self._ensure_columns()

    def _ensure_columns(self) -> None:
        if not self.columns:
            self.add_columns(*COLUMNS)

    def refresh_from(self, state: TelemetryState) -> None:
        snap = state.snapshot or {}
        nodes = snap.get("nodes", [])
        self._ensure_columns()  # independent of whether on_mount ran yet
        self.clear()
        if not nodes:
            backend = snap.get("volume", {}).get("backend", "local")
            self.add_row(Text("—", style="#7a8a99"),
                         Text(f"{backend} backend", style="#7a8a99"), "", "", "")
            return
        for node in nodes:
            st = node.get("state", "unknown")
            rtt = node.get("rtt_us", 0)
            seen = node.get("last_seen_ms", -1)
            self.add_row(
                Text(f"#{node.get('id')}", style="bold #00e5ff"),
                Text(st.upper(), style=STATE_STYLE.get(st, "#c9d4de")),
                Text(human_latency(rtt) if rtt > 0 else "—", style="#c9d4de"),
                disk_bar(node.get("disk_used", 0), node.get("disk_total", 0)),
                Text("never" if seen < 0 else f"{seen / 1000:.1f}s ago", style="#7a8a99"),
            )
