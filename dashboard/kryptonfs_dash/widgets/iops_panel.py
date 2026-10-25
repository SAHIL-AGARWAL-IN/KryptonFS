"""Active system state: IOPS, throughput, latency and cache."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Label, Sparkline, Static

from ..telemetry import TelemetryState, human_bytes, human_latency


def stats_text(state: TelemetryState) -> Text:
    """The panel's figures: per-op rates and latency, cache, data volume."""
    r = state.rates
    snap = state.snapshot or {}
    cache = snap.get("cache", {})
    usage = snap.get("usage", {})

    text = Text()
    for name, iops, bps, lat, lat_max in (
        ("READ ", r.read_iops, r.read_bps, r.read_lat_us, r.read_lat_max_us),
        ("WRITE", r.write_iops, r.write_bps, r.write_lat_us, r.write_lat_max_us),
    ):
        text.append(f" {name} ", style="bold #00e5ff")
        text.append(f"{iops:>8,.0f} op/s", style="bold #39ff14")
        text.append(f"  {human_bytes(bps):>11}/s", style="#c9d4de")
        text.append(f"   lat {human_latency(lat):>8}", style="#c9d4de")
        text.append(f"  max {human_latency(lat_max)}\n", style="#7a8a99")

    frames = cache.get("frames", 0) or 1
    lookups = cache.get("hits", 0) + cache.get("misses", 0)
    hit = 100.0 * cache.get("hits", 0) / lookups if lookups else 0.0
    text.append(" CACHE ", style="bold #00e5ff")
    text.append(f"{100 * cache.get('used', 0) / frames:5.1f}% used", style="#c9d4de")
    text.append(f"  {cache.get('dirty', 0):,} dirty", style="#c9d4de")
    text.append(f"  {hit:5.1f}% hits", style="#39ff14" if hit >= 90 else "#ff6f61")
    text.append(f"  {cache.get('evictions', 0):,} evictions\n", style="#7a8a99")

    text.append(" DATA  ", style="bold #00e5ff")
    text.append(f"{usage.get('files', 0):,} files  {usage.get('dirs', 0):,} dirs  "
                f"{usage.get('data_blocks', 0):,} encrypted blocks", style="#c9d4de")
    if r.errors:
        text.append(f"   {r.errors} I/O errors", style="bold #ff6f61")
    return text


class IOPanel(Vertical):
    def compose(self) -> ComposeResult:
        yield Static(id="io-stats")
        yield Label("READ IOPS", classes="spark-label")
        yield Sparkline([0], id="read-spark", summary_function=max)
        yield Label("WRITE IOPS", classes="spark-label")
        yield Sparkline([0], id="write-spark", summary_function=max)

    def refresh_from(self, state: TelemetryState) -> None:
        self.query_one("#io-stats", Static).update(stats_text(state))
        self.query_one("#read-spark", Sparkline).data = list(state.read_iops) or [0]
        self.query_one("#write-spark", Sparkline).data = list(state.write_iops) or [0]
