"""The KryptonFS dashboard application."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Grid
from textual.css.query import NoMatches
from textual.widgets import Footer, Header

from .telemetry import TelemetryState
from .widgets import ClusterPanel, IOPanel, MountTree, SecurityPanel

Source = Callable[[], AsyncIterator[dict[str, Any]]]


class KryptonDash(App):
    CSS_PATH = "theme.tcss"
    TITLE = "KRYPTONFS"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "clear_feed", "Clear feed"),
        ("t", "focus_tree", "Tree"),
    ]

    def __init__(self, source: Source, source_name: str, reconnect: bool = True) -> None:
        super().__init__()
        self.source = source
        self.source_name = source_name
        self.reconnect = reconnect
        self.state = TelemetryState()
        self.messages = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Grid(id="grid"):
            yield IOPanel(id="io", classes="panel")
            yield ClusterPanel(id="cluster", classes="panel")
            yield MountTree(id="tree", classes="panel")
            yield SecurityPanel(id="security", classes="panel")
        yield Footer()

    def on_mount(self) -> None:
        titles = {
            "#io": "◈ SYSTEM STATE",
            "#cluster": "◈ CLUSTER HEALTH",
            "#tree": "◈ VIRTUAL MOUNT TREE",
            "#security": "◈ SECURITY AUDIT",
        }
        for selector, title in titles.items():
            self.query_one(selector).border_title = title
        self.sub_title = f"connecting to {self.source_name}"

    def on_ready(self) -> None:
        # Not on_mount: each panel mounts on its own message queue, so a
        # message could otherwise arrive before a panel has finished mounting.
        self.io = self.query_one(IOPanel)
        self.cluster = self.query_one(ClusterPanel)
        self.mount_tree = self.query_one(MountTree)
        self.security = self.query_one(SecurityPanel)
        self.run_worker(self._consume(), exclusive=True)

    def _shutting_down(self) -> bool:
        return not all(p.is_attached for p in (self.io, self.cluster, self.mount_tree, self.security))

    async def _consume(self) -> None:
        while True:
            try:
                async for msg in self.source():
                    self.handle_message(msg)
                self.sub_title = f"{self.source_name}: daemon closed the stream"
            except OSError as exc:
                self.sub_title = f"waiting for {self.source_name}: {exc.strerror or exc}"
            except NoMatches:
                # On quit, the screen's widgets are torn down while a message
                # may still be in flight; anything else is a real bug.
                if self._shutting_down():
                    return
                raise
            if not self.reconnect:
                return
            await asyncio.sleep(1.0)

    def handle_message(self, msg: dict[str, Any]) -> None:
        fresh = self.state.apply(msg)
        self.messages += 1
        kind = msg.get("type")
        if kind == "snapshot":
            vol = msg.get("volume", {})
            self.sub_title = (f"{vol.get('name', '?')} @ {vol.get('mountpoint', '?')} · "
                              f"{vol.get('backend', '?')} · {vol.get('block_size', 0) // 1024} KiB blocks")
            self.io.refresh_from(self.state)
            self.cluster.refresh_from(self.state)
            self.security.refresh_from(self.state)
            self.mount_tree.border_subtitle = f"{msg.get('usage', {}).get('files', 0)} files"
        elif kind == "tree":
            self.mount_tree.refresh_from(self.state)
        if fresh:
            self.security.add_events(fresh)

    def action_clear_feed(self) -> None:
        self.security.clear_feed()

    def action_focus_tree(self) -> None:
        self.mount_tree.focus()
