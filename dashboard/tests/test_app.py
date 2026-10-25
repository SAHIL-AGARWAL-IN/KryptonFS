"""The dashboard rendered headless against the demo feed."""

from __future__ import annotations

import asyncio

from textual.widgets import DataTable, RichLog

from kryptonfs_dash.app import KryptonDash
from kryptonfs_dash.demo import demo_stream
from kryptonfs_dash.widgets import MountTree


def fast_demo():
    return demo_stream(interval=0.01)


async def wait_for(pilot, condition, timeout=10.0):
    """Polls instead of sleeping a fixed time, so slow machines don't flake."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition() and loop.time() < deadline:
        await pilot.pause(0.05)
    return condition()


def test_panels_fill_from_the_feed():
    async def scenario():
        app = KryptonDash(fast_demo, "demo", reconnect=False)
        async with app.run_test(size=(160, 48)) as pilot:
            await wait_for(pilot, lambda: len(app.state.read_iops) >= 5 and
                           len(app.query_one(MountTree).root.children) > 0)
            table = app.query_one("#cluster", DataTable)
            tree = app.query_one(MountTree)
            feed = app.query_one("#feed", RichLog)
            return {
                "rows": table.row_count,
                "top_level": [str(c.label) for c in tree.root.children],
                "feed_lines": len(feed.lines),
                "history": len(app.state.read_iops),
                "sub_title": app.sub_title,
            }

    got = asyncio.run(scenario())
    assert got["rows"] == 3
    assert any(label.startswith("finance") for label in got["top_level"])
    assert got["feed_lines"] >= 6  # the start-up events
    assert got["history"] >= 5
    assert "krypton @ /mnt/krypton" in got["sub_title"]


def test_keybindings_do_not_crash():
    async def scenario():
        app = KryptonDash(fast_demo, "demo", reconnect=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await wait_for(pilot, lambda: app.state.snapshot is not None)
            await pilot.press("t")
            await pilot.press("c")
            await pilot.pause(0.05)
            return len(app.query_one("#feed", RichLog).lines)

    asyncio.run(scenario())


def test_unreachable_socket_is_reported():
    async def unreachable():
        raise FileNotFoundError(2, "No such file or directory")
        yield  # pragma: no cover - makes this an async generator

    async def scenario():
        app = KryptonDash(unreachable, "/run/kryptonfs/telemetry.sock", reconnect=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await wait_for(pilot, lambda: "waiting" in app.sub_title)
            return app.sub_title

    assert "waiting for /run/kryptonfs/telemetry.sock" in asyncio.run(scenario())
