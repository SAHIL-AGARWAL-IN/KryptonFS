"""Telemetry aggregation, formatting and the socket client."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile

from kryptonfs_dash.demo import DemoFeed
from kryptonfs_dash.telemetry import TelemetryState, human_bytes, human_latency, stream
from kryptonfs_dash.widgets.audit_feed import status_text
from kryptonfs_dash.widgets.iops_panel import stats_text


def snapshot(**io):
    base = {"read_ops": 0, "write_ops": 0, "read_bytes": 0, "write_bytes": 0,
            "read_lat_us": 0, "write_lat_us": 0, "errors": 0}
    base.update(io)
    return {"type": "snapshot", "interval_ms": 500, "io": base, "events": []}


def test_rates_are_per_second():
    s = TelemetryState()
    s.apply(snapshot(read_ops=10, write_ops=3, read_bytes=40960, read_lat_us=250))
    assert s.rates.read_iops == 20
    assert s.rates.write_iops == 6
    assert s.rates.read_bps == 81920
    assert s.rates.read_lat_us == 250
    assert list(s.read_iops) == [20]


def test_history_is_bounded():
    s = TelemetryState(history=5)
    for i in range(12):
        s.apply(snapshot(read_ops=i))
    assert list(s.read_iops) == [14, 16, 18, 20, 22]


def test_events_are_deduplicated_across_backfill_and_snapshots():
    s = TelemetryState()
    backfill = {"type": "events", "events": [{"seq": n, "msg": str(n)} for n in (1, 2, 3)]}
    assert [e["seq"] for e in s.apply(backfill)] == [1, 2, 3]
    snap = snapshot()
    snap["events"] = [{"seq": 3, "msg": "3"}, {"seq": 4, "msg": "4"}]
    assert [e["seq"] for e in s.apply(snap)] == [4]
    assert len(s.events) == 4


def test_tree_message():
    s = TelemetryState()
    s.apply({"type": "tree", "entries": [{"path": "/", "dir": True}], "truncated": True})
    assert s.tree == [{"path": "/", "dir": True}]
    assert s.tree_truncated


def test_formatting():
    assert human_bytes(512) == "512 B"
    assert human_bytes(1536) == "1.5 KiB"
    assert human_bytes(3 * 1024**3) == "3.0 GiB"
    assert human_latency(850) == "850 µs"
    assert human_latency(12_500) == "12.5 ms"
    assert human_latency(2_500_000) == "2.50 s"


def test_panel_text_reflects_state():
    s = TelemetryState()
    feed = DemoFeed()
    s.apply(feed.snapshot())
    assert "op/s" in stats_text(s).plain
    status = status_text(s).plain
    assert "JAILED" in status
    assert "wiped from the daemon" in status

    failed = feed.snapshot()
    failed["sandbox"]["failed"] = True
    failed["keys"]["volume_key"] = "unavailable: sandbox failed closed"
    s.apply(failed)
    assert "FAILED CLOSED" in status_text(s).plain


def test_stream_reads_json_lines_from_a_unix_socket():
    async def scenario():
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.sock")
            lines = [json.dumps({"type": "events", "events": []}),
                     "{torn line",
                     json.dumps(snapshot(read_ops=1))]

            async def serve(reader, writer):
                writer.write(("\n".join(lines) + "\n").encode())
                await writer.drain()
                writer.close()

            server = await asyncio.start_unix_server(serve, path)
            async with server:
                return [m async for m in stream(path)]

    got = asyncio.run(scenario())
    assert [m["type"] for m in got] == ["events", "snapshot"]  # the torn line is skipped


def test_stream_raises_when_nothing_listens():
    async def scenario():
        async for _ in stream("/nonexistent/kryptonfs.sock"):
            pass

    try:
        asyncio.run(scenario())
    except OSError:
        return
    raise AssertionError("expected OSError")
