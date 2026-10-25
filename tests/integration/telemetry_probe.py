"""Reads a live kryptonfs telemetry socket and checks what it serves.

    python3 telemetry_probe.py SOCKET SECONDS [--expect-file PATH]
        [--expect-alert TEXT] [--expect-nodes N] [--expect-io]

Every line must be valid JSON; snapshots must carry the documented
sections. Exits non-zero with a reason on the first failed expectation.
Standard library only, so it runs without the dashboard installed.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time

SNAPSHOT_KEYS = {"type", "ts_ms", "interval_ms", "volume", "io", "cache", "usage",
                 "nodes", "sandbox", "keys", "events"}


def fail(reason: str) -> None:
    print(f"telemetry probe: {reason}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("socket")
    ap.add_argument("seconds", type=float)
    ap.add_argument("--expect-file")
    ap.add_argument("--expect-alert")
    ap.add_argument("--expect-nodes", type=int)
    ap.add_argument("--expect-io", action="store_true")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(args.socket)
    sock.settimeout(0.5)
    buf, msgs, deadline = b"", [], time.monotonic() + args.seconds
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(1 << 20)
        except socket.timeout:
            continue
        if not chunk:
            break
        buf += chunk
        *lines, buf = buf.split(b"\n")
        for line in lines:
            try:
                msgs.append(json.loads(line))
            except json.JSONDecodeError as exc:
                fail(f"invalid JSON ({exc}): {line[:120]!r}")
    sock.close()

    snaps = [m for m in msgs if m.get("type") == "snapshot"]
    trees = [m for m in msgs if m.get("type") == "tree"]
    events = [e for m in msgs if m.get("type") in ("snapshot", "events") for e in m["events"]]
    if not snaps or not trees:
        fail(f"expected snapshots and a tree, got types {sorted({m.get('type') for m in msgs})}")
    for s in snaps:
        if missing := SNAPSHOT_KEYS - s.keys():
            fail(f"snapshot lacks {sorted(missing)}")

    last = snaps[-1]
    workers = last["sandbox"]["workers"]
    if last["sandbox"]["failed"] or len(workers) != 4 or not all(w["alive"] for w in workers):
        fail(f"expected 4 live jailed workers, got {workers} failed={last['sandbox']['failed']}")
    if "wiped from the daemon" not in last["keys"]["volume_key"]:
        fail(f"unexpected key status {last['keys']['volume_key']!r}")
    if args.expect_io and not any(s["io"]["read_ops"] + s["io"]["write_ops"] for s in snaps):
        fail("no I/O was counted")
    if args.expect_file and not any(e["path"] == args.expect_file
                                    for t in trees for e in t["entries"]):
        fail(f"{args.expect_file} missing from the tree")
    if args.expect_alert and not any(e["level"] == "alert" and args.expect_alert in e["msg"]
                                     for e in events):
        fail(f"no alert containing {args.expect_alert!r}; events: {[e['msg'] for e in events]}")
    if args.expect_nodes is not None:
        up = [n for n in last["nodes"] if n["state"] == "up" and n["rtt_us"] > 0]
        if len(up) != args.expect_nodes:
            fail(f"expected {args.expect_nodes} nodes up with RTT, got {last['nodes']}")

    print(f"telemetry probe: {len(msgs)} messages, {len(snaps)} snapshots, "
          f"{len(events)} events, all valid")


if __name__ == "__main__":
    main()
