"""kryptonfs-dash: watch a running KryptonFS mount.

    sudo kryptonfs-dash [--socket PATH]     the live daemon (socket is root-only)
    kryptonfs-dash --demo                   a synthetic feed, no mount needed
"""

from __future__ import annotations

import argparse

from .app import KryptonDash
from .demo import demo_stream
from .telemetry import stream

DEFAULT_SOCKET = "/run/kryptonfs/telemetry.sock"


def main() -> None:
    parser = argparse.ArgumentParser(prog="kryptonfs-dash", description=__doc__.splitlines()[0])
    parser.add_argument("--socket", default=DEFAULT_SOCKET,
                        help=f"telemetry socket ([telemetry] socket; default {DEFAULT_SOCKET})")
    parser.add_argument("--demo", action="store_true", help="show a synthetic feed")
    args = parser.parse_args()

    if args.demo:
        app = KryptonDash(demo_stream, "demo feed", reconnect=False)
    else:
        app = KryptonDash(lambda: stream(args.socket), args.socket)
    app.run()


if __name__ == "__main__":
    main()
