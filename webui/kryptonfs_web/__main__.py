"""Run the Krypton Console, or create a password hash for production.

    python -m kryptonfs_web serve [--host 0.0.0.0] [--port 8080]
    python -m kryptonfs_web hash-password
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys


def main() -> None:
    ap = argparse.ArgumentParser(prog="kryptonfs_web")
    sub = ap.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve", help="run the console (settings from KFS_WEB_* variables)")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8080)
    sub.add_parser("hash-password", help="print a KFS_WEB_PASSWORD_HASH value")
    args = ap.parse_args()

    if args.cmd == "hash-password":
        from .auth import hash_password
        pw = getpass.getpass("Console password: ")
        if len(pw) < 12:
            sys.exit("Use at least 12 characters.")
        if getpass.getpass("Repeat it: ") != pw:
            sys.exit("The passwords do not match.")
        print(hash_password(pw))
        return

    import uvicorn

    from .server import create_app
    from .settings import Settings

    settings = Settings.from_env()
    # Client addresses (used to throttle logins) are taken from
    # X-Forwarded-For only when the request comes from one of these: the
    # HTTPS reverse proxy in front of the console.
    proxies = os.environ.get("KFS_WEB_TRUSTED_PROXIES", "127.0.0.1")
    uvicorn.run(create_app(settings), host=args.host, port=args.port, log_level="warning",
                proxy_headers=True, forwarded_allow_ips=proxies)


if __name__ == "__main__":
    main()
