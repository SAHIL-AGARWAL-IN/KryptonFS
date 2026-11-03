"""Where the console finds things and how it guards access.

Two modes:
  demo        local only: a launch-link token, every control enabled
  production  a deployed server: password login, Secure cookies, expiring
              sessions, the attack lab off
Every path is overridable, so tests can point the console at temp dirs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _flag(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    mode: str = "demo"                            # "demo" or "production"
    token: str = ""                               # demo: the secret in the launch link
    password_hash: str = ""                       # production: pbkdf2_sha256$iters$salt$hash
    public_url: str = ""                          # production: e.g. https://vault.example.com
    cookie_secure: bool = False
    session_hours: float = 12.0
    allow_attacks: bool = True                    # attack lab (deliberately damages data)
    allow_node_control: bool = True               # stop/start nodes this host runs
    mount: Path = Path("/mnt/krypton")            # the decrypted FUSE view
    demo: Path = Path("/demo")                    # node data, pids, configs, logs
    socket: Path = Path("/run/kryptonfs/telemetry.sock")
    static: Path | None = None                    # built frontend (webui/frontend/dist)
    bin_dir: Path = Path("/src/build-linux")      # kryptonfs, kfs-noded
    client_conf: Path = Path("/demo/client.conf")
    nodes: tuple[int, ...] = (1, 2, 3)
    max_upload: int = 256 * 1024 * 1024
    block_size: int = 4096                        # used until telemetry reports one

    @property
    def production(self) -> bool:
        return self.mode == "production"

    def data_dir(self, node: int) -> Path:
        return self.demo / f"data{node}"

    def validate(self) -> None:
        if self.mode not in ("demo", "production"):
            raise ValueError(f"KFS_WEB_MODE must be demo or production, not {self.mode!r}")
        if self.production:
            if not self.password_hash.startswith("pbkdf2_sha256$"):
                raise ValueError("production needs KFS_WEB_PASSWORD_HASH "
                                 "(create one with: python -m kryptonfs_web hash-password)")
            if not self.public_url.startswith("https://") and self.cookie_secure:
                raise ValueError("KFS_WEB_PUBLIC_URL must be the https:// address users open")
        elif len(self.token) < 32:
            raise ValueError("demo mode needs a launch token of at least 32 characters")

    @classmethod
    def from_env(cls) -> "Settings":
        mode = os.environ.get("KFS_WEB_MODE", "demo")
        production = mode == "production"
        token = ""
        if not production:
            token_file = Path(os.environ.get("KFS_WEB_TOKEN_FILE", "/demo/web.token"))
            token = token_file.read_text().strip()
        static = os.environ.get("KFS_WEB_STATIC")
        nodes = tuple(int(n) for n in os.environ.get("KFS_WEB_NODES", "1,2,3").split(",") if n)
        s = cls(
            mode=mode,
            token=token,
            password_hash=os.environ.get("KFS_WEB_PASSWORD_HASH", ""),
            public_url=os.environ.get("KFS_WEB_PUBLIC_URL", "").rstrip("/"),
            cookie_secure=_flag("KFS_WEB_COOKIE_SECURE", production),
            session_hours=float(os.environ.get("KFS_WEB_SESSION_HOURS", "12")),
            allow_attacks=_flag("KFS_WEB_ALLOW_ATTACKS", not production),
            allow_node_control=_flag("KFS_WEB_ALLOW_NODE_CONTROL", True),
            mount=Path(os.environ.get("KFS_WEB_MOUNT", "/mnt/krypton")),
            demo=Path(os.environ.get("KFS_WEB_DEMO", "/demo")),
            socket=Path(os.environ.get("KFS_WEB_SOCKET", "/run/kryptonfs/telemetry.sock")),
            static=Path(static) if static else None,
            bin_dir=Path(os.environ.get("KFS_WEB_BIN", "/src/build-linux")),
            client_conf=Path(os.environ.get("KFS_WEB_CLIENT_CONF", "/demo/client.conf")),
            nodes=nodes,
            max_upload=int(os.environ.get("KFS_WEB_MAX_UPLOAD_MB", "256")) * 1024 * 1024,
        )
        s.validate()
        return s
