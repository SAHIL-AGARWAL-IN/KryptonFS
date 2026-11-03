"""Cluster controls (nodes, lock/unlock) and the attack lab.

The console manages the processes of the layout scripts/demo-cluster.sh
(and deploy/) creates: /demo/node<N>.{conf,pid,log}, /demo/client.{conf,
pid,log}. Attack simulations deliberately damage and then restore data,
so they exist only when the settings allow them (never by default in
production).
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .files import block_id, object_path

router = APIRouter(prefix="/api")
_ops = asyncio.Lock()          # one lock/unlock/attack at a time
_children: dict[str, subprocess.Popen] = {}


def S(request: Request):
    return request.app.state.settings


# ---------------------------------------------------------------------------
# processes
# ---------------------------------------------------------------------------

def _pid(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def _alive(pid: int | None, name: str) -> bool:
    if not pid:
        return False
    for key, proc in list(_children.items()):   # reap our own exited children
        if proc.poll() is not None:
            _children.pop(key, None)
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return name.encode() in cmdline and ") Z " not in stat  # not a zombie


def _spawn(key: str, argv: list[str], log: Path, pidfile: Path, stdin: bytes | None = None,
           env: dict[str, str] | None = None) -> subprocess.Popen:
    out = open(log, "ab")
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                            stdout=out, stderr=subprocess.STDOUT, start_new_session=True, env=env)
    out.close()
    if stdin is not None:
        proc.stdin.write(stdin)
        proc.stdin.close()
    pidfile.write_text(f"{proc.pid}\n")
    _children[key] = proc
    return proc


def _tail(path: Path, lines: int) -> list[str]:
    try:
        data = path.read_bytes()[-64 * 1024:]
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()[-lines:]


def _dir_usage(d: Path) -> tuple[int, int]:
    count = size = 0
    for root, _, names in os.walk(d):
        for n in names:
            if n.startswith(".tmp."):
                continue
            count += 1
            try:
                size += os.stat(os.path.join(root, n)).st_size
            except OSError:
                pass
    return count, size


def _node_info(s, node: int) -> dict[str, Any]:
    pid = _pid(s.demo / f"node{node}.pid")
    objects, size = _dir_usage(s.data_dir(node))
    return {"id": node, "pid": pid, "running": _alive(pid, "kfs-noded"),
            "objects": objects, "bytes": size,
            "managed": (s.demo / f"node{node}.conf").is_file()}


def _check_node(s, node: int) -> None:
    if not s.allow_node_control:
        raise HTTPException(403, "Node control is turned off on this server.")
    if node not in s.nodes or not (s.demo / f"node{node}.conf").is_file():
        raise HTTPException(404, f"Node {node} is not managed by this server.")


@router.get("/cluster")
async def cluster(request: Request) -> dict[str, Any]:
    s = S(request)
    nodes = await asyncio.to_thread(lambda: [_node_info(s, n) for n in s.nodes])
    client_pid = _pid(s.demo / "client.pid")
    return {"nodes": nodes, "mounted": s.mount.is_mount(),
            "client": {"pid": client_pid, "running": _alive(client_pid, "kryptonfs")},
            "features": {"attacks": s.allow_attacks, "nodeControl": s.allow_node_control}}


class StopBody(BaseModel):
    how: str = "graceful"   # "graceful" (SIGTERM) or "crash" (SIGKILL)


@router.post("/cluster/nodes/{node}/stop")
async def stop_node(request: Request, node: int, body: StopBody) -> dict[str, Any]:
    s = S(request)
    _check_node(s, node)
    pid = _pid(s.demo / f"node{node}.pid")
    if not _alive(pid, "kfs-noded"):
        raise HTTPException(409, f"Node {node} is not running.")
    os.kill(pid, signal.SIGKILL if body.how == "crash" else signal.SIGTERM)
    for _ in range(50):
        if not _alive(pid, "kfs-noded"):
            break
        await asyncio.sleep(0.1)
    return _node_info(s, node)


@router.post("/cluster/nodes/{node}/start")
async def start_node(request: Request, node: int) -> dict[str, Any]:
    s = S(request)
    _check_node(s, node)
    if _alive(_pid(s.demo / f"node{node}.pid"), "kfs-noded"):
        raise HTTPException(409, f"Node {node} is already running.")
    proc = _spawn(f"node{node}", [str(s.bin_dir / "src/node/kfs-noded"), "-c",
                                  str(s.demo / f"node{node}.conf")],
                  s.demo / f"node{node}.log", s.demo / f"node{node}.pid")
    await asyncio.sleep(0.8)
    if proc.poll() is not None:
        raise HTTPException(500, f"Node {node} exited at once: "
                                 + " ".join(_tail(s.demo / f"node{node}.log", 3)))
    return _node_info(s, node)


@router.get("/cluster/nodes/{node}/log")
async def node_log(request: Request, node: int, lines: int = 80) -> dict[str, Any]:
    s = S(request)
    if node not in s.nodes:
        raise HTTPException(404, f"No node {node}.")
    return {"node": node, "lines": _tail(s.demo / f"node{node}.log", min(lines, 500))}


# ---------------------------------------------------------------------------
# lock / unlock
# ---------------------------------------------------------------------------

async def _lock(s) -> None:
    if not s.mount.is_mount():
        return
    for _ in range(20):  # files opened only for a moment shouldn't stop a lock
        proc = await asyncio.create_subprocess_exec("fusermount3", "-u", str(s.mount),
                                                    stderr=asyncio.subprocess.PIPE)
        _, err = await proc.communicate()
        if proc.returncode == 0:
            break
        await asyncio.sleep(0.25)
    else:
        msg = err.decode(errors="replace").strip()
        raise HTTPException(409, "The volume is busy (a file is open in it). "
                                 f"Close it and try again. {msg}")
    pid = _pid(s.demo / "client.pid")
    for _ in range(100):  # the daemon syncs and exits after unmount
        if not _alive(pid, "kryptonfs"):
            return
        await asyncio.sleep(0.1)


async def _unlock(s, passphrase: str) -> None:
    if s.mount.is_mount():
        return
    if not passphrase:
        raise HTTPException(400, "Enter the volume passphrase.")
    # The daemon reads $KRYPTONFS_PASSPHRASE before stdin: drop it so the
    # passphrase typed here is the one that counts.
    env = {k: v for k, v in os.environ.items() if k != "KRYPTONFS_PASSPHRASE"}
    log = s.demo / "client.log"
    mark = log.stat().st_size if log.exists() else 0
    proc = _spawn("client", [str(s.bin_dir / "src/fuse/kryptonfs"), "-c", str(s.client_conf),
                             str(s.mount)], log, s.demo / "client.pid",
                  stdin=passphrase.encode() + b"\n", env=env)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if s.mount.is_mount():
            return
        if proc.poll() is not None:
            out = log.read_bytes()[mark:].decode("utf-8", "replace")
            if "wrong passphrase" in out:
                raise HTTPException(401, "That passphrase does not unlock this volume.")
            last = [l for l in out.splitlines() if l.strip()][-1:] or ["no output"]
            raise HTTPException(500, f"The volume did not mount: {last[0]}")
        await asyncio.sleep(0.2)
    raise HTTPException(504, "The volume did not mount within 30 seconds.")


class UnlockBody(BaseModel):
    passphrase: str


@router.post("/volume/lock")
async def lock(request: Request) -> dict[str, Any]:
    async with _ops:
        await _lock(S(request))
    return {"mounted": S(request).mount.is_mount()}


@router.post("/volume/unlock")
async def unlock(request: Request, body: UnlockBody) -> dict[str, Any]:
    async with _ops:
        await _unlock(S(request), body.passphrase)
    return {"mounted": S(request).mount.is_mount()}


# ---------------------------------------------------------------------------
# attack lab
# ---------------------------------------------------------------------------

def _require_attacks(s) -> None:
    if not s.allow_attacks:
        raise HTTPException(403, "The attack lab is turned off on this server.")
    if not s.mount.is_mount():
        raise HTTPException(409, "Unlock the volume first.")


def _step(steps: list, code: str, ok: bool = True, **params: Any) -> None:
    """Steps are codes plus values; the UI words them in its language."""
    steps.append({"code": code, "ok": ok, "params": params})


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _demo_passphrase() -> str:
    return os.environ.get("KFS_WEB_DEMO_PASSPHRASE", "")


async def _remount(s, steps: list) -> None:
    await _lock(s)
    await _unlock(s, _demo_passphrase())
    _step(steps, "remount")


@router.post("/attacks/malware")
async def attack_malware(request: Request) -> dict[str, Any]:
    s = S(request)
    _require_attacks(s)
    steps: list = []
    lab = s.mount / "attack-lab"
    target = lab / "dropper.elf"

    def attempt() -> OSError | None:
        lab.mkdir(exist_ok=True)
        try:
            with open(target, "wb") as fh:
                fh.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)
            return None
        except OSError as exc:
            return exc
        finally:
            try:
                target.unlink()
            except OSError:
                pass

    async with _ops:
        _step(steps, "malware.tried", path="/attack-lab/dropper.elf")
        err = await asyncio.to_thread(attempt)
    blocked = err is not None and err.errno == errno.EACCES
    if blocked:
        _step(steps, "malware.blocked")
    else:
        _step(steps, "malware.allowed", False, error=str(err))
    return {"attack": "malware", "defended": blocked, "steps": steps}


def _pick_file(s, rel: str | None) -> Path:
    if rel:
        p = Path(os.path.realpath(s.mount / rel.lstrip("/")))
        if s.mount.resolve() not in p.parents or not p.is_file() or p.stat().st_size == 0:
            raise HTTPException(400, "Pick a non-empty file inside the volume.")
        return p
    # A file nothing is writing to, so a changed read means tampering.
    quiet = time.time() - 10
    for root, _, names in os.walk(s.mount):
        for n in sorted(names):
            p = Path(root) / n
            st = p.stat()
            if st.st_size > 0 and st.st_mtime < quiet and "attack-lab" not in p.parts:
                return p
    raise HTTPException(409, "Upload a file first: there is nothing to tamper with.")


async def _integrity_alert(request: Request, since_ms: float) -> bool:
    """Whether the daemon reported a failed integrity check since then."""
    hub = request.app.state.hub
    for _ in range(15):  # events arrive with the next snapshot
        if any(e.get("kind") == "integrity" and e.get("ts_ms", 0) >= since_ms
               for e in list(hub.state.events)):
            return True
        await asyncio.sleep(0.2)
    return False


class TamperBody(BaseModel):
    path: str | None = None


@router.post("/attacks/tamper")
async def attack_tamper(request: Request, body: TamperBody) -> dict[str, Any]:
    s = S(request)
    _require_attacks(s)
    steps: list = []
    async with _ops:
        f = await asyncio.to_thread(_pick_file, s, body.path)
        rel = "/" + f.relative_to(s.mount.resolve()).as_posix()
        before = await asyncio.to_thread(_sha256, f)
        ino = f.stat().st_ino
        _step(steps, "tamper.fingerprint", path=rel, hash=before[:16])

        holders = {}
        for node in s.nodes:
            objs = [object_path(s.data_dir(node), block_id(ino, 0, p)) for p in (0, 1)]
            if objs := [o for o in objs if o.exists()]:
                holders[node] = objs
        if not holders:
            raise HTTPException(409, f"No stored copy of {rel} was found on this host's nodes.")

        # Corrupt block 0 on one server at a time. The client reads the
        # servers in its own preference order and stops at the first good
        # copy, so if it happened to read an honest server first, the
        # damage went unseen: put it back and try the next server.
        defended = False
        for victim, objs in holders.items():
            backups = {o: o.read_bytes() for o in objs}
            try:
                for o, data in backups.items():
                    flipped = bytearray(data)
                    flipped[min(len(flipped) - 1, 56 + 10)] ^= 0xFF
                    o.write_bytes(bytes(flipped))
                _step(steps, "tamper.corrupted", node=victim, objects=len(backups))
                await _remount(s, steps)
                since = time.time() * 1000 - 50
                try:
                    same = await asyncio.to_thread(_sha256, f) == before
                except OSError as exc:
                    _step(steps, "tamper.readFailed", False, error=exc.strerror or str(exc))
                    break
                if not same:
                    _step(steps, "tamper.readDiff", False)
                    break
                if await _integrity_alert(request, since):
                    _step(steps, "tamper.readSame")
                    defended = True
                    break
                _step(steps, "tamper.notRead", node=victim)
            finally:
                for o, data in backups.items():
                    o.write_bytes(data)
                _step(steps, "tamper.repaired", node=victim)
    return {"attack": "tamper", "defended": defended, "steps": steps}


class KillBody(BaseModel):
    node: int | None = None


@router.post("/attacks/kill-node")
async def attack_kill(request: Request, body: KillBody) -> dict[str, Any]:
    s = S(request)
    _require_attacks(s)
    steps: list = []
    async with _ops:
        node = body.node or next((n for n in s.nodes
                                  if _alive(_pid(s.demo / f"node{n}.pid"), "kfs-noded")), None)
        if node is None:
            raise HTTPException(409, "No storage node is running.")
        _check_node(s, node)
        os.kill(_pid(s.demo / f"node{node}.pid"), signal.SIGKILL)
        _step(steps, "kill.crashed", node=node)
        await asyncio.sleep(2.0)  # let heartbeats notice
        await _remount(s, steps)
        f = await asyncio.to_thread(_pick_file, s, None)
        try:
            await asyncio.to_thread(_sha256, f)
            ok = True
            _step(steps, "kill.readOk", path="/" + f.relative_to(s.mount.resolve()).as_posix())
        except OSError as exc:
            ok = False
            _step(steps, "kill.readFailed", False, error=exc.strerror or str(exc))
        _step(steps, "kill.leftDown", node=node)
    return {"attack": "kill-node", "defended": ok, "steps": steps, "node": node}
