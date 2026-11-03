"""Krypton Console API: access control, file manager, storage view, cluster
controls. Runs against temp dirs standing in for the mount and node data;
node control uses a fake `kfs-noded` script (Linux /proc required)."""

from __future__ import annotations

import asyncio
import errno
import os
import stat
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kryptonfs_web import files as files_mod
from kryptonfs_web.auth import LoginThrottle, Sessions, hash_password, verify_password
from kryptonfs_web.server import COOKIE, create_app
from kryptonfs_web.settings import Settings

TOKEN = "t" * 40
HDR = {"X-KFS-Request": "1"}
SNAPSHOT = {"type": "snapshot", "interval_ms": 500, "volume": {"name": "krypton",
            "block_size": 4096}, "io": {"read_ops": 4}, "events": [
            {"seq": 1, "level": "alert", "kind": "scanner", "msg": "blocked x"}]}


async def fake_source():
    yield SNAPSHOT
    yield {"type": "tree", "entries": [{"path": "/", "dir": True}], "truncated": False}
    await asyncio.sleep(3600)


def make(tmp_path: Path, **kw) -> Settings:
    (tmp_path / "mnt").mkdir(exist_ok=True)
    (tmp_path / "demo").mkdir(exist_ok=True)
    base = dict(mode="demo", token=TOKEN, mount=tmp_path / "mnt", demo=tmp_path / "demo",
                socket=tmp_path / "none.sock", bin_dir=tmp_path / "bin")
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def demo(tmp_path):
    app = create_app(make(tmp_path), source=fake_source)
    with TestClient(app) as c:
        c.get(f"/?token={TOKEN}", follow_redirects=False)
        yield c, tmp_path


# --- access control ---------------------------------------------------------

def test_demo_requires_the_launch_link(tmp_path):
    with TestClient(create_app(make(tmp_path), source=fake_source)) as c:
        assert c.get("/api/status").status_code == 401
        assert c.get("/").status_code == 401
        assert c.get("/?token=wrong").status_code == 401
        r = c.get(f"/?token={TOKEN}&tab=files", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/?tab=files"
        cookie = r.cookies[COOKIE]
        assert TOKEN not in cookie
        assert "httponly" in r.headers["set-cookie"].lower()
        assert "samesite=strict" in r.headers["set-cookie"].lower()
        assert c.get("/api/status").status_code == 200


def test_mutations_need_the_request_header(demo):
    c, _ = demo
    assert c.post("/api/files/mkdir", json={"path": "/x"}).status_code == 403
    assert c.post("/api/files/mkdir", json={"path": "/x"}, headers=HDR).status_code == 200


def test_security_headers(demo):
    c, _ = demo
    r = c.get("/api/status")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"


def prod(tmp_path, **kw):
    return make(tmp_path, mode="production", token="", password_hash=hash_password("correct horse 42", 1000),
                public_url="https://vault.example", cookie_secure=True, allow_attacks=False, **kw)


def test_production_password_login(tmp_path):
    with TestClient(create_app(prod(tmp_path), source=fake_source),
                    base_url="https://vault.example") as c:
        o = {**HDR, "Origin": "https://vault.example"}
        assert c.get("/api/session").json()["loginRequired"] is True
        assert c.get("/api/status").status_code == 401
        assert c.get(f"/?token={TOKEN}").status_code != 303          # no launch links
        assert c.post("/api/login", json={"password": "nope"}, headers=o).status_code == 401
        r = c.post("/api/login", json={"password": "correct horse 42"}, headers=o)
        assert r.status_code == 200
        assert "secure" in r.headers["set-cookie"].lower()
        assert c.get("/api/status").status_code == 200
        assert c.get("/api/session").json()["features"]["attacks"] is False
        # Cross-origin mutation refused even with a valid session.
        bad = {**HDR, "Origin": "https://evil.example"}
        assert c.post("/api/files/mkdir", json={"path": "/x"}, headers=bad).status_code == 403
        c.post("/api/logout", headers=o)
        assert c.get("/api/status").status_code == 401


def test_login_is_throttled(tmp_path):
    with TestClient(create_app(prod(tmp_path), source=fake_source),
                    base_url="https://vault.example") as c:
        o = {**HDR, "Origin": "https://vault.example"}
        codes = [c.post("/api/login", json={"password": "x"}, headers=o).status_code
                 for _ in range(7)]
        assert codes[:5] == [401] * 5 and 429 in codes[5:]


def test_password_and_session_primitives():
    h = hash_password("s3cret passphrase", 1000)
    assert verify_password("s3cret passphrase", h) and not verify_password("other", h)
    assert not verify_password("x", "garbage")
    s = Sessions(b"k" * 32, max_age_seconds=60)
    v = s.issue(now=1000)
    assert s.valid(v, now=1030) and not s.valid(v, now=2000)
    assert not s.valid(v[:-1] + ("0" if v[-1] != "0" else "1"), now=1030)
    assert not Sessions(b"other" * 8, 60).valid(v, now=1030)
    t = LoginThrottle()
    for _ in range(LoginThrottle.FREE_ATTEMPTS - 1):
        t.failed("a", now=0)
    assert t.wait_seconds("a", now=0) == 0
    t.failed("a", now=0)
    assert t.wait_seconds("a", now=0) > 0 and t.wait_seconds("b", now=0) == 0


def test_settings_validation(tmp_path):
    with pytest.raises(ValueError):
        make(tmp_path, token="short").validate()
    with pytest.raises(ValueError):
        make(tmp_path, mode="production", password_hash="").validate()
    prod(tmp_path).validate()


# --- websocket ----------------------------------------------------------------

def test_websocket_streams_state(demo):
    c, _ = demo
    with c.websocket_connect("/ws", headers={"Origin": "http://testserver"}) as ws:
        kinds = [ws.receive_json()["type"] for _ in range(3)]
        assert kinds[0] == "status" and "snapshot" in kinds


def test_websocket_refuses_strangers(tmp_path):
    with TestClient(create_app(make(tmp_path), source=fake_source)) as c:
        with pytest.raises(Exception):
            with c.websocket_connect("/ws", headers={"Origin": "http://testserver"}) as ws:
                ws.receive_json()
        c.get(f"/?token={TOKEN}")
        with pytest.raises(Exception):
            with c.websocket_connect("/ws", headers={"Origin": "http://evil.example"}) as ws:
                ws.receive_json()


# --- file manager -------------------------------------------------------------

def test_file_round_trip(demo):
    c, tmp = demo
    payload = os.urandom(70_000)
    assert c.post("/api/files/mkdir", json={"path": "/docs"}, headers=HDR).status_code == 200
    r = c.put("/api/files/content?path=/docs/a.bin", content=payload, headers=HDR)
    assert r.status_code == 200 and r.json()["size"] == len(payload)
    assert c.put("/api/files/content?path=/docs/a.bin", content=b"x", headers=HDR).status_code == 409
    listing = c.get("/api/files/list?path=/docs").json()
    assert [e["name"] for e in listing["entries"]] == ["a.bin"]
    assert c.get("/api/files/download?path=/docs/a.bin").content == payload
    r = c.post("/api/files/rename", json={"source": "/docs/a.bin", "target": "/docs/b.bin"},
               headers=HDR)
    assert r.status_code == 200 and (tmp / "mnt/docs/b.bin").exists()
    assert c.delete("/api/files?path=/docs", headers=HDR).status_code == 409   # not empty
    assert c.delete("/api/files?path=/docs&recursive=true", headers=HDR).status_code == 200
    assert not (tmp / "mnt/docs").exists()
    assert c.delete("/api/files?path=/", headers=HDR).status_code == 400


@pytest.mark.parametrize("path", ["/../escape.txt", "../../etc/passwd", "/a/../../x"])
def test_paths_cannot_leave_the_volume(demo, path):
    c, _ = demo
    assert c.get(f"/api/files/list?path={path}").status_code in (400, 404)
    assert c.put(f"/api/files/content?path={path}", content=b"x", headers=HDR).status_code == 400


def test_symlinks_cannot_leave_the_volume(demo):
    c, tmp = demo
    (tmp / "outside.txt").write_text("secret")
    os.symlink(tmp / "outside.txt", tmp / "mnt/link")
    assert c.get("/api/files/download?path=/link").status_code == 400


def test_scanner_rejection_becomes_403(demo, monkeypatch):
    c, tmp = demo

    class Blocked:
        def write(self, _):
            raise OSError(errno.EACCES, "Permission denied")

        def close(self):
            pass

    monkeypatch.setattr(files_mod, "open", lambda *a, **k: Blocked(), raising=False)
    r = c.put("/api/files/content?path=/evil.elf", content=b"\x7fELF", headers=HDR)
    assert r.status_code == 403 and "malware scanner" in r.json()["detail"]


def test_upload_size_cap(tmp_path):
    app = create_app(make(tmp_path, max_upload=1000), source=fake_source)
    with TestClient(app) as c:
        c.get(f"/?token={TOKEN}")
        r = c.put("/api/files/content?path=/big", content=b"x" * 2000, headers=HDR)
        assert r.status_code == 413 and not (tmp_path / "mnt/big").exists()


# --- storage view ---------------------------------------------------------------

def test_block_naming_matches_the_c_code():
    # kfs_bid(5, 3, gen=1) = 5<<24 | 3<<1 | 1; backend_local: <low byte>/<16 hex>
    assert files_mod.block_id(5, 3, 1) == 0x5000007
    assert files_mod.object_path(Path("/d"), 0x5000007) == Path("/d/07/0000000005000007")


def test_blocks_view_finds_copies_on_nodes(demo):
    c, tmp = demo
    f = tmp / "mnt/photo.raw"
    f.write_bytes(b"P" * 5000)                      # two 4 KiB blocks
    ino = f.stat().st_ino
    for node, parity in ((1, 0), (3, 0), (2, 1)):
        obj = files_mod.object_path(tmp / f"demo/data{node}", files_mod.block_id(ino, 0, parity))
        obj.parent.mkdir(parents=True, exist_ok=True)
        obj.write_bytes((7).to_bytes(8, "big") + b"\xaa" * 100)
    v = c.get("/api/files/blocks?path=/photo.raw").json()
    assert v["blockCount"] == 2 and v["blockSize"] == 4096
    copies = {(cp["node"], cp["parity"], cp["generation"]) for cp in v["blocks"][0]["copies"]}
    assert copies == {(1, 0, 7), (3, 0, 7), (2, 1, 7)}
    assert v["blocks"][1]["copies"] == []
    assert v["plainText"].startswith("PPP")


# --- cluster controls -------------------------------------------------------------

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs /proc")
def test_node_start_stop_and_log(tmp_path):
    s = make(tmp_path)
    node_bin = s.bin_dir / "src/node/kfs-noded"
    node_bin.parent.mkdir(parents=True)
    # No exec: the process must keep its kfs-noded command line, which is
    # what the server checks before trusting a pid file.
    node_bin.write_text("#!/bin/sh\necho node started\nwhile :; do sleep 1; done\n")
    node_bin.chmod(node_bin.stat().st_mode | stat.S_IEXEC)
    (s.demo / "node2.conf").write_text("[node]\nid = 2\n")
    with TestClient(create_app(s, source=fake_source)) as c:
        c.get(f"/?token={TOKEN}")
        r = c.post("/api/cluster/nodes/2/start", headers=HDR)
        assert r.status_code == 200 and r.json()["running"] is True
        assert c.post("/api/cluster/nodes/2/start", headers=HDR).status_code == 409
        assert c.post("/api/cluster/nodes/1/start", headers=HDR).status_code == 404  # unmanaged
        r = c.post("/api/cluster/nodes/2/stop", json={"how": "crash"}, headers=HDR)
        assert r.status_code == 200 and r.json()["running"] is False
        assert "node started" in c.get("/api/cluster/nodes/2/log").json()["lines"][-1]


def test_attack_lab_guarded(tmp_path):
    with TestClient(create_app(make(tmp_path), source=fake_source)) as c:
        c.get(f"/?token={TOKEN}")
        # The temp dir is not a mounted volume.
        assert c.post("/api/attacks/malware", headers=HDR).status_code == 409
    with TestClient(create_app(prod(tmp_path), source=fake_source),
                    base_url="https://vault.example") as c:
        o = {**HDR, "Origin": "https://vault.example"}
        c.post("/api/login", json={"password": "correct horse 42"}, headers=o)
        assert c.post("/api/attacks/malware", headers=o).status_code == 403
