"""File manager API over the decrypted mount, and the "what the servers
store" view of any file's encrypted blocks.

Every write goes through the real FUSE mount, so uploads are scanned,
encrypted and replicated exactly like any other write. Uploads are
streamed straight into the mount: no plaintext temp file is ever written
outside the encrypted volume.
"""

from __future__ import annotations

import asyncio
import errno
import math
import os
import shutil
import stat as st
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/files")

BLOCKS_SHOWN = 64      # blocks listed per file in the storage view
HEX_PREVIEW = 48       # bytes of ciphertext / plaintext shown per block
ENVELOPE_HDR = 56      # generation(8) | iv(16) | tag(32), see krypton_protocol.h


def settings_of(request: Request):
    return request.app.state.settings


def resolve(request: Request, rel: str, must_exist: bool = True) -> Path:
    """Maps a volume path ("/docs/a.txt") to the mount, refusing anything
    that would land outside it: "..", absolute tricks, or symlinks."""
    if "\x00" in rel:
        raise HTTPException(400, "Path contains a NUL byte.")
    root = Path(os.path.realpath(settings_of(request).mount))
    target = Path(os.path.realpath(root / rel.lstrip("/")))
    if target != root and root not in target.parents:
        raise HTTPException(400, "That path is outside the volume.")
    if must_exist and not target.exists():
        raise HTTPException(404, f"{rel} does not exist.")
    return target


def volume_path(request: Request, p: Path) -> str:
    root = Path(os.path.realpath(settings_of(request).mount))
    rel = p.relative_to(root).as_posix()
    return "/" if rel == "." else "/" + rel


def entry(p: Path) -> dict[str, Any]:
    s = p.lstat()
    return {"name": p.name, "dir": st.S_ISDIR(s.st_mode), "size": s.st_size,
            "mtime": int(s.st_mtime), "mode": oct(st.S_IMODE(s.st_mode))}


def os_error(exc: OSError, what: str) -> HTTPException:
    if exc.errno == errno.EACCES:
        return HTTPException(403, f"{what} was blocked by the malware scanner.")
    if exc.errno == errno.EEXIST:
        return HTTPException(409, f"{what}: something with that name already exists.")
    if exc.errno == errno.ENOTEMPTY:
        return HTTPException(409, f"{what}: the folder is not empty.")
    if exc.errno == errno.ENOENT:
        return HTTPException(404, f"{what}: not found.")
    if exc.errno == errno.EIO:
        return HTTPException(502, f"{what} failed: no healthy, authentic copy of the data "
                                  "was available.")
    return HTTPException(500, f"{what} failed: {exc.strerror}.")


@router.get("/list")
async def list_dir(request: Request, path: str = "/") -> dict[str, Any]:
    d = resolve(request, path)
    if not d.is_dir():
        raise HTTPException(400, f"{path} is not a folder.")
    try:
        entries = await asyncio.to_thread(lambda: [entry(c) for c in d.iterdir()])
    except OSError as exc:
        raise os_error(exc, "Listing") from exc
    entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
    return {"path": volume_path(request, d), "entries": entries,
            "mounted": settings_of(request).mount.is_mount()}


@router.get("/download")
async def download(request: Request, path: str) -> FileResponse:
    f = resolve(request, path)
    if not f.is_file():
        raise HTTPException(400, f"{path} is not a file.")
    return FileResponse(f, filename=f.name, media_type="application/octet-stream")


@router.put("/content")
async def upload(request: Request, path: str, overwrite: bool = False) -> dict[str, Any]:
    """Streams the request body into `path` through the encrypted mount."""
    s = settings_of(request)
    target = resolve(request, path, must_exist=False)
    if not target.parent.is_dir():
        raise HTTPException(404, "The destination folder does not exist.")
    if target.exists() and not overwrite:
        raise HTTPException(409, f"{target.name} already exists.")
    length = request.headers.get("content-length")
    if length is not None and int(length) > s.max_upload:
        raise HTTPException(413, f"Files up to {s.max_upload // (1024 * 1024)} MB can be uploaded.")

    written = 0
    f = await asyncio.to_thread(open, target, "wb")
    try:
        async for chunk in request.stream():
            written += len(chunk)
            if written > s.max_upload:
                raise HTTPException(413, f"Files up to {s.max_upload // (1024 * 1024)} MB "
                                         "can be uploaded.")
            await asyncio.to_thread(f.write, chunk)
        await asyncio.to_thread(_commit, f)
    except (OSError, HTTPException) as exc:
        await asyncio.to_thread(_close_quietly, f)
        await asyncio.to_thread(_unlink_quietly, target)
        if isinstance(exc, HTTPException):
            raise
        raise os_error(exc, f"Saving {target.name}") from exc
    return {"path": volume_path(request, target), "size": written}


class PathBody(BaseModel):
    path: str


class RenameBody(BaseModel):
    source: str
    target: str


@router.post("/mkdir")
async def mkdir(request: Request, body: PathBody) -> dict[str, Any]:
    d = resolve(request, body.path, must_exist=False)
    try:
        await asyncio.to_thread(d.mkdir)
    except OSError as exc:
        raise os_error(exc, f"Creating {d.name}") from exc
    return {"path": volume_path(request, d)}


@router.post("/rename")
async def rename(request: Request, body: RenameBody) -> dict[str, Any]:
    src = resolve(request, body.source)
    dst = resolve(request, body.target, must_exist=False)
    root = Path(os.path.realpath(settings_of(request).mount))
    if src == root:
        raise HTTPException(400, "The volume's root folder cannot be renamed.")
    try:
        await asyncio.to_thread(os.rename, src, dst)
    except OSError as exc:
        raise os_error(exc, f"Renaming {src.name}") from exc
    return {"path": volume_path(request, dst)}


@router.delete("")
async def delete(request: Request, path: str, recursive: bool = False) -> dict[str, Any]:
    p = resolve(request, path)
    root = Path(os.path.realpath(settings_of(request).mount))
    if p == root:
        raise HTTPException(400, "The volume's root folder cannot be deleted.")
    try:
        if p.is_dir():
            await asyncio.to_thread(shutil.rmtree if recursive else os.rmdir, p)
        else:
            await asyncio.to_thread(p.unlink)
    except OSError as exc:
        raise os_error(exc, f"Deleting {p.name}") from exc
    return {"deleted": path}


# ---------------------------------------------------------------------------
# What the servers store
# ---------------------------------------------------------------------------

def block_id(ino: int, index: int, generation_parity: int) -> int:
    """kfs_bid() from include/krypton/krypton_volume.h."""
    return (ino << 24) | (index << 1) | (generation_parity & 1)


def object_path(data_dir: Path, bid: int) -> Path:
    """Object naming of src/fs/backend_local.c."""
    return data_dir / f"{bid & 0xff:02x}" / f"{bid:016x}"


def stored_copies(settings, ino: int, index: int) -> list[dict[str, Any]]:
    copies = []
    for node in settings.nodes:
        for parity in (0, 1):
            bid = block_id(ino, index, parity)
            obj = object_path(settings.data_dir(node), bid)
            try:
                with open(obj, "rb") as fh:
                    head = fh.read(ENVELOPE_HDR + HEX_PREVIEW)
                size = obj.stat().st_size
            except OSError:
                continue
            copies.append({
                "node": node, "parity": parity, "objectId": f"{bid:016x}", "bytes": size,
                "generation": int.from_bytes(head[:8], "big") if len(head) >= 8 else None,
                "cipherHex": head[ENVELOPE_HDR:].hex(),
                "tagHex": head[24:ENVELOPE_HDR].hex(),
            })
    return copies


@router.get("/blocks")
async def blocks(request: Request, path: str) -> dict[str, Any]:
    s = settings_of(request)
    f = resolve(request, path)
    if not f.is_file():
        raise HTTPException(400, "Pick a file to see its stored blocks.")
    snap = request.app.state.hub.state.snapshot or {}
    bs = snap.get("volume", {}).get("block_size") or s.block_size

    def gather() -> dict[str, Any]:
        info = f.stat()
        n = math.ceil(info.st_size / bs) if info.st_size else 0
        with open(f, "rb") as fh:
            plain = fh.read(HEX_PREVIEW)
        rows = []
        for index in range(min(n, BLOCKS_SHOWN)):
            rows.append({"index": index, "copies": stored_copies(s, info.st_ino, index)})
        return {"path": volume_path(request, f), "inode": info.st_ino, "size": info.st_size,
                "blockSize": bs, "blockCount": n, "shown": len(rows), "blocks": rows,
                "plainHex": plain.hex(), "plainText": plain.decode("utf-8", "replace")}

    try:
        return await asyncio.to_thread(gather)
    except OSError as exc:
        raise os_error(exc, f"Reading {f.name}") from exc


def _commit(f) -> None:
    """Pushes the file to the storage servers before the upload is reported
    as stored; otherwise it may sit in the daemon's cache for a while."""
    f.flush()
    os.fsync(f.fileno())
    f.close()


def _close_quietly(f) -> None:
    try:
        f.close()
    except OSError:
        pass


def _unlink_quietly(p: Path) -> None:
    try:
        p.unlink()
    except OSError:
        pass
