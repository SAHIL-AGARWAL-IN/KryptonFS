"""The Krypton Console HTTP and WebSocket server.

Access control:
- demo mode: Docker publishes the port only on the host's loopback. The
  launch link's ?token= is swapped for a session cookie on first use and
  redirected away, so it never lingers in history or Referer headers.
- production mode: one shared password (PBKDF2 hash in the environment),
  sessions that expire, failed logins throttled per address, Secure
  cookies, and Origin checked against the public URL.
- Both: HttpOnly SameSite=Strict cookies; state-changing requests must send
  `X-KFS-Request: 1` (a cross-site form cannot); WebSockets must come from
  the page's own origin; CSP and anti-framing headers on every response.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import secrets
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from kryptonfs_dash.telemetry import stream

from .auth import LoginThrottle, Sessions, verify_password
from .hub import Source, TelemetryHub
from .settings import Settings

COOKIE = "kfs_session"
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
OPEN_PATHS = {"/healthz", "/api/session", "/api/login"}
SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; connect-src 'self' ws: wss:; "
                                "img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
                                "font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; "
                                "form-action 'self'"),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

LINK_PAGE = """<!doctype html><meta charset="utf-8"><title>Krypton Console</title>
<style>body{background:#07090c;color:#dfe7ee;font:16px system-ui;display:grid;place-items:center;height:100vh;margin:0}
main{max-width:34rem;padding:2rem}h1{color:#00e5ff;font-size:1.4rem}code{color:#39ff14}</style>
<main><h1>Open the console with its link</h1>
<p>This page needs the private link printed when the demo started. Run
<code>.\\run.cmd</code> again (or <code>./run.sh</code>) and it opens the right address for you.</p></main>"""

NOT_BUILT_PAGE = """<!doctype html><meta charset="utf-8"><title>Krypton Console</title>
<body style="background:#07090c;color:#dfe7ee;font:16px system-ui;padding:2rem">
<h1 style="color:#ff6f61">The console's frontend is not built</h1>
<p>Run <code>npm ci &amp;&amp; npm run build</code> in <code>webui/frontend</code>, or restart the demo.</p>"""


class LoginBody(BaseModel):
    password: str


def create_app(settings: Settings, source: Source | None = None,
               secret: bytes | None = None) -> FastAPI:
    sessions = Sessions(secret or secrets.token_bytes(32),
                        settings.session_hours * 3600 if settings.production else None)
    throttle = LoginThrottle()
    hub = TelemetryHub(source or (lambda: stream(str(settings.socket))))

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        hub.start()
        yield
        await hub.stop()

    app = FastAPI(title="Krypton Console", lifespan=lifespan, docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.settings = settings
    app.state.hub = hub

    def set_session(resp) -> None:
        resp.set_cookie(COOKIE, sessions.issue(), httponly=True, samesite="strict", path="/",
                        secure=settings.cookie_secure,
                        max_age=int(settings.session_hours * 3600) if settings.production else None)

    def origin_ok(origin: str | None, host: str | None) -> bool:
        if origin is None:
            return False
        if settings.public_url:
            return origin == settings.public_url
        return host is not None and origin.split("://", 1)[-1] == host

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        token = request.query_params.get("token")
        if token is not None and not settings.production:
            if not hmac.compare_digest(token, settings.token):
                return _secure(HTMLResponse(LINK_PAGE, status_code=401))
            rest = {k: v for k, v in request.query_params.items() if k != "token"}
            resp = RedirectResponse(path + (f"?{urlencode(rest)}" if rest else ""), status_code=303)
            set_session(resp)
            return _secure(resp)

        signed_in = sessions.valid(request.cookies.get(COOKIE))
        if request.method in MUTATING:
            if request.headers.get("x-kfs-request") != "1":
                return _secure(JSONResponse({"error": "Missing X-KFS-Request header."}, 403))
            if settings.production and not origin_ok(request.headers.get("origin"),
                                                     request.headers.get("host")):
                return _secure(JSONResponse({"error": "Cross-origin request refused."}, 403))

        if not signed_in and path not in OPEN_PATHS:
            if path.startswith("/api/"):
                msg = ("Sign in to continue." if settings.production
                       else "Open the console with the link from run.cmd.")
                return _secure(JSONResponse({"error": msg}, status_code=401))
            if not settings.production:
                return _secure(HTMLResponse(LINK_PAGE, status_code=401))
            # production: the single-page app shows its own sign-in screen
        return _secure(await call_next(request))

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True}

    @app.get("/api/session")
    async def session(request: Request) -> dict[str, Any]:
        """What the frontend needs before it can render anything."""
        return {
            "signedIn": sessions.valid(request.cookies.get(COOKIE)),
            "mode": settings.mode,
            "loginRequired": settings.production,
            "features": {"attacks": settings.allow_attacks,
                         "nodeControl": settings.allow_node_control},
        }

    @app.post("/api/login")
    async def login(body: LoginBody, request: Request) -> JSONResponse:
        if not settings.production:
            return JSONResponse({"error": "Demo mode uses the launch link instead."}, 400)
        addr = request.client.host if request.client else "?"
        wait = throttle.wait_seconds(addr)
        if wait > 0:
            return JSONResponse({"error": f"Too many attempts. Try again in {int(wait) + 1} s."},
                                429, headers={"Retry-After": str(int(wait) + 1)})
        # PBKDF2 is deliberately slow; keep the event loop free meanwhile.
        ok = await asyncio.to_thread(verify_password, body.password, settings.password_hash)
        if not ok:
            throttle.failed(addr)
            return JSONResponse({"error": "That password is not correct."}, 401)
        throttle.succeeded(addr)
        resp = JSONResponse({"signedIn": True})
        set_session(resp)
        return resp

    @app.post("/api/logout")
    async def logout() -> JSONResponse:
        resp = JSONResponse({"signedIn": False})
        resp.delete_cookie(COOKIE, path="/")
        return resp

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        return {"telemetry": hub.status(), "mounted": settings.mount.is_mount()}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        if not sessions.valid(websocket.cookies.get(COOKIE)) or \
                not origin_ok(websocket.headers.get("origin"), websocket.headers.get("host")):
            await websocket.close(code=4401)
            return
        await websocket.accept()
        queue = hub.subscribe()
        try:
            for msg in hub.hello():
                await websocket.send_json(msg)
            while True:
                msg = await queue.get()
                await websocket.send_json(msg)
                if msg.get("type") == "overflow":
                    break  # the browser fell behind; it reconnects and resyncs
        except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
            pass
        finally:
            hub.unsubscribe(queue)
            with contextlib.suppress(RuntimeError):
                await websocket.close()

    from . import cluster, files  # routers read app.state.settings
    app.include_router(files.router)
    app.include_router(cluster.router)

    if settings.static is not None and (settings.static / "index.html").is_file():
        app.mount("/", StaticFiles(directory=settings.static, html=True), name="ui")
    else:
        @app.get("/")
        async def not_built() -> HTMLResponse:
            return HTMLResponse(NOT_BUILT_PAGE, status_code=503)

    return app


def _secure(resp):
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp
