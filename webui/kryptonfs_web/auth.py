"""Passwords, sessions and login throttling (standard library only)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

PBKDF2_ITERATIONS = 600_000  # same floor the volume KDF uses


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_b64, digest_b64 = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64),
                                     int(iters))
        return hmac.compare_digest(digest, base64.b64decode(digest_b64))
    except (ValueError, TypeError):
        return False


class Sessions:
    """Stateless signed sessions: "<issued>.<hmac>". A server restart or a
    changed secret invalidates every session, which is the safe default."""

    def __init__(self, secret: bytes, max_age_seconds: float | None) -> None:
        self.secret = secret
        self.max_age = max_age_seconds

    def _sig(self, issued: str) -> str:
        return hmac.new(self.secret, issued.encode(), hashlib.sha256).hexdigest()

    def issue(self, now: float | None = None) -> str:
        issued = str(int(now if now is not None else time.time()))
        return f"{issued}.{self._sig(issued)}"

    def valid(self, cookie: str | None, now: float | None = None) -> bool:
        if not cookie or "." not in cookie:
            return False
        issued, sig = cookie.split(".", 1)
        if not issued.isdigit() or not hmac.compare_digest(sig, self._sig(issued)):
            return False
        if self.max_age is None:
            return True
        age = (now if now is not None else time.time()) - int(issued)
        return 0 <= age <= self.max_age


class LoginThrottle:
    """After 5 failures from one address, each further attempt is refused
    for an exponentially growing wait (2 s, 4 s, ... capped at 15 min)."""

    FREE_ATTEMPTS = 5
    MAX_WAIT = 15 * 60

    def __init__(self) -> None:
        self._fails: dict[str, tuple[int, float]] = {}

    def wait_seconds(self, addr: str, now: float | None = None) -> float:
        count, last = self._fails.get(addr, (0, 0.0))
        if count < self.FREE_ATTEMPTS:
            return 0.0
        wait = min(2 ** (count - self.FREE_ATTEMPTS + 1), self.MAX_WAIT)
        remaining = last + wait - (now if now is not None else time.time())
        return max(0.0, remaining)

    def failed(self, addr: str, now: float | None = None) -> None:
        count, _ = self._fails.get(addr, (0, 0.0))
        self._fails[addr] = (count + 1, now if now is not None else time.time())
        if len(self._fails) > 10_000:  # bound memory under a spray of addresses
            self._fails.pop(next(iter(self._fails)))

    def succeeded(self, addr: str) -> None:
        self._fails.pop(addr, None)
