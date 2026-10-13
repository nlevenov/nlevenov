"""Authentication, session handling and HTTP hardening for the web app.

When an API key is configured every page and endpoint except ``/health``,
``/login`` and static assets requires one of:

* an ``X-API-Key`` header (scripts, SIEM forwarders, SOAR), or
* a signed session cookie, obtained by entering the key on ``/login``.

Requests authenticated by cookie that change state must also come from the
same origin (CSRF protection on top of ``SameSite=Strict``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SESSION_COOKIE = "socprio_session"
SESSION_TTL = 12 * 3600  # one shift
MIN_KEY_LENGTH = 16
_PLACEHOLDER_KEYS = {"change-me", "changeme", "secret", "password", "admin"}

CSP_APP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
# Plotly's offline HTML export and Swagger UI rely on inline bootstrap scripts.
# Everything they render is escaped server-side, so the relaxation is scoped
# to those responses only.
CSP_REPORT = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
)
CSP_DOCS = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'none'"
)


def validate_api_key(key: str) -> None:
    """Refuse keys that are trivially guessable. An empty key disables auth."""
    if not key:
        return
    if key.lower() in _PLACEHOLDER_KEYS or len(key) < MIN_KEY_LENGTH:
        raise ValueError(
            f"SOCPRIO_API_KEY is too weak: use at least {MIN_KEY_LENGTH} random characters, "
            "e.g. python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )


class SessionSigner:
    """Stateless HMAC-signed session tokens.

    The signing key is derived from the API key, so rotating the API key
    invalidates every existing session.
    """

    def __init__(self, api_key: str, ttl: int = SESSION_TTL) -> None:
        self._key = hmac.new(api_key.encode(), b"socprio-session-v1", hashlib.sha256).digest()
        self.ttl = ttl

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def issue(self) -> str:
        payload = f"{int(time.time()) + self.ttl}:{secrets.token_hex(8)}".encode()
        return base64.urlsafe_b64encode(payload).decode() + "." + self._sign(payload)

    def verify(self, token: str | None) -> bool:
        if not token or "." not in token:
            return False
        encoded, signature = token.rsplit(".", 1)
        try:
            payload = base64.urlsafe_b64decode(encoded.encode())
            expires = int(payload.split(b":", 1)[0])
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(signature, self._sign(payload)) and expires > time.time()


class FailureLimiter:
    """Locks a client out after too many failed authentication attempts."""

    def __init__(self, max_failures: int = 10, window: int = 300) -> None:
        self.max_failures = max_failures
        self.window = window
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, client: str, now: float) -> deque[float]:
        attempts = self._failures[client]
        while attempts and now - attempts[0] > self.window:
            attempts.popleft()
        return attempts

    def blocked(self, client: str) -> bool:
        with self._lock:
            return len(self._prune(client, time.monotonic())) >= self.max_failures

    def failure(self, client: str) -> None:
        with self._lock:
            now = time.monotonic()
            self._prune(client, now).append(now)

    def reset(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)


def same_origin(origin_or_referer: str | None, host: str | None) -> bool:
    if not origin_or_referer or not host:
        return False
    return urlsplit(origin_or_referer).netloc == host


class HardeningMiddleware:
    """Security headers on every response and a cap on request body size."""

    def __init__(self, app: ASGIApp, max_body_bytes: int = 10 * 1024 * 1024) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope["path"]
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_body_bytes:
            await _plain_response(send, 413, b"request body too large")
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise _BodyTooLarge
            return message

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                if path.startswith(("/docs", "/redoc")):
                    csp = CSP_DOCS
                elif path.startswith("/api/report.html"):
                    csp = CSP_REPORT
                else:
                    csp = CSP_APP
                headers.setdefault("Content-Security-Policy", csp)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "same-origin")
                headers.setdefault("Permissions-Policy",
                                   "camera=(), microphone=(), geolocation=()")
                headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
                if not path.startswith(("/static", "/vendor")):
                    headers.setdefault("Cache-Control", "no-store")
                if scope.get("scheme") == "https":
                    headers.setdefault("Strict-Transport-Security",
                                       "max-age=31536000; includeSubDomains")
            await send(message)

        try:
            await self.app(scope, limited_receive, send_with_headers)
        except _BodyTooLarge:
            await _plain_response(send, 413, b"request body too large")


class _BodyTooLarge(Exception):
    pass


async def _plain_response(send: Send, status: int, body: bytes) -> None:
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"text/plain"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})
