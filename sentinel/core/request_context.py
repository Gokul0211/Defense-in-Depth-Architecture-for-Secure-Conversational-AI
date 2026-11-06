"""
Per-request context shared by the layers (L1 review B8, 2026-10-27).

`LIVE_REQUEST` is True while the FastAPI app is serving a request (set by `LiveRequestMiddleware` in app.py) and
False everywhere else -- evaluation harnesses call the layers directly and never pass through the middleware.

Why it exists: the hosted L1 judge waits patiently for a rate-limited key pool, which is correct for a benchmark
(a skipped sample corrupts the measurement) and wrong for a live request (a user waits behind it). The judge reads
this flag and applies `L1_JUDGE_LIVE_DEADLINE_S` only to live requests, so every evaluation keeps its behaviour.
"""
from __future__ import annotations

import contextvars

LIVE_REQUEST: contextvars.ContextVar[bool] = contextvars.ContextVar("dida_live_request", default=False)


def is_live_request() -> bool:
    return LIVE_REQUEST.get()


class LiveRequestMiddleware:
    """Pure ASGI middleware: marks HTTP and WebSocket handling as live. (Not BaseHTTPMiddleware, which runs the app
    in a separate task and has known problems with streaming responses.)"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        token = LIVE_REQUEST.set(True)
        try:
            await self.app(scope, receive, send)
        finally:
            LIVE_REQUEST.reset(token)
