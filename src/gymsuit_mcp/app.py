"""Starlette wiring: OAuth routes + /mcp (FastMCP, Streamable HTTP).

/mcp is guarded by a pure-ASGI Bearer check (streaming-safe: it never
reads the response body). A missing or invalid token gets a 401 with a
WWW-Authenticate header pointing at the protected-resource metadata, as
the MCP Authorization spec requires.
"""

from __future__ import annotations

import json
import secrets
import sys
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.routing import Mount

from .config import Settings
from .gymsuit import GymSuitClient
from .mcp_server import create_mcp_server, current_gymsuit_email
from .oauth import OAuthRoutes
from .store import Store


class MCPAuthMiddleware:
    def __init__(self, app, store: Store, public_url: str) -> None:
        self.app = app
        self.store = store
        self.public_url = public_url

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not str(scope.get("path", "")).startswith("/mcp"):
            await self.app(scope, receive, send)
            return
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        auth = headers.get(b"authorization", b"").decode("latin-1")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        record = await self.store.get_access_token(token) if token else None
        if record is None:
            body = json.dumps(
                {
                    "error": "unauthorized",
                    "error_description": "A valid MCP access token is required. Sign in with your GymSuit account.",
                }
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (
                            b"www-authenticate",
                            f'Bearer resource_metadata="{self.public_url}/.well-known/oauth-protected-resource"'.encode(),
                        ),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        reset = current_gymsuit_email.set(record["email"])
        try:
            await self.app(scope, receive, send)
        finally:
            current_gymsuit_email.reset(reset)


def _allowed_hosts(settings: Settings) -> list[str] | None:
    override = __import__("os").environ.get("MCP_ALLOWED_HOSTS", "").strip()
    if override:
        return [h.strip() for h in override.split(",") if h.strip()]
    host = urlparse(settings.public_url).hostname
    if host and host not in ("127.0.0.1", "localhost"):
        return [host]
    return None


def create_app(settings: Settings | None = None) -> Starlette:
    settings = settings or Settings.from_env()
    if not settings.secret_key:
        settings.secret_key = secrets.token_urlsafe(32)
        print(
            "WARNING: MCP_SECRET_KEY is not set; using a random key. Sessions and "
            "stored GymSuit tokens will NOT survive a restart.",
            file=sys.stderr,
        )
    store = Store(settings.database_path)
    gymsuit = GymSuitClient(settings.gymsuit_api_base)
    mcp = create_mcp_server(settings, store, gymsuit)
    oauth = OAuthRoutes(settings, store, gymsuit)

    mcp_app = mcp.http_app(
        path="/",
        transport="streamable-http",
        allowed_hosts=_allowed_hosts(settings),
    )

    @asynccontextmanager
    async def lifespan(app: Starlette):
        # FastMCP's Streamable HTTP transport needs its own lifespan running
        # (it starts the session manager's task group); without it every
        # /mcp request fails with "Task group is not initialized".
        await store.init()
        async with mcp_app.lifespan(app):
            yield
        await store.close()
        await gymsuit.close()

    routes = list(oauth.router().routes)
    routes.append(Mount("/mcp", app=mcp_app))
    app = Starlette(
        routes=routes,
        middleware=[
            Middleware(SessionMiddleware, secret_key=settings.secret_key, max_age=1800)
        ],
        lifespan=lifespan,
    )
    app.add_middleware(MCPAuthMiddleware, store=store, public_url=settings.public_url)
    return app
