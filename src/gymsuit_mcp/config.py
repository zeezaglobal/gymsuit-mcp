"""Configuration for the GymSuit MCP server, read from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    # Public base URL of this MCP server, e.g. https://mcp.gymsuit.app.
    # Used as the OAuth issuer and in all metadata / redirect URLs.
    public_url: str = field(
        default_factory=lambda: os.environ.get("PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/")
    )
    # GymSuit backend API, e.g. https://api.gymsuit.app.
    gymsuit_api_base: str = field(
        default_factory=lambda: os.environ.get("GYMSUIT_API_BASE", "https://api.gymsuit.app").rstrip("/")
    )
    # Long random secret. Encrypts stored GymSuit tokens and signs web
    # sessions. Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    secret_key: str = field(default_factory=lambda: os.environ.get("MCP_SECRET_KEY", ""))
    database_path: str = field(
        default_factory=lambda: os.environ.get("DATABASE_PATH", "data/gymsuit-mcp.db")
    )
    host: str = field(default_factory=lambda: os.environ.get("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.environ.get("PORT", "8000")))
    # MCP access tokens live 1 hour; refresh tokens 30 days (rotated on use).
    access_token_ttl: int = field(
        default_factory=lambda: int(os.environ.get("MCP_ACCESS_TOKEN_TTL_SECONDS", "3600"))
    )
    refresh_token_ttl: int = field(
        default_factory=lambda: int(
            os.environ.get("MCP_REFRESH_TOKEN_TTL_SECONDS", str(30 * 24 * 3600))
        )
    )
    auth_code_ttl: int = 600  # OAuth authorization codes: 10 minutes, single use.
    scopes_supported: tuple[str, ...] = ("food:read", "food:write")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls()
