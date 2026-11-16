"""SQLite storage for the OAuth authorization server.

Tables:
- oauth_clients: dynamically registered MCP clients (public clients, PKCE).
- auth_codes: single-use authorization codes, stored hashed, PKCE-bound.
- mcp_tokens: MCP access + refresh tokens, stored hashed, revocable.
- gymsuit_users: one row per GymSuit user, holding their GymSuit tokens
  Fernet-encrypted so this server can call the GymSuit API for them.
"""

from __future__ import annotations

import json
import time

import aiosqlite

from .crypto import new_token, pkce_challenge, token_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    redirect_uris TEXT NOT NULL,
    client_name TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scope TEXT NOT NULL,
    email TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS mcp_tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    client_id TEXT NOT NULL,
    email TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS gymsuit_users (
    email TEXT PRIMARY KEY,
    first_name TEXT,
    last_name TEXT,
    member_id INTEGER,
    gym_id INTEGER,
    gym_name TEXT,
    access_token_enc TEXT NOT NULL,
    refresh_token_enc TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
"""


class Store:
    def __init__(self, path: str) -> None:
        self._path = path
        self._db: aiosqlite.Connection | None = None

    async def init(self) -> None:
        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    # -- OAuth clients -------------------------------------------------
    async def create_client(self, redirect_uris: list[str], client_name: str | None) -> str:
        client_id = "mcp_" + new_token().replace("-", "").replace("_", "")[:28]
        await self._db.execute(
            "INSERT INTO oauth_clients (client_id, redirect_uris, client_name, created_at)"
            " VALUES (?, ?, ?, ?)",
            (client_id, json.dumps(redirect_uris), client_name, int(time.time())),
        )
        await self._db.commit()
        return client_id

    async def get_client(self, client_id: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    # -- Authorization codes -------------------------------------------
    async def create_auth_code(
        self, client_id: str, redirect_uri: str, code_challenge: str, scope: str, email: str, ttl: int
    ) -> str:
        code = new_token()
        await self._db.execute(
            "INSERT INTO auth_codes (code_hash, client_id, redirect_uri, code_challenge,"
            " scope, email, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                token_hash(code),
                client_id,
                redirect_uri,
                code_challenge,
                scope,
                email,
                int(time.time()) + ttl,
            ),
        )
        await self._db.commit()
        return code

    async def redeem_auth_code(
        self, code: str, client_id: str, redirect_uri: str, verifier: str
    ) -> dict | None:
        """Validate a code (hash, client, redirect, expiry, PKCE) and burn it."""
        cursor = await self._db.execute(
            "SELECT * FROM auth_codes WHERE code_hash = ?", (token_hash(code),)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        data = dict(row)
        if data["used"]:
            return None
        if data["expires_at"] <= int(time.time()):
            return None
        if data["client_id"] != client_id or data["redirect_uri"] != redirect_uri:
            return None
        if pkce_challenge(verifier) != data["code_challenge"]:
            return None
        await self._db.execute(
            "UPDATE auth_codes SET used = 1 WHERE code_hash = ?", (token_hash(code),)
        )
        await self._db.commit()
        return data

    # -- MCP tokens ------------------------------------------------------
    async def issue_token_pair(
        self, client_id: str, email: str, scope: str, access_ttl: int, refresh_ttl: int
    ) -> tuple[str, str]:
        access_raw, refresh_raw = new_token(), new_token()
        now = int(time.time())
        await self._db.execute(
            "INSERT INTO mcp_tokens (token_hash, kind, client_id, email, scope, expires_at)"
            " VALUES (?, 'access', ?, ?, ?, ?)",
            (token_hash(access_raw), client_id, email, scope, now + access_ttl),
        )
        await self._db.execute(
            "INSERT INTO mcp_tokens (token_hash, kind, client_id, email, scope, expires_at)"
            " VALUES (?, 'refresh', ?, ?, ?, ?)",
            (token_hash(refresh_raw), client_id, email, scope, now + refresh_ttl),
        )
        await self._db.commit()
        return access_raw, refresh_raw

    async def get_access_token(self, raw: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM mcp_tokens WHERE token_hash = ? AND kind = 'access' AND revoked = 0",
            (token_hash(raw),),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        data = dict(row)
        if data["expires_at"] <= int(time.time()):
            return None
        return data

    async def rotate_refresh_token(
        self, refresh_raw: str, client_id: str | None, access_ttl: int, refresh_ttl: int
    ) -> tuple[str, str] | None:
        """Consume a refresh token, revoke the session's old tokens, issue a new pair."""
        cursor = await self._db.execute(
            "SELECT * FROM mcp_tokens WHERE token_hash = ? AND kind = 'refresh' AND revoked = 0",
            (token_hash(refresh_raw),),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        data = dict(row)
        if data["expires_at"] <= int(time.time()):
            return None
        if client_id is not None and data["client_id"] != client_id:
            return None
        # One active session per (client, user): revoke everything it held.
        await self._db.execute(
            "UPDATE mcp_tokens SET revoked = 1 WHERE client_id = ? AND email = ?",
            (data["client_id"], data["email"]),
        )
        await self._db.commit()
        return await self.issue_token_pair(
            data["client_id"], data["email"], data["scope"], access_ttl, refresh_ttl
        )

    # -- GymSuit users ---------------------------------------------------
    async def upsert_gymsuit_user(
        self,
        email: str,
        profile: dict,
        access_token_enc: str,
        refresh_token_enc: str,
    ) -> None:
        await self._db.execute(
            "INSERT INTO gymsuit_users (email, first_name, last_name, member_id, gym_id,"
            " gym_name, access_token_enc, refresh_token_enc, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(email) DO UPDATE SET first_name = excluded.first_name,"
            " last_name = excluded.last_name, member_id = excluded.member_id,"
            " gym_id = excluded.gym_id, gym_name = excluded.gym_name,"
            " access_token_enc = excluded.access_token_enc,"
            " refresh_token_enc = excluded.refresh_token_enc,"
            " updated_at = excluded.updated_at",
            (
                email,
                profile.get("firstName"),
                profile.get("lastName"),
                profile.get("memberId"),
                profile.get("gymId"),
                profile.get("gymName"),
                access_token_enc,
                refresh_token_enc,
                int(time.time()),
            ),
        )
        await self._db.commit()

    async def get_gymsuit_user(self, email: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM gymsuit_users WHERE email = ?", (email,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def update_gymsuit_tokens(self, email: str, access_token_enc: str, refresh_token_enc: str) -> None:
        await self._db.execute(
            "UPDATE gymsuit_users SET access_token_enc = ?, refresh_token_enc = ?,"
            " updated_at = ? WHERE email = ?",
            (access_token_enc, refresh_token_enc, int(time.time()), email),
        )
        await self._db.commit()
