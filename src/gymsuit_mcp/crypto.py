"""Small crypto helpers: hashing for stored tokens, Fernet for secrets.

Raw tokens are never stored. What lands in SQLite is a SHA-256 hash (for
MCP access/refresh tokens and OAuth codes) or a Fernet ciphertext (for the
GymSuit tokens we hold on each user's behalf).
"""

from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.fernet import Fernet, InvalidToken


def token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def _fernet(secret: str) -> Fernet:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(secret: str, plaintext: str) -> str:
    return _fernet(secret).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(secret: str, ciphertext: str) -> str:
    try:
        return _fernet(secret).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("stored token could not be decrypted") from exc


def pkce_challenge(verifier: str) -> str:
    """S256 code challenge: base64url(sha256(verifier)) without padding."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
