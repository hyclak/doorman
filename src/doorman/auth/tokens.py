"""Random tokens. Only SHA-256 digests are stored, so a leaked database can't be replayed."""

from __future__ import annotations

import hashlib
import hmac
import secrets


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_pin(length: int = 6) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(length))


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
