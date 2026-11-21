"""argon2id password/PIN hashing sized for a Pi Zero (19 MiB, t=2: OWASP minimum)."""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
# Verified against when the username doesn't exist, so timing doesn't reveal valid names.
_DUMMY = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 10


def hash_secret(secret: str) -> str:
    return _hasher.hash(secret)


def verify_secret(stored: str | None, candidate: str) -> bool:
    try:
        return _hasher.verify(stored or _DUMMY, candidate) and stored is not None
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def needs_rehash(stored: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored)
    except InvalidHash:
        return True


def password_problem(password: str, username: str = "") -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if username and password.lower() == username.lower():
        return "The password can't be the username."
    if len(set(password)) < 4:
        return "That password is too repetitive."
    return None
