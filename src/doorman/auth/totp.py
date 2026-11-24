"""TOTP (authenticator app) codes with replay protection."""

from __future__ import annotations

import time

import pyotp
import segno


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str, issuer: str = "doorman") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def qr_svg(uri: str) -> str:
    """Inline SVG QR code (no external services)."""
    # Plain black on white: QR scanners need the contrast in dark mode too, and Debian's segno
    # rejects CSS keywords such as "currentColor".
    return segno.make(uri, error="m").svg_inline(scale=5, dark="#000000", light="#ffffff")


def verify(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Return the matched time step if ``code`` is valid and newer than ``last_step``."""
    code = "".join(c for c in code if c.isdigit())
    if len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now = time.time() if now is None else now
    current = int(now // totp.interval)
    for step in (current - 1, current, current + 1):
        if step <= last_step:
            continue
        if pyotp.utils.strings_equal(totp.generate_otp(step), code):
            return step
    return None
