"""Request context, auth guards, CSRF, rendering helpers."""

from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import quote, urlsplit

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from doorman.access import Principal
from doorman.auth import tokens
from doorman.auth.ratelimit import RateLimiter
from doorman.core import Core
from doorman.store import Session

REAUTH_WINDOW = timedelta(minutes=10)
FLASH_COOKIE = "doorman_flash"

login_limiter = RateLimiter(limit=10, window_s=300)
pin_limiter = RateLimiter(limit=10, window_s=300)
# Starting a passkey request proves nothing and costs one in-memory challenge; the sign-in page
# starts one on every load (for autofill), so it gets its own, roomier budget.
passkey_begin_limiter = RateLimiter(limit=60, window_s=300)


class Redirect(Exception):
    def __init__(self, url: str, flash: str = "") -> None:
        self.url = url
        self.flash = flash


class Forbidden(Exception):
    def __init__(self, message: str = "You don't have access to that page.") -> None:
        self.message = message


@dataclass
class Ctx:
    session: Session | None = None
    user: sqlite3.Row | None = None
    link: sqlite3.Row | None = None
    principal: Principal | None = None
    pending_user: sqlite3.Row | None = None  # password OK, second factor still required

    @property
    def is_admin(self) -> bool:
        return self.principal is not None and self.principal.is_admin

    @property
    def is_guest(self) -> bool:
        return self.principal is not None and self.principal.kind == "link"


def core(request: Request) -> Core:
    c: Core = request.app.state.core
    return c


def cookie_name(request: Request) -> str:
    return "__Host-doorman" if core(request).cfg.server.cookie_secure else "doorman_session"


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    trusted = core(request).cfg.server.trusted_proxies
    xff = request.headers.get("x-forwarded-for", "")
    if peer in trusted and xff:
        candidate = xff.split(",")[-1].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return peer


def load_ctx(request: Request) -> Ctx:
    c = core(request)
    token = request.cookies.get(cookie_name(request))
    if not token:
        return Ctx()
    now = c.clock.now()
    s = c.store.session(token, now)
    if s is None:
        return Ctx()
    if s.user_id is not None:
        u = c.store.user(s.user_id)
        if u is None or u["disabled"]:
            c.store.delete_session(s.id)
            return Ctx()
        c.store.touch_session(s, now, u["role"])
        if s.mfa_pending:
            return Ctx(session=s, pending_user=u)
        return Ctx(session=s, user=u, principal=c.principal_for_user(u))
    if s.link_id is not None:
        link = c.store.link(s.link_id)
        if link is None or link["revoked"] or link["user_disabled"]:
            c.store.delete_session(s.id)
            return Ctx()
        return Ctx(session=s, link=link, principal=c.principal_for_link(link, s))
    return Ctx()


def ctx(request: Request) -> Ctx:
    cx: Ctx = request.state.ctx
    return cx


def _next(request: Request) -> str:
    path = request.url.path
    if request.url.query:
        path += "?" + request.url.query
    return quote(path, safe="")


def require_login(request: Request) -> Ctx:
    cx = ctx(request)
    if cx.principal is None:
        if cx.pending_user is not None:
            raise Redirect("/login/mfa")
        raise Redirect(f"/login?next={_next(request)}")
    path = request.url.path
    # Admins must have a passkey or authenticator app before doing anything else.
    if (
        cx.user is not None
        and cx.user["role"] == "admin"
        and path not in ("/profile", "/logout")
        and not path.startswith("/profile/")
        and not core(request).store.has_second_factor(cx.user)
    ):
        raise Redirect("/profile?setup=mfa", "Admins need a passkey or an authenticator app. Add one below.")
    return cx


def require_user(request: Request) -> Ctx:
    cx = require_login(request)
    if cx.user is None:
        raise Redirect("/")
    return cx


def require_admin(request: Request, recent: bool = False) -> Ctx:
    cx = require_user(request)
    if not cx.is_admin:
        raise Forbidden()
    if recent:
        assert cx.session is not None
        reauth = cx.session.reauth_at
        if reauth is None or core(request).clock.now() - reauth > REAUTH_WINDOW:
            back = request.headers.get("referer", "")
            target = urlsplit(back).path if back else request.url.path
            raise Redirect(
                f"/reauth?next={quote(target or '/admin', safe='')}", "Confirm it's you to change settings."
            )
    return cx


def safe_next(value: str | None, default: str = "/") -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return default
    return value


async def form(request: Request) -> dict[str, Any]:
    data = await request.form()
    out: dict[str, Any] = {}
    for k in data:
        values = data.getlist(k)
        out[k] = values if len(values) > 1 or k.endswith("[]") else values[0]
    return out


def check_csrf(request: Request, submitted: str | None) -> None:
    cx = ctx(request)
    expected = cx.session.csrf if cx.session else None
    submitted = submitted or request.headers.get("x-csrf-token")
    if not expected or not submitted or not tokens.same(expected, str(submitted)):
        raise Forbidden("Your session expired or the form was stale. Reload the page and try again.")


def origin_ok(request: Request) -> bool:
    """Reject cross-site form posts (defense in depth on top of SameSite cookies + CSRF tokens)."""
    expected = core(request).cfg.server.public_origin.rstrip("/")
    origin = request.headers.get("origin")
    if origin:
        return origin.rstrip("/") == expected
    referer = request.headers.get("referer")
    if referer:
        parts = urlsplit(referer)
        return f"{parts.scheme}://{parts.netloc}" == expected
    return True  # non-browser clients; protected by CSRF tokens


def set_session_cookie(request: Request, response: Response, token: str, max_age: int) -> None:
    response.set_cookie(
        cookie_name(request),
        token,
        max_age=max_age,
        path="/",
        secure=core(request).cfg.server.cookie_secure,
        httponly=True,
        samesite="lax",
    )


def clear_session_cookie(request: Request, response: Response) -> None:
    response.delete_cookie(cookie_name(request), path="/", secure=core(request).cfg.server.cookie_secure)


def redirect(request: Request, url: str, flash: str = "") -> RedirectResponse:
    resp = RedirectResponse(url, status_code=303)
    if flash:
        resp.set_cookie(
            FLASH_COOKIE,
            quote(flash),
            max_age=60,
            path="/",
            httponly=True,
            samesite="lax",
            secure=core(request).cfg.server.cookie_secure,
        )
    return resp


def render(request: Request, name: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    templates: Jinja2Templates = request.app.state.templates
    from urllib.parse import unquote

    flash = unquote(request.cookies.get(FLASH_COOKIE, ""))
    cx = ctx(request)
    c = core(request)
    resp = templates.TemplateResponse(
        request,
        name,
        {
            "ctx": cx,
            "csrf": cx.session.csrf if cx.session else "",
            "flash": flash,
            "now": c.clock.now(),
            "dev_mode": c.cfg.server.dev_mode,
            **context,
        },
        status_code=status_code,
    )
    if flash:
        resp.delete_cookie(FLASH_COOKIE, path="/", secure=c.cfg.server.cookie_secure)
    return resp
