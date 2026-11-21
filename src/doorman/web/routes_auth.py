"""Sign-in, second factor, passkey sign-in, re-authentication, sign-out."""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from doorman.auth import totp
from doorman.auth.passkeys import PasskeyError, user_id_from_handle
from doorman.notify import EventType
from doorman.store import SESSION_DAYS
from doorman.web.deps import (
    check_csrf,
    clear_session_cookie,
    client_ip,
    core,
    ctx,
    form,
    login_limiter,
    redirect,
    render,
    require_user,
    safe_next,
    set_session_cookie,
)

router = APIRouter()


def needs_second_factor(request: Request, u: sqlite3.Row) -> bool:
    c = core(request)
    return bool(u["totp_secret"]) or (u["role"] == "admin" and bool(c.store.passkeys(u["id"])))


def _start_session(request: Request, u: sqlite3.Row, response: Response, *, pending: bool = False) -> None:
    c = core(request)
    now = c.clock.now()
    token, s = c.store.create_session(
        now,
        user=u,
        mfa_pending=pending,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )
    max_age = int((s.expires_at - now).total_seconds())
    set_session_cookie(request, response, token, max_age)
    if not pending:
        _logged_in(request, u, "password")


def _logged_in(request: Request, u: sqlite3.Row, method: str) -> None:
    c = core(request)
    now = c.clock.now()
    ip = client_ip(request)
    c.store.record_login(u["id"], now)
    c.store.audit(now, "user", u["username"], "auth.login", {"method": method}, u["id"], ip)
    c.metrics.logins.labels(result="ok").inc()
    if u["role"] == "admin":
        c.notifier.publish(
            EventType.SECURITY, f"Admin sign-in: {u['username']}", f"From {ip} using {method}."
        )


@router.get("/login")
async def login_page(request: Request, next: str = "/") -> Response:
    if ctx(request).principal is not None:
        return redirect(request, safe_next(next))
    return render(request, "login.html", next=safe_next(next))


@router.post("/login")
async def login(request: Request) -> Response:
    c = core(request)
    data = await form(request)
    nxt = safe_next(data.get("next"))
    ip = client_ip(request)
    username = str(data.get("username", "")).strip()
    if not login_limiter.hit(f"ip:{ip}"):
        return render(
            request,
            "login.html",
            429,
            next=nxt,
            username=username,
            error="Too many sign-in attempts. Wait a few minutes.",
        )
    u, err = c.store.check_login(username, str(data.get("password", "")), c.clock.now())
    if u is None:
        c.metrics.logins.labels(result="fail").inc()
        if err == "locked":
            c.store.audit(c.clock.now(), "user", username, "auth.locked", "", None, ip)
            c.notifier.publish(
                EventType.SECURITY, f"Account locked: {username}", f"Too many wrong passwords from {ip}."
            )
            err = "Too many failed attempts. Try again later."
        return render(request, "login.html", 401, next=nxt, username=username, error=err)
    if needs_second_factor(request, u):
        resp = redirect(request, f"/login/mfa?next={nxt}")
        _start_session(request, u, resp, pending=True)
        return resp
    resp = redirect(request, nxt)
    _start_session(request, u, resp)
    return resp


@router.get("/login/mfa")
async def mfa_page(request: Request, next: str = "/") -> Response:
    cx = ctx(request)
    if cx.pending_user is None:
        return redirect(request, "/login")
    c = core(request)
    return render(
        request,
        "login_mfa.html",
        next=safe_next(next),
        has_totp=bool(cx.pending_user["totp_secret"]),
        has_passkey=bool(c.store.passkeys(cx.pending_user["id"])),
    )


@router.post("/login/mfa")
async def mfa_submit(request: Request) -> Response:
    cx = ctx(request)
    c = core(request)
    data = await form(request)
    nxt = safe_next(data.get("next"))
    u = cx.pending_user
    if u is None or cx.session is None:
        return redirect(request, "/login")
    check_csrf(request, data.get("csrf"))
    if not login_limiter.hit(f"mfa:{u['id']}") or not u["totp_secret"]:
        return redirect(request, "/login", "Too many attempts. Sign in again.")
    step = totp.verify(u["totp_secret"], str(data.get("code", "")), u["totp_last_step"])
    if step is None:
        return render(
            request,
            "login_mfa.html",
            401,
            next=nxt,
            has_totp=True,
            has_passkey=bool(c.store.passkeys(u["id"])),
            error="That code didn't match. Try the newest one.",
        )
    c.store.update_user(u["id"], totp_last_step=step)
    c.store.complete_mfa(cx.session, u, c.clock.now())
    _logged_in(request, u, "password + authenticator code")
    resp = redirect(request, nxt)
    set_session_cookie(request, resp, request.cookies[_cookie(request)], SESSION_DAYS[u["role"]] * 86400)
    return resp


def _cookie(request: Request) -> str:
    from doorman.web.deps import cookie_name

    return cookie_name(request)


# ---- passkey sign-in (JSON endpoints used by static/app.js) -----------------------------------


@router.post("/login/passkey/begin")
async def passkey_begin(request: Request) -> JSONResponse:
    c = core(request)
    cx = ctx(request)
    if not login_limiter.hit(f"ip:{client_ip(request)}"):
        return JSONResponse({"detail": "Too many attempts. Wait a few minutes."}, 429)
    allowed = None
    if cx.pending_user is not None:
        allowed = [bytes(p["public_key"]) for p in c.store.passkeys(cx.pending_user["id"])]
    handle, options = c.passkeys.begin_authentication(allowed)
    return JSONResponse({"handle": handle, "options": options})


def _verify_passkey(request: Request, body: dict[str, Any], expect_user: int | None) -> sqlite3.Row:
    c = core(request)
    cred = body.get("credential") or {}
    cred_id = c.passkeys.credential_id_of(cred)
    pk = c.store.passkey_by_credential(cred_id)
    if pk is None or (expect_user is not None and pk["user_id"] != expect_user):
        raise PasskeyError("This passkey isn't registered here.")
    a = c.passkeys.finish_authentication(
        str(body.get("handle", "")), cred, bytes(pk["public_key"]), pk["sign_count"]
    )
    owner = user_id_from_handle(a.user_handle)
    if owner is not None and owner != pk["user_id"]:
        raise PasskeyError("This passkey belongs to a different account.")
    c.store.touch_passkey(pk["id"], a.sign_count, c.clock.now())
    u = c.store.user(pk["user_id"])
    if u is None or u["disabled"]:
        raise PasskeyError("This account is disabled.")
    return u


@router.post("/login/passkey/finish")
async def passkey_finish(request: Request) -> JSONResponse:
    c = core(request)
    cx = ctx(request)
    body = await request.json()
    nxt = safe_next(body.get("next"))
    expect = cx.pending_user["id"] if cx.pending_user is not None else None
    try:
        u = _verify_passkey(request, body, expect)
    except PasskeyError as e:
        c.metrics.logins.labels(result="fail").inc()
        return JSONResponse({"detail": str(e)}, 400)
    resp = JSONResponse({"redirect": nxt})
    if cx.pending_user is not None and cx.session is not None:
        c.store.complete_mfa(cx.session, u, c.clock.now())
        _logged_in(request, u, "password + passkey")
        set_session_cookie(request, resp, request.cookies[_cookie(request)], SESSION_DAYS[u["role"]] * 86400)
    else:
        if u["totp_secret"] and u["role"] != "admin":
            pass  # a passkey is itself a strong, phishing-resistant factor
        token, s = c.store.create_session(
            c.clock.now(), user=u, ip=client_ip(request), user_agent=request.headers.get("user-agent", "")
        )
        set_session_cookie(request, resp, token, int((s.expires_at - c.clock.now()).total_seconds()))
        _logged_in(request, u, "passkey")
    return resp


# ---- re-authentication before sensitive admin changes ---------------------------------------


@router.get("/reauth")
async def reauth_page(request: Request, next: str = "/admin") -> Response:
    cx = require_user(request)
    assert cx.user is not None
    c = core(request)
    return render(
        request,
        "reauth.html",
        next=safe_next(next, "/admin"),
        has_totp=bool(cx.user["totp_secret"]),
        has_passkey=bool(c.store.passkeys(cx.user["id"])),
    )


@router.post("/reauth")
async def reauth(request: Request) -> Response:
    cx = require_user(request)
    c = core(request)
    data = await form(request)
    check_csrf(request, data.get("csrf"))
    u = cx.user
    assert u is not None and cx.session is not None
    nxt = safe_next(data.get("next"), "/admin")
    has_pk = bool(c.store.passkeys(u["id"]))
    if not login_limiter.hit(f"reauth:{u['id']}"):
        return redirect(request, "/logout-now")
    ok_pw, _ = c.store.check_login(u["username"], str(data.get("password", "")), c.clock.now())
    ok = ok_pw is not None
    if ok and u["totp_secret"]:
        step = totp.verify(u["totp_secret"], str(data.get("code", "")), u["totp_last_step"])
        ok = step is not None
        if step is not None:
            c.store.update_user(u["id"], totp_last_step=step)
    if not ok:
        return render(
            request,
            "reauth.html",
            401,
            next=nxt,
            has_totp=bool(u["totp_secret"]),
            has_passkey=has_pk,
            error="That didn't match.",
        )
    c.store.mark_reauth(cx.session, c.clock.now())
    return redirect(request, nxt)


@router.post("/reauth/passkey/begin")
async def reauth_passkey_begin(request: Request) -> JSONResponse:
    cx = require_user(request)
    check_csrf(request, None)
    c = core(request)
    assert cx.user is not None
    allowed = [bytes(p["public_key"]) for p in c.store.passkeys(cx.user["id"])]
    handle, options = c.passkeys.begin_authentication(allowed)
    return JSONResponse({"handle": handle, "options": options})


@router.post("/reauth/passkey/finish")
async def reauth_passkey_finish(request: Request) -> JSONResponse:
    cx = require_user(request)
    check_csrf(request, None)
    c = core(request)
    assert cx.user is not None and cx.session is not None
    body = await request.json()
    try:
        _verify_passkey(request, body, cx.user["id"])
    except PasskeyError as e:
        return JSONResponse({"detail": str(e)}, 400)
    c.store.mark_reauth(cx.session, c.clock.now())
    return JSONResponse({"redirect": safe_next(body.get("next"), "/admin")})


@router.post("/logout")
async def logout(request: Request) -> Response:
    cx = ctx(request)
    data = await form(request)
    if cx.session is not None:
        check_csrf(request, data.get("csrf"))
        core(request).store.delete_session(cx.session.id)
    resp = redirect(request, "/login", "Signed out.")
    clear_session_cookie(request, resp)
    return resp


@router.get("/logout-now")
async def logout_now(request: Request) -> Response:
    """Used after too many failed re-auth attempts: drop the session."""
    cx = ctx(request)
    if cx.session is not None:
        core(request).store.delete_session(cx.session.id)
    resp = redirect(request, "/login", "Signed out after too many attempts.")
    clear_session_cookie(request, resp)
    return resp
