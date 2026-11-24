"""Sign-in, second factor, passkey sign-in, re-authentication, sign-out."""

from __future__ import annotations

import logging
import sqlite3
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from doorman.auth import totp
from doorman.auth.passkeys import PasskeyError, UnknownPasskey, user_id_from_handle
from doorman.notify import EventType
from doorman.store import SESSION_DAYS
from doorman.web.deps import (
    account_limiter,
    check_csrf,
    clear_session_cookie,
    client_ip,
    core,
    ctx,
    form,
    hash_queue_full,
    login_limiter,
    off_loop,
    passkey_begin_limiter,
    rate_key,
    redirect,
    render,
    require_user,
    safe_next,
    set_session_cookie,
)

router = APIRouter()
log = logging.getLogger(__name__)

# One message for an unknown user, a wrong password and a locked account, so the answer doesn't
# reveal which usernames exist. The lockout rule is stated for everyone alike.
LOGIN_FAILED = "Wrong username or password. After 5 wrong tries, an account is paused for 15 minutes."


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
    if hash_queue_full():
        return render(
            request,
            "login.html",
            429,
            next=nxt,
            username=username,
            error="Sign-in is busy right now. Wait a moment and try again.",
        )
    if not login_limiter.hit(rate_key(ip)):
        return render(
            request,
            "login.html",
            429,
            next=nxt,
            username=username,
            error="Too many sign-in attempts. Wait a few minutes.",
        )
    u, err = await off_loop(c.store.check_login, username, str(data.get("password", "")), c.clock.now())
    if u is None:
        c.metrics.logins.labels(result="fail").inc()
        if err == "locked":
            c.store.audit(c.clock.now(), "user", username, "auth.locked", "", None, ip)
            c.notifier.publish(
                EventType.SECURITY, f"Account locked: {username}", f"Too many wrong passwords from {ip}."
            )
        elif err == "still_locked":
            c.store.audit(c.clock.now(), "user", username, "auth.locked_attempt", "", None, ip)
        message = "This account is disabled." if err == "disabled" else LOGIN_FAILED
        return render(request, "login.html", 401, next=nxt, username=username, error=message)
    if needs_second_factor(request, u):
        resp = redirect(request, f"/login/mfa?next={quote(nxt, safe='')}")
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
    if not account_limiter.hit(f"mfa:{u['id']}") or not u["totp_secret"]:
        c.store.delete_session(cx.session.id)
        resp = redirect(request, "/login", "Too many attempts. Sign in again.")
        clear_session_cookie(request, resp)
        return resp
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
    if not passkey_begin_limiter.hit(rate_key(client_ip(request))):
        return JSONResponse({"detail": "Too many attempts. Wait a few minutes."}, 429)
    allowed = None
    if cx.pending_user is not None:
        allowed = [bytes(p["public_key"]) for p in c.store.passkeys(cx.pending_user["id"])]
    # A passkey that is the whole sign-in must verify the person; after a password it's the
    # second factor and may skip that (e.g. a security key without a PIN).
    handle, options = c.passkeys.begin_authentication(allowed, require_uv=cx.pending_user is None)
    return JSONResponse({"handle": handle, "options": options})


def _verify_passkey(
    request: Request, body: dict[str, Any], expect_user: int | None, *, require_uv: bool = True
) -> sqlite3.Row:
    c = core(request)
    cred = body.get("credential") or {}
    cred_id = c.passkeys.credential_id_of(cred)
    pk = c.store.passkey_by_credential(cred_id)
    if pk is None:
        raise UnknownPasskey(cred_id)
    if expect_user is not None and pk["user_id"] != expect_user:
        raise PasskeyError("That passkey belongs to a different account.")
    a = c.passkeys.finish_authentication(
        str(body.get("handle", "")), cred, bytes(pk["public_key"]), pk["sign_count"], require_uv=require_uv
    )
    owner = user_id_from_handle(a.user_handle)
    if owner is not None and owner != pk["user_id"]:
        raise PasskeyError("This passkey belongs to a different account.")
    c.store.touch_passkey(pk["id"], a.sign_count, c.clock.now())
    u = c.store.user(pk["user_id"])
    if u is None or u["disabled"]:
        raise PasskeyError("This account is disabled.")
    return u


def _accepted(request: Request, user_id: int) -> dict[str, Any]:
    c = core(request)
    return c.passkeys.signal_accepted(user_id, [bytes(p["credential_id"]) for p in c.store.passkeys(user_id)])


def _passkey_failure(request: Request, e: PasskeyError, flow: str) -> JSONResponse:
    c = core(request)
    out: dict[str, Any] = {"detail": str(e)}
    if isinstance(e, UnknownPasskey):
        out["unknown"] = c.passkeys.signal_unknown(e.credential_id)
    log.warning("passkey %s failed from %s: %s", flow, client_ip(request), e)
    return JSONResponse(out, 400)


@router.post("/login/passkey/finish")
async def passkey_finish(request: Request) -> JSONResponse:
    c = core(request)
    cx = ctx(request)
    body = await request.json()
    nxt = safe_next(body.get("next"))
    expect = cx.pending_user["id"] if cx.pending_user is not None else None
    try:
        u = _verify_passkey(request, body, expect, require_uv=expect is None)
    except PasskeyError as e:
        c.metrics.logins.labels(result="fail").inc()
        return _passkey_failure(request, e, "sign-in")
    resp = JSONResponse({"redirect": nxt, "accepted": _accepted(request, u["id"])})
    if cx.pending_user is not None and cx.session is not None:
        c.store.complete_mfa(cx.session, u, c.clock.now())
        _logged_in(request, u, "password + passkey")
        set_session_cookie(request, resp, request.cookies[_cookie(request)], SESSION_DAYS[u["role"]] * 86400)
    else:
        # A user-verified passkey is itself two factors (the device, plus its PIN or biometric).
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
    if not account_limiter.hit(f"reauth:{u['id']}"):
        return redirect(request, "/logout-now")
    password = str(data.get("password", ""))
    ok_pw, _ = await off_loop(c.store.check_login, u["username"], password, c.clock.now())
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
        return _passkey_failure(request, e, "re-authentication")
    c.store.mark_reauth(cx.session, c.clock.now())
    return JSONResponse(
        {"redirect": safe_next(body.get("next"), "/admin"), "accepted": _accepted(request, cx.user["id"])}
    )


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
