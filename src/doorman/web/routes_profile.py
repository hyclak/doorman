"""The signed-in user's own security and notification settings."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from doorman import notify_urls
from doorman.auth import passwords, totp
from doorman.auth.passkeys import PasskeyError
from doorman.notify import ADMIN_ONLY_EVENTS, ALERT_ROLES, DEFAULT_EVENTS, EventType, events_for_role
from doorman.web.deps import (
    Ctx,
    Forbidden,
    check_csrf,
    client_ip,
    core,
    form,
    notify_test_limiter,
    off_loop,
    redirect,
    render,
    require_recent,
    require_user,
)

router = APIRouter(prefix="/profile")

# Pending TOTP enrolment secrets, keyed by session id: (secret, monotonic time started).
_pending_totp: dict[str, tuple[str, float]] = {}
PENDING_TOTP_TTL_S = 900
FACTOR_REAUTH = "Confirm it's you to change how you sign in."


def _recent(request: Request, cx: Ctx) -> None:
    """Adding or removing a sign-in method needs a fresh sign-in, so a stolen or borrowed session
    can't plant its own passkey (which would survive a password change)."""
    require_recent(request, cx, FACTOR_REAUTH, "/profile")


def _pending_secret(session_id: str) -> str | None:
    now = time.monotonic()
    for k in [k for k, (_, t) in _pending_totp.items() if now - t > PENDING_TOTP_TTL_S]:
        _pending_totp.pop(k, None)
    entry = _pending_totp.get(session_id)
    return entry[0] if entry else None


def _factor_alert(request: Request, cx: Ctx, what: str) -> None:
    c = core(request)
    assert cx.user is not None
    c.notifier.publish(EventType.SECURITY, f"{what}: {cx.user['username']}", f"From {client_ip(request)}.")


def _profile_context(request: Request) -> dict[str, Any]:
    cx = require_user(request)
    c = core(request)
    u = cx.user
    assert u is not None and cx.session is not None
    prefs = c.store.notify_prefs(u["id"])
    events = set(prefs["events"].split(",")) - {""} if prefs else DEFAULT_EVENTS[u["role"]]
    if u["role"] != "admin":
        events -= ADMIN_ONLY_EVENTS
    return {
        "u": u,
        "passkeys": c.store.passkeys(u["id"]),
        # Lets the browser / password manager hide passkeys doorman no longer accepts (Signal API).
        "passkey_accepted": c.passkeys.signal_accepted(
            u["id"], [bytes(p["credential_id"]) for p in c.store.passkeys(u["id"])]
        ),
        "sessions": c.store.user_sessions(u["id"]),
        "current_session": cx.session.id,
        "event_info": events_for_role(u["role"]),
        "gets_alerts": u["role"] in ALERT_ROLES,
        "events": events,
        "use_shared": bool(prefs["use_shared"]) if prefs else True,
        "apprise_url": prefs["apprise_url"] if prefs else "",
        "shared_available": bool(c.cfg.shared_discord_webhook),
        "needs_mfa": u["role"] == "admin" and not c.store.has_second_factor(u),
    }


@router.get("")
async def profile(request: Request) -> Response:
    return render(request, "profile/index.html", **_profile_context(request))


@router.post("/password")
async def change_password(request: Request) -> Response:
    cx = require_user(request)
    c = core(request)
    data = await form(request)
    check_csrf(request, data.get("csrf"))
    u = cx.user
    assert u is not None and cx.session is not None
    if not await off_loop(passwords.verify_secret, u["password_hash"], str(data.get("current", ""))):
        return redirect(request, "/profile", "Your current password didn't match.")
    if data.get("new") != data.get("confirm"):
        return redirect(request, "/profile", "The new passwords don't match.")
    try:
        await off_loop(c.store.set_password, u["id"], str(data.get("new", "")))
    except ValueError as e:
        return redirect(request, "/profile", str(e))
    c.store.delete_user_sessions(u["id"], except_id=cx.session.id)
    c.store.audit(c.clock.now(), "user", u["username"], "auth.password_changed", "", u["id"])
    return redirect(request, "/profile", "Password changed. Other devices were signed out.")


# ---- authenticator app (TOTP) ----------------------------------------------------------------


@router.post("/totp/begin")
async def totp_begin(request: Request) -> Response:
    cx = require_user(request)
    data = await form(request)
    check_csrf(request, data.get("csrf"))
    assert cx.user is not None and cx.session is not None
    _recent(request, cx)
    secret = totp.new_secret()
    _pending_secret(cx.session.id)  # prunes stale entries
    _pending_totp[cx.session.id] = (secret, time.monotonic())
    uri = totp.provisioning_uri(secret, cx.user["username"], "doorman")
    return render(request, "profile/totp.html", secret=secret, qr=totp.qr_svg(uri))


@router.post("/totp/confirm")
async def totp_confirm(request: Request) -> Response:
    cx = require_user(request)
    c = core(request)
    data = await form(request)
    check_csrf(request, data.get("csrf"))
    assert cx.user is not None and cx.session is not None
    secret = _pending_secret(cx.session.id)
    if not secret:
        return redirect(request, "/profile", "Setup expired. Start again.")
    step = totp.verify(secret, str(data.get("code", "")), 0)
    if step is None:
        uri = totp.provisioning_uri(secret, cx.user["username"], "doorman")
        return render(
            request,
            "profile/totp.html",
            400,
            secret=secret,
            qr=totp.qr_svg(uri),
            error="That code didn't match. Check the time on your phone and try the newest code.",
        )
    _pending_totp.pop(cx.session.id, None)
    c.store.update_user(cx.user["id"], totp_secret=secret, totp_last_step=step)
    c.store.audit(c.clock.now(), "user", cx.user["username"], "auth.totp_enabled", "", cx.user["id"])
    _factor_alert(request, cx, "Authenticator app added")
    return redirect(request, "/profile", "Authenticator app added. You'll enter a code when you sign in.")


@router.post("/totp/disable")
async def totp_disable(request: Request) -> Response:
    cx = require_user(request)
    c = core(request)
    data = await form(request)
    check_csrf(request, data.get("csrf"))
    u = cx.user
    assert u is not None
    if u["role"] == "admin" and not c.store.passkeys(u["id"]):
        return redirect(
            request, "/profile", "Admins need a passkey or authenticator app. Add a passkey first."
        )
    if not await off_loop(passwords.verify_secret, u["password_hash"], str(data.get("password", ""))):
        return redirect(request, "/profile", "Password didn't match.")
    c.store.update_user(u["id"], totp_secret=None, totp_last_step=0)
    c.store.audit(c.clock.now(), "user", u["username"], "auth.totp_disabled", "", u["id"])
    return redirect(request, "/profile", "Authenticator app removed.")


# ---- passkeys ---------------------------------------------------------------------------------


@router.post("/passkeys/begin")
async def passkey_begin(request: Request) -> JSONResponse:
    cx = require_user(request)
    check_csrf(request, None)
    _recent(request, cx)
    c = core(request)
    u = cx.user
    assert u is not None
    existing = [bytes(p["public_key"]) for p in c.store.passkeys(u["id"])]
    handle, options = c.passkeys.begin_registration(u["id"], u["username"], u["display_name"], existing)
    return JSONResponse({"handle": handle, "options": options})


@router.post("/passkeys/finish")
async def passkey_finish(request: Request) -> JSONResponse:
    cx = require_user(request)
    check_csrf(request, None)
    _recent(request, cx)
    c = core(request)
    u = cx.user
    assert u is not None
    body = await request.json()
    try:
        new = c.passkeys.finish_registration(
            str(body.get("handle", "")), body.get("credential") or {}, u["id"]
        )
    except PasskeyError as e:
        return JSONResponse({"detail": str(e)}, 400)
    if c.store.passkey_by_credential(new.credential_id):
        return JSONResponse({"detail": "That passkey is already registered."}, 409)
    # The passkeys.public_key column holds fido2's AttestedCredentialData (id + COSE key).
    c.store.add_passkey(
        u["id"],
        new.credential_id,
        new.credential_data,
        new.sign_count,
        str(body.get("name") or "Passkey"),
        c.clock.now(),
    )
    c.store.audit(c.clock.now(), "user", u["username"], "auth.passkey_added", "", u["id"])
    _factor_alert(request, cx, "Passkey added")
    return JSONResponse({"redirect": "/profile"})


@router.post("/passkeys/{passkey_id}/delete")
async def passkey_delete(request: Request, passkey_id: int) -> Response:
    cx = require_user(request)
    c = core(request)
    data = await form(request)
    check_csrf(request, data.get("csrf"))
    _recent(request, cx)
    u = cx.user
    assert u is not None
    if u["role"] == "admin" and not u["totp_secret"] and len(c.store.passkeys(u["id"])) <= 1:
        return redirect(
            request, "/profile", "That's your only second factor. Add another before removing it."
        )
    c.store.delete_passkey(passkey_id, u["id"])
    c.store.audit(c.clock.now(), "user", u["username"], "auth.passkey_removed", "", u["id"])
    return redirect(request, "/profile", "Passkey removed.")


# ---- sessions ---------------------------------------------------------------------------------


@router.post("/sessions/{session_id}/revoke")
async def revoke_session(request: Request, session_id: str) -> Response:
    cx = require_user(request)
    c = core(request)
    data = await form(request)
    check_csrf(request, data.get("csrf"))
    assert cx.user is not None
    if any(s.id == session_id for s in c.store.user_sessions(cx.user["id"])):
        c.store.delete_session(session_id)
    return redirect(request, "/profile", "Device signed out.")


# ---- notifications ----------------------------------------------------------------------------


@router.post("/notifications")
async def save_notifications(request: Request) -> Response:
    cx = require_user(request)
    c = core(request)
    data = await form(request)
    check_csrf(request, data.get("csrf"))
    u = cx.user
    assert u is not None
    if u["role"] not in ALERT_ROLES:
        raise Forbidden("Alerts are for Admin and Household accounts.")
    raw = data.get("events", [])
    allowed = {e.value for e in events_for_role(u["role"])}
    events = {e for e in ([raw] if isinstance(raw, str) else raw) if e in allowed}
    try:
        c.store.update_user(u["id"], discord_user_id=str(data.get("discord_user_id", "")))
        c.store.set_notify_prefs(
            u["id"], events, data.get("use_shared") == "on", str(data.get("apprise_url", ""))
        )
    except ValueError as e:
        return redirect(request, "/profile#notifications", str(e))
    return redirect(request, "/profile#notifications", "Notification settings saved.")


@router.post("/notifications/test")
async def test_notification(request: Request) -> Response:
    cx = require_user(request)
    c = core(request)
    data = await form(request)
    check_csrf(request, data.get("csrf"))
    u = cx.user
    assert u is not None
    if u["role"] not in ALERT_ROLES:
        raise Forbidden("Alerts are for Admin and Household accounts.")
    if not notify_test_limiter.hit(f"user:{u['id']}"):
        return redirect(request, "/profile#notifications", "Too many tests. Wait a few minutes.")
    prefs = c.store.notify_prefs(u["id"])
    targets = []
    # Apprise refuses to send an empty body, so every test carries a message.
    message = "Test notification from doorman."
    if (prefs is None or prefs["use_shared"]) and c.cfg.shared_discord_webhook:
        body = f"{message}\n<@{u['discord_user_id']}>" if u["discord_user_id"] else message
        targets.append((c.cfg.shared_discord_webhook, body))
    if prefs and prefs["apprise_url"]:
        if problem := notify_urls.problem(prefs["apprise_url"]):
            return redirect(request, "/profile#notifications", problem)
        targets.append((prefs["apprise_url"], message))
    if not targets:
        return redirect(request, "/profile#notifications", "No destination set up yet.")
    results = [
        await c.notifier.send_test(url, f"doorman test for {u['username']}", body) for url, body in targets
    ]
    msg = "Test sent." if all(results) else "The test couldn't be delivered. Check the URL."
    return redirect(request, "/profile#notifications", msg)
