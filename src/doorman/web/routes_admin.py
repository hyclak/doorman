"""Admin pages. Viewing needs an admin session; every change also needs a recent re-auth."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import Response

from doorman.door import DoorError
from doorman.notify import EventType
from doorman.schedules import DAY_NAMES
from doorman.settings import SETTINGS
from doorman.store import ROLE_HELP, ROLES
from doorman.web.deps import check_csrf, client_ip, core, form, off_loop, redirect, render, require_admin
from doorman.web.forms import FormError, parse_window

router = APIRouter(prefix="/admin")


async def _mutate(request: Request) -> tuple[Any, dict[str, Any]]:
    cx = require_admin(request, recent=True)
    data = await form(request)
    check_csrf(request, data.get("csrf"))
    return cx, data


def _audit(request: Request, cx: Any, action: str, detail: Any = "") -> None:
    c = core(request)
    c.store.audit(
        c.clock.now(), "user", cx.user["username"], action, detail, cx.user["id"], client_ip(request)
    )


@router.get("")
async def admin_home(request: Request) -> Response:
    require_admin(request)
    return redirect(request, "/admin/users")


# ---- users ------------------------------------------------------------------------------------


@router.get("/users")
async def users(request: Request) -> Response:
    require_admin(request)
    return render(
        request, "admin/users.html", users=core(request).store.users(), roles=ROLES, role_help=ROLE_HELP
    )


@router.post("/users")
async def create_user(request: Request) -> Response:
    cx, data = await _mutate(request)
    c = core(request)
    try:
        uid = await off_loop(
            c.store.create_user,
            str(data.get("username", "")),
            str(data.get("password", "")),
            str(data.get("role", "")),
            c.clock.now(),
            str(data.get("display_name", "")),
        )
    except ValueError as e:
        return redirect(request, "/admin/users", str(e))
    _audit(request, cx, "admin.user_created", {"username": data.get("username"), "role": data.get("role")})
    return redirect(request, f"/admin/users/{uid}", "User created.")


@router.get("/users/{uid}")
async def user_detail(request: Request, uid: int) -> Response:
    require_admin(request)
    c = core(request)
    u = c.store.user(uid)
    if u is None:
        return redirect(request, "/admin/users", "No such user.")
    return render(
        request,
        "admin/user.html",
        u=u,
        roles=ROLES,
        role_help=ROLE_HELP,
        windows=c.store.windows("user", uid),
        sessions=c.store.user_sessions(uid),
        passkeys=c.store.passkeys(uid),
        day_names=DAY_NAMES,
    )


@router.post("/users/{uid}")
async def update_user(request: Request, uid: int) -> Response:
    cx, data = await _mutate(request)
    c = core(request)
    u = c.store.user(uid)
    if u is None:
        return redirect(request, "/admin/users")
    role = str(data.get("role", u["role"]))
    disabled = data.get("disabled") == "on"
    if u["role"] == "admin" and (role != "admin" or disabled) and c.store.admin_count(exclude=uid) == 0:
        return redirect(request, f"/admin/users/{uid}", "You can't remove the last admin.")
    try:
        c.store.update_user(
            uid,
            display_name=str(data.get("display_name", "")).strip(),
            role=role,
            disabled=int(disabled),
            discord_user_id=str(data.get("discord_user_id", "")),
        )
    except ValueError as e:
        return redirect(request, f"/admin/users/{uid}", str(e))
    if disabled or role != u["role"]:
        c.store.delete_user_sessions(uid)
    if role in ("admin", "household") and u["role"] not in ("admin", "household"):
        # Guest links are only for time-limited accounts; once always-allowed, they'd grant
        # anyone holding one unlimited access.
        c.store.revoke_user_links(uid)
    _audit(request, cx, "admin.user_updated", {"user": u["username"], "role": role, "disabled": disabled})
    return redirect(request, f"/admin/users/{uid}", "Saved.")


@router.post("/users/{uid}/password")
async def reset_password(request: Request, uid: int) -> Response:
    cx, data = await _mutate(request)
    c = core(request)
    try:
        await off_loop(c.store.set_password, uid, str(data.get("password", "")))
    except ValueError as e:
        return redirect(request, f"/admin/users/{uid}", str(e))
    # Sign out their devices; when resetting your own, keep only this one.
    c.store.delete_user_sessions(uid, except_id=cx.session.id if uid == cx.user["id"] else None)
    _audit(request, cx, "admin.password_reset", {"user_id": uid})
    return redirect(request, f"/admin/users/{uid}", "Password set. Their devices were signed out.")


@router.post("/users/{uid}/reset-mfa")
async def reset_mfa(request: Request, uid: int) -> Response:
    cx, _ = await _mutate(request)
    c = core(request)
    c.store.update_user(uid, totp_secret=None, totp_last_step=0)
    for pk in c.store.passkeys(uid):
        c.store.delete_passkey(pk["id"], uid)
    c.store.delete_user_sessions(uid)
    _audit(request, cx, "admin.mfa_reset", {"user_id": uid})
    return redirect(request, f"/admin/users/{uid}", "Passkeys and authenticator app removed.")


@router.post("/users/{uid}/sessions/revoke")
async def revoke_user_sessions(request: Request, uid: int) -> Response:
    cx, _ = await _mutate(request)
    core(request).store.delete_user_sessions(uid, except_id=cx.session.id)
    _audit(request, cx, "admin.sessions_revoked", {"user_id": uid})
    return redirect(request, f"/admin/users/{uid}", "Signed out everywhere.")


@router.post("/users/{uid}/delete")
async def delete_user(request: Request, uid: int) -> Response:
    cx, _ = await _mutate(request)
    c = core(request)
    u = c.store.user(uid)
    if u is None:
        return redirect(request, "/admin/users")
    if uid == cx.user["id"]:
        return redirect(request, f"/admin/users/{uid}", "You can't delete yourself.")
    if u["role"] == "admin" and c.store.admin_count(exclude=uid) == 0:
        return redirect(request, f"/admin/users/{uid}", "You can't delete the last admin.")
    c.store.delete_user(uid)
    _audit(request, cx, "admin.user_deleted", {"user": u["username"]})
    return redirect(request, "/admin/users", f"Deleted {u['username']}.")


@router.post("/users/{uid}/windows")
async def add_user_window(request: Request, uid: int) -> Response:
    cx, data = await _mutate(request)
    c = core(request)
    try:
        w = parse_window(data, c.clock.tz)
    except FormError as e:
        return redirect(request, f"/admin/users/{uid}#windows", str(e))
    c.store.add_window("user", uid, w)
    _audit(request, cx, "admin.window_added", {"user_id": uid, "window": w.describe()})
    return redirect(request, f"/admin/users/{uid}#windows", "Access window added.")


@router.post("/users/{uid}/windows/{wid}/delete")
async def delete_user_window(request: Request, uid: int, wid: int) -> Response:
    cx, _ = await _mutate(request)
    core(request).store.delete_window(wid, "user", uid)
    _audit(request, cx, "admin.window_deleted", {"user_id": uid, "window_id": wid})
    return redirect(request, f"/admin/users/{uid}#windows", "Access window removed.")


# ---- guest links ------------------------------------------------------------------------------


@router.get("/links")
async def links(request: Request) -> Response:
    require_admin(request)
    c = core(request)
    now = c.clock.now()
    rows = []
    for link in c.store.links():
        windows = c.store.windows("link", link["id"])
        expired = all(w.is_expired(now) for w in windows)
        rows.append({"link": link, "windows": windows, "expired": expired})
    users = [u for u in c.store.users() if not u["disabled"]]
    return render(request, "admin/links.html", rows=rows, users=users, today=now.date().isoformat())


@router.post("/links")
async def create_link(request: Request) -> Response:
    cx, data = await _mutate(request)
    c = core(request)
    try:
        uid = int(data.get("user_id", 0))
        u = c.store.user(uid)
        if u is None:
            raise FormError("Pick the account this link belongs to.")
        if u["role"] in ("admin", "household"):
            raise FormError("Attach links to a Scheduled or Viewer account, not an always-allowed one.")
        w = parse_window({**data, "kind": "once"}, c.clock.tz, allow_kinds=("once",))
        if w.is_expired(c.clock.now()):
            raise FormError("That time has already passed.")
        link_id, token, pin = await off_loop(
            c.store.create_link,
            uid,
            str(data.get("label", "")),
            w,
            c.clock.now(),
            cx.user["id"],
            max_redemptions=int(data.get("max_redemptions") or 1),
            pin=str(data.get("pin") or "") or None,
        )
    except (FormError, ValueError) as e:
        return redirect(request, "/admin/links", str(e))
    _audit(
        request, cx, "admin.link_created", {"link": link_id, "user": u["username"], "window": w.describe()}
    )
    url = f"{c.cfg.server.public_origin.rstrip('/')}/g/{token}"
    return render(
        request, "admin/link_created.html", url=url, pin=pin, window=w, u=u, label=data.get("label", "")
    )


@router.post("/links/{link_id}/revoke")
async def revoke_link(request: Request, link_id: int) -> Response:
    cx, _ = await _mutate(request)
    core(request).store.revoke_link(link_id)
    _audit(request, cx, "admin.link_revoked", {"link": link_id})
    return redirect(request, "/admin/links", "Link turned off and its devices signed out.")


@router.post("/links/{link_id}/delete")
async def delete_link(request: Request, link_id: int) -> Response:
    cx, _ = await _mutate(request)
    core(request).store.delete_link(link_id)
    _audit(request, cx, "admin.link_deleted", {"link": link_id})
    return redirect(request, "/admin/links", "Link deleted.")


# ---- quiet hours ------------------------------------------------------------------------------


@router.get("/quiet")
async def quiet(request: Request) -> Response:
    require_admin(request)
    c = core(request)
    keys = ("quiet.reminder_interval_min", "quiet.max_reminders", "quiet.stop_time")
    defs = [s for s in SETTINGS if s.key in keys]
    return render(
        request,
        "admin/quiet.html",
        windows=c.store.windows("quiet"),
        day_names=DAY_NAMES,
        defs=defs,
        values=c.settings.all(),
        state=c.alerts.quiet,
    )


@router.post("/quiet")
async def add_quiet(request: Request) -> Response:
    cx, data = await _mutate(request)
    c = core(request)
    try:
        w = parse_window(data, c.clock.tz)
    except FormError as e:
        return redirect(request, "/admin/quiet", str(e))
    c.store.add_window("quiet", None, w)
    _audit(request, cx, "admin.quiet_added", {"window": w.describe()})
    return redirect(request, "/admin/quiet", "Quiet-hours window added.")


@router.post("/quiet/{wid}/delete")
async def delete_quiet(request: Request, wid: int) -> Response:
    cx, _ = await _mutate(request)
    core(request).store.delete_window(wid, "quiet", None)
    _audit(request, cx, "admin.quiet_deleted", {"window_id": wid})
    return redirect(request, "/admin/quiet", "Quiet-hours window removed.")


# ---- settings ---------------------------------------------------------------------------------


@router.get("/settings")
async def settings_page(request: Request) -> Response:
    require_admin(request)
    c = core(request)
    groups = {
        "Door": [s for s in SETTINGS if s.key.startswith("door.")],
        "Quiet-hour reminders": [s for s in SETTINGS if s.key.startswith("quiet.")],
        "Other alerts": [s for s in SETTINGS if s.key.startswith("alerts.")],
    }
    return render(
        request,
        "admin/settings.html",
        groups=groups,
        values=c.settings.all(),
        shared=bool(c.cfg.shared_discord_webhook),
        recent_sends=list(reversed(c.notifier.sent[-10:])),
    )


@router.post("/settings")
async def save_settings(request: Request) -> Response:
    cx, data = await _mutate(request)
    c = core(request)
    values = {s.key: data[s.key] for s in SETTINGS if s.key in data}
    back = str(data.get("back") or "/admin/settings")
    back = back if back in ("/admin/settings", "/admin/quiet") else "/admin/settings"
    try:
        c.settings.set_many(values)
    except (ValueError, KeyError) as e:
        return redirect(request, back, str(e))
    _audit(request, cx, "admin.settings_changed", json.dumps(values))
    return redirect(request, back, "Settings saved.")


@router.post("/settings/test-crack")
async def test_crack(request: Request) -> Response:
    cx, _ = await _mutate(request)
    c = core(request)
    try:
        await c.door.test_crack(cx.user["display_name"] or cx.user["username"])
    except DoorError as e:
        return redirect(request, "/admin/settings", str(e))
    _audit(request, cx, "door.crack.calibration")
    return redirect(request, "/admin/settings", "Crack test sent. Check how far the door opened.")


@router.post("/settings/test-notify")
async def test_notify(request: Request) -> Response:
    cx, _ = await _mutate(request)
    core(request).notifier.publish(EventType.HEALTH, "doorman test alert", f"Sent by {cx.user['username']}.")
    return redirect(request, "/admin/settings", "Test alert queued for everyone subscribed to Health alerts.")


# ---- API tokens -------------------------------------------------------------------------------


@router.get("/tokens")
async def tokens_page(request: Request) -> Response:
    require_admin(request)
    return render(request, "admin/tokens.html", tokens=core(request).store.api_tokens(), new_token=None)


@router.post("/tokens")
async def create_token(request: Request) -> Response:
    cx, data = await _mutate(request)
    c = core(request)
    scopes = {"read"} | ({"operate"} if data.get("operate") == "on" else set())
    try:
        token = c.store.create_api_token(str(data.get("name", "")), scopes, c.clock.now())
    except ValueError as e:
        return redirect(request, "/admin/tokens", str(e))
    _audit(request, cx, "admin.token_created", {"name": data.get("name"), "scopes": sorted(scopes)})
    return render(request, "admin/tokens.html", tokens=c.store.api_tokens(), new_token=token)


@router.post("/tokens/{token_id}/revoke")
async def revoke_token(request: Request, token_id: int) -> Response:
    cx, _ = await _mutate(request)
    core(request).store.revoke_api_token(token_id)
    _audit(request, cx, "admin.token_revoked", {"id": token_id})
    return redirect(request, "/admin/tokens", "Token revoked.")


# ---- audit ------------------------------------------------------------------------------------


@router.get("/audit")
async def audit(request: Request, page: int = 0, filter: str = "") -> Response:
    require_admin(request)
    prefixes = {"": "", "door": "door.", "auth": "auth.", "admin": "admin.", "link": "link."}
    prefix = prefixes.get(filter, "")
    rows = core(request).store.audit_rows(limit=100, offset=max(page, 0) * 100, action_prefix=prefix)
    return render(request, "admin/audit.html", rows=rows, page=max(page, 0), filter=filter, filters=prefixes)
