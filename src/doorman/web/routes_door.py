"""Door page, live status, door actions, guest links."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from doorman.access import OPENING_ACTIONS, Action, permitted_actions
from doorman.core import SOURCE_LABELS, AccessDenied
from doorman.door import ACTION_LABELS, DoorError
from doorman.notify import EventType
from doorman.schedules import active_occurrence, next_start
from doorman.web.deps import (
    Forbidden,
    check_csrf,
    client_ip,
    core,
    ctx,
    hash_queue_full,
    off_loop,
    pin_limiter,
    rate_key,
    redirect,
    render,
    require_login,
    set_session_cookie,
)

router = APIRouter()


def panel_context(request: Request) -> dict[str, Any]:
    cx = require_login(request)
    c = core(request)
    assert cx.principal is not None
    now = c.clock.now()
    snap = c.door.snapshot()
    synced = c.clock.synced()
    actions, reason = permitted_actions(cx.principal, snap.actions, now, synced)
    if not snap.actions and snap.moving:
        reason = ""
    window = None
    if cx.principal.time_limited:
        occ = active_occurrence(cx.principal.windows, now)
        window = {
            "active_until": occ[1] if occ else None,
            "next": None if occ else next_start(cx.principal.windows, now),
            "late_close_until": cx.principal.late_close_until,
        }
    return {
        "snap": snap,
        "actions": actions,
        "primary": actions[0] if actions else None,
        "secondary": actions[1:],
        "reason": reason,
        "labels": ACTION_LABELS,
        "confirm": {a.value for a in OPENING_ACTIONS},
        "source_labels": SOURCE_LABELS,
        "window": window,
        "clock_synced": synced,
    }


@router.get("/")
async def index(request: Request) -> Response:
    cx = require_login(request)
    c = core(request)
    context = panel_context(request)
    recent = [] if cx.is_guest else _recent(request)
    return render(request, "door.html", **context, stats=None if cx.is_guest else c.stats, recent=recent)


def _recent(request: Request) -> list[Any]:
    rows = core(request).store.audit_rows(limit=12, action_prefix="door.")
    return [r for r in rows if r["action"] in ("door.opened", "door.closed")][:5]


@router.get("/activity")
async def activity_fragment(request: Request) -> Response:
    cx = require_login(request)
    if cx.is_guest:
        raise Forbidden()
    return render(request, "partials/activity.html", recent=_recent(request))


@router.get("/status")
async def status_fragment(request: Request) -> Response:
    return render(request, "partials/door_panel.html", **panel_context(request))


@router.get("/stats")
async def stats_fragment(request: Request) -> Response:
    cx = require_login(request)
    if cx.is_guest:
        raise Forbidden()
    return render(request, "partials/stats.html", stats=core(request).stats)


@router.post("/door/{action}")
async def door_action(request: Request, action: str) -> JSONResponse:
    cx = require_login(request)
    check_csrf(request, None)
    c = core(request)
    assert cx.principal is not None
    try:
        act = Action(action)
    except ValueError:
        return JSONResponse({"detail": "Unknown action."}, 404)
    body: dict[str, Any] = {}
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
    if act in OPENING_ACTIONS and body.get("confirmed") is not True:
        return JSONResponse({"detail": "Hold the button to confirm."}, 400)
    try:
        await c.operate(cx.principal, act, client_ip(request))
    except (AccessDenied, DoorError) as e:
        return JSONResponse({"detail": str(e)}, 409)
    return JSONResponse({"ok": True})


# ---- guest links ------------------------------------------------------------------------------


def _guest_view(request: Request, token: str) -> tuple[Any, dict[str, Any]]:
    c = core(request)
    link = c.store.link_by_token(token)
    if link is None:
        return None, {"problem": "This link isn't valid. Check you copied all of it."}
    now = c.clock.now()
    windows = c.store.windows("link", link["id"])
    occ = active_occurrence(windows, now)
    info: dict[str, Any] = {"link": link, "occ": occ, "next": None if occ else next_start(windows, now)}
    if problem := c.store.link_problem(link):
        info["problem"] = problem
    elif not c.clock.synced():
        info["problem"] = "The door controller's clock hasn't synced yet. Try again in a minute."
    elif occ is None:
        info["problem"] = "This link isn't active right now."
    return link, info


@router.get("/g/{token}")
async def guest_link(request: Request, token: str) -> Response:
    cx = ctx(request)
    link, info = _guest_view(request, token)
    if link is not None and cx.link is not None and cx.link["id"] == link["id"]:
        return redirect(request, "/")
    return render(request, "guest.html", token=token, **info)


@router.post("/g/{token}")
async def guest_redeem(request: Request, token: str) -> Response:
    c = core(request)
    ip = client_ip(request)
    link, info = _guest_view(request, token)
    if link is None or info.get("problem"):
        return render(request, "guest.html", 400, token=token, **info)
    data = await request.form()
    if hash_queue_full():
        return render(
            request, "guest.html", 429, token=token, **info, error="Busy right now. Try again in a moment."
        )
    if not pin_limiter.hit(rate_key(ip)):
        return render(
            request, "guest.html", 429, token=token, **info, error="Too many attempts. Wait a few minutes."
        )
    result = await off_loop(c.store.redeem_link, link["id"], str(data.get("pin", "")))
    now = c.clock.now()
    who = link["display_name"] or link["username"]
    if result == "unusable":
        fresh = c.store.link(link["id"])
        problem = (c.store.link_problem(fresh) if fresh else None) or "This link isn't valid."
        return render(request, "guest.html", 403, token=token, **{**info, "problem": problem})
    if result != "ok":
        c.store.audit(now, "link", who, "link.bad_pin", {"link": link["id"]}, link["id"], ip)
        if result == "locked":
            c.notifier.publish(
                EventType.SECURITY, f"Guest link locked: {who}", f"Too many wrong PINs from {ip}."
            )
            return render(
                request,
                "guest.html",
                403,
                token=token,
                **info,
                problem="This link is locked after too many wrong PINs. Ask for a new one.",
            )
        return render(request, "guest.html", 401, token=token, **info, error="That PIN didn't match.")
    occ = info["occ"]
    late = c.store.late_close_until(occ[1], now)
    session_token, _ = c.store.create_session(
        now,
        link_id=link["id"],
        expires_at=late,
        late_close_until=late,
        ip=ip,
        user_agent=request.headers.get("user-agent", ""),
    )
    c.store.audit(
        now, "link", who, "link.redeemed", {"link": link["id"], "label": link["label"]}, link["id"], ip
    )
    c.notifier.publish(EventType.GUEST_USE, f"Guest link opened: {who}", link["label"] or "")
    resp = redirect(request, "/")
    set_session_cookie(request, resp, session_token, int((late - now).total_seconds()))
    return resp


# ---- development helpers ----------------------------------------------------------------------


@router.post("/dev/reed/{state}")
async def dev_reed(request: Request, state: str) -> JSONResponse:
    c = core(request)
    if not c.cfg.server.dev_mode or c.cfg.gpio.backend != "mock":
        raise Forbidden("Not available.")
    require_login(request)
    check_csrf(request, None)
    from doorman.hardware.mock import MockBackend

    assert isinstance(c.backend, MockBackend)
    c.backend.set_reed({"closed": True, "open": False}.get(state))
    return JSONResponse({"ok": True})
