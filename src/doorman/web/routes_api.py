"""Bearer-token REST API for Home Assistant and scripts (no cookies, so no CSRF surface)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from doorman.access import Action, Principal
from doorman.auth.ratelimit import RateLimiter
from doorman.core import AccessDenied
from doorman.door import DoorError
from doorman.web.deps import client_ip, core

router = APIRouter(prefix="/api/v1")
_bad_token = RateLimiter(limit=20, window_s=300)


def _principal(request: Request) -> Principal | JSONResponse:
    c = core(request)
    ip = client_ip(request)
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return JSONResponse({"detail": "Missing bearer token."}, 401, headers={"WWW-Authenticate": "Bearer"})
    row = c.store.api_token(auth[7:].strip(), c.clock.now())
    if row is None:
        if not _bad_token.hit(ip):
            return JSONResponse({"detail": "Too many bad tokens."}, 429)
        return JSONResponse({"detail": "Invalid token."}, 401, headers={"WWW-Authenticate": "Bearer"})
    return c.principal_for_token(row)


def _status(request: Request) -> dict[str, Any]:
    c = core(request)
    snap = c.door.snapshot()
    st = c.stats
    return {
        "state": snap.state.value,
        "label": snap.label,
        "closed": snap.reed_closed,
        "since": snap.since.isoformat(),
        "open_since": snap.open_since.isoformat() if snap.open_since else None,
        "available_actions": [a.value for a in snap.actions],
        "message": snap.message,
        "last_actor": snap.last_actor,
        "last_source": snap.last_source,
        "stats": st.as_dict() if st else None,
    }


@router.get("/status")
async def status(request: Request) -> JSONResponse:
    p = _principal(request)
    if isinstance(p, JSONResponse):
        return p
    return JSONResponse(_status(request))


@router.post("/door/{action}")
async def door(request: Request, action: str) -> JSONResponse:
    p = _principal(request)
    if isinstance(p, JSONResponse):
        return p
    try:
        act = Action(action)
    except ValueError:
        return JSONResponse({"detail": "Unknown action. Use open, close, crack or toggle."}, 404)
    try:
        await core(request).operate(p, act, client_ip(request))
    except AccessDenied as e:
        return JSONResponse({"detail": str(e)}, 403)
    except DoorError as e:
        return JSONResponse({"detail": str(e), **_status(request)}, 409)
    return JSONResponse(_status(request))


@router.get("/health")
async def health(request: Request) -> JSONResponse:
    """Unauthenticated liveness probe: reveals nothing about the door."""
    return JSONResponse({"ok": True})
