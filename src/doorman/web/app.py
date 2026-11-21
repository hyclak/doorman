"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from importlib import resources

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from doorman import __version__
from doorman.config import Config
from doorman.core import Core
from doorman.schedules import fmt_date, fmt_time
from doorman.stats import fmt_duration
from doorman.store import ROLE_LABELS
from doorman.web import deps
from doorman.web.deps import Forbidden, Redirect

log = logging.getLogger(__name__)

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; object-src 'none'"
)


def _ago(dt: datetime | None, now: datetime) -> str:
    if dt is None:
        return "never"
    s = (now - dt).total_seconds()
    if s < 60:
        return "just now"
    return fmt_duration(s) + " ago"


def _when(dt: datetime | None, now: datetime) -> str:
    if dt is None:
        return "—"
    if dt.date() == now.date():
        return fmt_time(dt.time())
    return f"{fmt_date(dt)}, {fmt_time(dt.time())}"


def describe_user_agent(ua: str) -> str:
    """Short human label like 'Chrome on Android' (good enough for a device list)."""
    ua = ua or ""
    browser = next(
        (
            name
            for key, name in (
                ("Edg/", "Edge"),
                ("Firefox/", "Firefox"),
                ("CriOS", "Chrome"),
                ("Chrome/", "Chrome"),
                ("Safari/", "Safari"),
            )
            if key in ua
        ),
        "Browser",
    )
    system = next(
        (
            name
            for key, name in (
                ("Android", "Android"),
                ("iPhone", "iPhone"),
                ("iPad", "iPad"),
                ("Mac OS X", "Mac"),
                ("Windows", "Windows"),
                ("Linux", "Linux"),
            )
            if key in ua
        ),
        "",
    )
    if "python" in ua.lower() or "curl" in ua.lower() or "HomeAssistant" in ua:
        return ua.split(" ")[0][:40]
    return f"{browser} on {system}" if system else browser


def create_app(cfg: Config, core: Core | None = None) -> FastAPI:
    core = core or Core(cfg)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await core.start()
        try:
            yield
        finally:
            await core.stop()

    app = FastAPI(
        title="doorman",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )
    app.state.core = core

    pkg = resources.files("doorman.web")
    templates = Jinja2Templates(directory=str(pkg / "templates"))
    templates.env.globals.update(
        version=__version__,
        role_labels=ROLE_LABELS,
        fmt_time=fmt_time,
        fmt_date=fmt_date,
        ago=_ago,
        when=_when,
        duration=fmt_duration,
    )
    templates.env.filters["todt"] = lambda v: datetime.fromisoformat(v) if isinstance(v, str) else v
    templates.env.filters["ua"] = describe_user_agent
    app.state.templates = templates
    app.mount("/static", StaticFiles(directory=str(pkg / "static")), name="static")

    @app.middleware("http")
    async def context_and_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        is_api = request.url.path.startswith("/api/")
        if request.method not in ("GET", "HEAD", "OPTIONS") and not is_api and not deps.origin_ok(request):
            log.warning(
                "refused cross-site %s %s (origin=%r)",
                request.method,
                request.url.path,
                request.headers.get("origin"),
            )
            return JSONResponse({"detail": "Cross-site request refused."}, status_code=403)
        request.state.ctx = deps.Ctx() if is_api else deps.load_ctx(request)
        response = await call_next(request)
        h = response.headers
        h.setdefault("Content-Security-Policy", CSP)
        h.setdefault("X-Content-Type-Options", "nosniff")
        # same-origin: guest-link tokens never leak to other sites, and browsers still send a real
        # Origin on our own form posts ("no-referrer" makes Chrome send "Origin: null").
        h.setdefault("Referrer-Policy", "same-origin")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if not request.url.path.startswith("/static/"):
            h.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(Redirect)
    async def on_redirect(request: Request, exc: Redirect) -> Response:
        if request.headers.get("accept", "").startswith("application/json"):
            return JSONResponse(
                {"detail": exc.flash or "Sign in again.", "redirect": exc.url}, status_code=401
            )
        return deps.redirect(request, exc.url, exc.flash)

    @app.exception_handler(Forbidden)
    async def on_forbidden(request: Request, exc: Forbidden) -> Response:
        if request.headers.get("accept", "").startswith("application/json"):
            return JSONResponse({"detail": exc.message}, status_code=403)
        return deps.render(request, "error.html", status_code=403, message=exc.message)

    from doorman.web import routes_admin, routes_api, routes_auth, routes_door, routes_profile

    app.include_router(routes_auth.router)
    app.include_router(routes_door.router)
    app.include_router(routes_profile.router)
    app.include_router(routes_admin.router)
    app.include_router(routes_api.router)
    return app
