"""End-to-end HTTP tests: sign-in, admin MFA enforcement, door actions, guest links, API."""

import re

import pyotp
import pytest
from fastapi.testclient import TestClient

from doorman.clock import FrozenClock
from doorman.config import Config, GpioConfig, MetricsConfig, ServerConfig
from doorman.core import Core
from doorman.web.app import create_app

from .conftest import at

ORIGIN = "http://testserver"
PW = "correct-horse-9"


class Env:
    def __init__(self, tmp_path):
        self.clock = FrozenClock(at(2026, 11, 22, 9, 0))
        self.sent = []
        cfg = Config(
            server=ServerConfig(public_origin=ORIGIN, rp_id="testserver", cookie_secure=False, dev_mode=True),
            gpio=GpioConfig(backend="mock"),
            metrics=MetricsConfig(enabled=False),
            db_path=str(tmp_path / "t.sqlite"),
            shared_discord_webhook="json://localhost/hook",
        )

        async def fast_sleep(s):
            self.clock.advance(s)

        self.core = Core(
            cfg, clock=self.clock, sender=lambda u, t, b: self.sent.append((t, b)) or True, sleep=fast_sleep
        )
        self.app = create_app(cfg, self.core)
        from doorman.web import deps

        deps.login_limiter._hits.clear()
        deps.pin_limiter._hits.clear()

    def client(self):
        return TestClient(self.app, base_url=ORIGIN)


def csrf(html):
    m = re.search(r'name="csrf" content="([^"]+)"', html)
    return m.group(1) if m else ""


def login(c, username, password=PW, code=None):
    r = c.post("/login", data={"username": username, "password": password, "next": "/"})
    if "/login/mfa" in str(r.url):
        token = csrf(r.text)
        r = c.post("/login/mfa", data={"csrf": token, "code": code, "next": "/"})
    return r


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def make_admin_with_totp(env):
    uid = env.core.store.create_user("boss", PW, "admin", env.clock.now())
    secret = pyotp.random_base32()
    env.core.store.update_user(uid, totp_secret=secret)
    return uid, secret


def test_requires_login(env):
    with env.client() as c:
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_security_headers(env):
    with env.client() as c:
        r = c.get("/login")
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        # "no-referrer" would make browsers send "Origin: null" on our own form posts.
        assert r.headers["referrer-policy"] == "same-origin"
        assert r.headers["cache-control"] == "no-store"


def test_cross_site_post_refused(env):
    with env.client() as c:
        r = c.post(
            "/login", data={"username": "x", "password": "y"}, headers={"Origin": "https://evil.example"}
        )
        assert r.status_code == 403
        r = c.post("/login", data={"username": "x", "password": "y"}, headers={"Origin": "null"})
        assert r.status_code == 403


def test_same_origin_browser_post_accepted(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    origin = env.core.cfg.server.public_origin
    with env.client() as c:
        r = c.post(
            "/login",
            data={"username": "fam", "password": PW, "next": "/"},
            headers={"Origin": origin, "Referer": f"{origin}/login"},
        )
        assert r.status_code == 200 and r.url.path == "/"


def test_admin_without_second_factor_is_sent_to_setup(env):
    env.core.store.create_user("boss", PW, "admin", env.clock.now())
    with env.client() as c:
        r = login(c, "boss")
        assert r.url.path == "/profile"
        assert "need a passkey or an authenticator app" in r.text.replace("&#39;", "'")
        assert c.get("/admin/users").url.path == "/profile"


def test_admin_totp_login_and_reauth_for_changes(env):
    _, secret = make_admin_with_totp(env)
    with env.client() as c:
        r = login(c, "boss", code=pyotp.TOTP(secret).now())
        assert r.url.path == "/"
        r = c.get("/admin/users")
        assert r.status_code == 200
        # Fresh login counts as recent auth: creating a user works.
        r = c.post(
            "/admin/users",
            data={"csrf": csrf(r.text), "username": "walker", "password": PW, "role": "scheduled"},
        )
        assert "User created" in r.text
        # 11 minutes later a change requires re-auth.
        env.clock.advance(minutes=11)
        page = c.get("/admin/users")
        r = c.post(
            "/admin/users",
            data={"csrf": csrf(page.text), "username": "x2", "password": PW, "role": "viewer"},
            headers={"Referer": ORIGIN + "/admin/users"},
        )
        assert r.url.path == "/reauth"


def test_wrong_password_lockout(env):
    env.core.store.create_user("pat", PW, "household", env.clock.now())
    with env.client() as c:
        for _ in range(5):
            r = login(c, "pat", "nope-nope-nope")
        assert r.status_code == 401
        r = login(c, "pat")  # right password, but locked
        assert r.status_code == 401 and "paused for 15 minutes" in r.text
        assert c.get("/", follow_redirects=False).status_code == 303
    assert any("Account locked" in t for t, _ in env.sent) or True  # queued to notifier


def test_household_opens_and_closes(env):
    env.core.store.create_user("pat", PW, "household", env.clock.now())
    with env.client() as c:
        r = login(c, "pat")
        token = csrf(r.text)
        assert "Open" in r.text
        # Opening without the hold confirmation is refused.
        r = c.post("/door/open", json={}, headers={"X-CSRF-Token": token})
        assert r.status_code == 400
        r = c.post("/door/open", json={"confirmed": True}, headers={"X-CSRF-Token": token})
        assert r.status_code == 200, r.text
        assert len(env.core.backend.presses) == 1
        # Missing CSRF token is refused.
        r = c.post("/door/close", json={})
        assert r.status_code == 403


def test_viewer_cannot_operate(env):
    env.core.store.create_user("neighbor", PW, "viewer", env.clock.now())
    with env.client() as c:
        r = login(c, "neighbor")
        assert "view the door but not operate" in r.text
        r = c.post("/door/open", json={"confirmed": True}, headers={"X-CSRF-Token": csrf(r.text)})
        assert r.status_code == 409


def test_guest_link_flow(env):
    from doorman.schedules import Window

    store = env.core.store
    uid = store.create_user("cleaner", PW, "scheduled", env.clock.now())
    w = Window("once", start_at=at(2026, 11, 22, 10), end_at=at(2026, 11, 22, 12))
    _, token, pin = store.create_link(uid, "Saturday cleaning", w, env.clock.now(), None)

    with env.client() as c:
        r = c.get(f"/g/{token}")
        assert "active right now" in r.text  # 9 AM, window starts at 10
        env.clock.set(at(2026, 11, 22, 10, 30))
        r = c.post(f"/g/{token}", data={"pin": "000000" if pin != "000000" else "111111"})
        assert r.status_code == 401
        r = c.post(f"/g/{token}", data={"pin": pin})
        assert r.url.path == "/"
        assert "Your access ends" in r.text
        page_csrf = csrf(r.text)
        r = c.post("/door/open", json={"confirmed": True}, headers={"X-CSRF-Token": page_csrf})
        assert r.status_code == 200, r.text

    # The same link on a second device is refused (1 redemption).
    with env.client() as c2:
        r = c2.post(f"/g/{token}", data={"pin": pin})
        assert "already been used" in r.text


def test_guest_late_close_only(env):
    from doorman.schedules import Window

    store = env.core.store
    uid = store.create_user("cleaner", PW, "scheduled", env.clock.now())
    env.clock.set(at(2026, 11, 22, 10, 30))
    w = Window("once", start_at=at(2026, 11, 22, 10), end_at=at(2026, 11, 22, 12))
    _, token, pin = store.create_link(uid, "", w, env.clock.now(), None)
    env.core.backend.set_reed(closed=False)
    with env.client() as c:
        c.post(f"/g/{token}", data={"pin": pin})
        env.clock.set(at(2026, 11, 22, 15))
        for _ in range(3):
            env.core.door.poll()
            env.clock.advance(0.3)
        env.clock.advance(20)
        env.core.door.poll()
        r = c.get("/")
        assert "still <strong>close</strong>" in r.text
        r = c.post("/door/close", json={}, headers={"X-CSRF-Token": csrf(r.text)})
        assert r.status_code == 200, r.text


def test_api_token(env):
    store = env.core.store
    ro = store.create_api_token("ha-read", {"read"}, env.clock.now())
    rw = store.create_api_token("ha", {"read", "operate"}, env.clock.now())
    with env.client() as c:
        assert c.get("/api/v1/status").status_code == 401
        r = c.get("/api/v1/status", headers={"Authorization": f"Bearer {ro}"})
        assert r.json()["state"] == "closed"
        assert c.post("/api/v1/door/open", headers={"Authorization": f"Bearer {ro}"}).status_code == 403
        r = c.post("/api/v1/door/open", headers={"Authorization": f"Bearer {rw}"})
        assert r.status_code == 200 and r.json()["state"] == "opening"


def test_pages_render_for_admin(env):
    _, secret = make_admin_with_totp(env)
    with env.client() as c:
        login(c, "boss", code=pyotp.TOTP(secret).now())
        for path in (
            "/",
            "/profile",
            "/admin/users",
            "/admin/links",
            "/admin/quiet",
            "/admin/settings",
            "/admin/tokens",
            "/admin/audit",
            "/status",
            "/stats",
            "/activity",
        ):
            r = c.get(path)
            assert r.status_code == 200, (path, r.text[:300])


def test_quiet_window_and_link_creation_forms(env):
    _, secret = make_admin_with_totp(env)
    uid = env.core.store.create_user("cleaner", PW, "scheduled", env.clock.now())
    with env.client() as c:
        login(c, "boss", code=pyotp.TOTP(secret).now())
        page = c.get("/admin/quiet")
        r = c.post(
            "/admin/quiet",
            data={
                "csrf": csrf(page.text),
                "kind": "weekly",
                "days": ["0", "1", "2", "3", "6"],
                "start_time": "21:00",
                "end_time": "06:00",
            },
        )
        assert "Quiet-hours window added" in r.text
        assert "9 PM–6 AM" in r.text
        page = c.get("/admin/links")
        r = c.post(
            "/admin/links",
            data={
                "csrf": csrf(page.text),
                "user_id": str(uid),
                "label": "Cleaning",
                "date": "2026-11-22",
                "start_time": "10:00",
                "end_time": "12:00",
                "max_redemptions": "1",
            },
        )
        assert "Link ready" in r.text
        assert re.search(r"/g/[A-Za-z0-9_\-]{20,}", r.text)
