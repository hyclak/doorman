"""Regression tests for the security review fixes (SSRF via notification URLs, passkey user
verification, re-auth before changing sign-in methods, open redirects, rate-limit eviction,
hashing off the event loop, guest-link races and smaller hardening)."""

import re
import threading
from datetime import timedelta

import pyotp
import pytest

from doorman import notify_urls
from doorman.auth.ratelimit import RateLimiter
from doorman.config import Config, GpioConfig, MetricsConfig, MqttConfig, ServerConfig
from doorman.core import Core
from doorman.notify import EventType, Message
from doorman.schedules import Window
from doorman.store import MAX_PIN_ATTEMPTS
from doorman.web import deps
from doorman.web.app import create_app
from doorman.web.deps import rate_key, safe_next

from .test_auth_flows import _page_csrf, _passkey_sign_in, _register_passkey
from .test_web import ORIGIN, PW, Env, csrf, login, make_admin_with_totp

JSON = {"Accept": "application/json"}


def _assert(key, begin):
    return key.get(begin["options"], rp_id="testserver", origin=ORIGIN)


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    deps.account_limiter._hits.clear()
    deps.notify_test_limiter._hits.clear()
    deps.passkey_begin_limiter._hits.clear()
    return e


# ---- open redirect -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "/\t/evil.example",
        "/\n/evil.example",
        "/\r/evil.example",
        "/\\evil.example",
        "//evil.example",
        "/ /evil.example",
        "https://evil.example/",
        "javascript:alert(1)",
        "/\x00/evil.example",
    ],
)
def test_safe_next_refuses_off_site_tricks(value):
    assert safe_next(value) == "/"


@pytest.mark.parametrize("value", ["/", "/admin/users", "/profile?setup=mfa#notifications", "/g/abc-_"])
def test_safe_next_keeps_local_paths(value):
    assert safe_next(value) == value


def test_login_and_reauth_pages_drop_tab_redirect(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    with env.client() as c:
        r = c.get("/login", params={"next": "/\t/evil.example"})
        assert re.search(r'data-next="([^"]*)"', r.text).group(1) == "/"
        login(c, "fam")
        r = c.get("/reauth", params={"next": "/\t/evil.example"})
        assert "evil.example" not in r.text


# ---- SSRF through personal notification URLs ------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "discord://1234/abcd",
        "tgram://bottoken/chatid",
        "pover://user@token",
        "slack://T1/B1/C1",
        "ntfys://ntfy.sh/my-topic",
        "ntfy://ntfy.sh/my-topic",
        "https://discord.com/api/webhooks/123/abc",
        "https://hooks.slack.com/services/T1/B1/C1",
        "https://ntfy.sh/my-topic",
    ],
)
def test_personal_url_allowed(url):
    assert notify_urls.problem(url) is None


@pytest.mark.parametrize(
    "url",
    [
        "json://127.0.0.1:2019/stop?method=POST",  # Caddy admin API
        "json://example.com/hook",
        "jsons://example.com/hook",
        "xml://10.10.40.1/",
        "form://192.168.1.1/",
        "ntfys://ntfy.internal.example/topic",
        "ntfys://attacker.example/t",  # public, but could 307-redirect or DNS-rebind to the LAN
        "ntfys://attacker.example/t?redirect=yes",
        "ntfys://ntfy.sh/t?redirect=yes",
        "ntfys://ntfy.sh/t?Redirect=Yes",
        "discord://1234/abcd?redirect=yes",
        "ntfys://ntfy.sh:2019/t",
        "ntfys://ntfy.sh@127.0.0.1/t",
        "ntfys://ntfy.sh\\@127.0.0.1/t",
        "ntfys://ntfy.sh.attacker.example/t",
        "ntfys://127.0.0.1:2019/x",
        "ntfys://[::1]/x",
        "ntfys://[::ffff:127.0.0.1]/x",
        "ntfys://169.254.169.254/x",
        "ntfys://100.64.0.1/x",  # carrier-grade NAT
        "ntfy://my-topic",  # bare topic: no server to check
        "discord://12 34/abcd",
        "file:///etc/passwd",
        "https://example.com/hook",
        "https://discord.com.evil.example/api/webhooks/1/a",
        "https://discord.com:2019/api/webhooks/1/a",
        "mailto://user:pass@example.com?smtp=10.10.40.1",
    ],
)
def test_personal_url_refused(url):
    assert notify_urls.problem(url)


def test_viewer_cannot_save_internal_notification_url(env):
    uid = env.core.store.create_user("watcher", PW, "viewer", env.clock.now())
    with env.client() as c:
        login(c, "watcher")
        r = c.post(
            "/profile/notifications",
            data={"csrf": _page_csrf(c), "apprise_url": "json://127.0.0.1:2019/stop?method=POST"},
        )
        assert "kind of notification URL" in r.text
    assert env.core.store.notify_prefs(uid) is None


def test_stored_bad_url_is_skipped_at_send_time(env):
    uid = env.core.store.create_user("old", PW, "household", env.clock.now())
    # A row saved before validation existed.
    env.core.db.execute(
        "INSERT INTO notify_prefs(user_id, events, use_shared, apprise_url) VALUES(?,?,?,?)",
        (uid, "quiet_hours", 0, "json://127.0.0.1:2019/load"),
    )
    assert env.core.notifier.deliveries(Message(EventType.QUIET_HOURS, "t", "b")) == []
    with env.client() as c:
        login(c, "old")
        r = c.post("/profile/notifications/test", data={"csrf": _page_csrf(c)})
        assert "kind of notification URL" in r.text
    assert env.sent == []


def test_test_notification_is_rate_limited(env):
    uid = env.core.store.create_user("fam", PW, "household", env.clock.now())
    env.core.store.set_notify_prefs(uid, {"quiet_hours"}, True, "")
    with env.client() as c:
        login(c, "fam")
        token = _page_csrf(c)
        for _ in range(5):
            assert "Test sent" in c.post("/profile/notifications/test", data={"csrf": token}).text
        assert "Too many tests" in c.post("/profile/notifications/test", data={"csrf": token}).text


def test_security_alerts_go_to_admins_only(env):
    a = env.core.store.create_user("boss", PW, "admin", env.clock.now())
    v = env.core.store.create_user("walker", PW, "scheduled", env.clock.now())
    env.core.store.set_notify_prefs(a, {"security"}, False, "ntfys://ntfy.sh/admin-topic")
    env.core.store.set_notify_prefs(v, {"security"}, False, "ntfys://ntfy.sh/walker-topic")
    sends = env.core.notifier.deliveries(Message(EventType.SECURITY, "Admin sign-in", "From 1.2.3.4"))
    assert [s[0] for s in sends] == ["ntfys://ntfy.sh/admin-topic"]
    with env.client() as c:
        login(c, "walker")
        page = c.get("/profile").text
        assert 'value="security"' not in page and 'value="door_change"' in page
        c.post(
            "/profile/notifications",
            data={"csrf": csrf(page), "events": ["security", "door_change"], "apprise_url": ""},
        )
    assert env.core.store.notify_prefs(v)["events"] == "door_change"


# ---- passkeys: user verification --------------------------------------------------------------


def test_passkey_without_pin_cannot_sign_in_alone(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    with env.client() as c:
        login(c, "fam")
        key = _register_passkey(c)
    key.uv = False  # e.g. a security key with no PIN set, or one someone picked up
    with env.client() as c:
        r = _passkey_sign_in(c, key)
        assert r.status_code == 400
        assert c.get("/", follow_redirects=False).status_code == 303


def test_passkey_without_pin_still_works_as_second_factor(env):
    env.core.store.create_user("boss", PW, "admin", env.clock.now())
    with env.client() as c:
        login(c, "boss")
        key = _register_passkey(c)  # admins may add their first factor right after signing in
    key.uv = False
    with env.client() as c:
        r = c.post("/login", data={"username": "boss", "password": PW, "next": "/"})
        assert "/login/mfa" in str(r.url)
        r = _passkey_sign_in(c, key)
        assert r.status_code == 200, r.text
        assert c.get("/", follow_redirects=False).status_code == 200


def test_second_factor_handle_cannot_finish_passwordless(env):
    """A challenge issued for the MFA step (no PIN needed) can't be redeemed without the password."""
    env.core.store.create_user("boss", PW, "admin", env.clock.now())
    with env.client() as c:
        login(c, "boss")
        key = _register_passkey(c)
    key.uv = False
    with env.client() as c:
        c.post("/login", data={"username": "boss", "password": PW, "next": "/"})
        begin = c.post("/login/passkey/begin").json()
    with env.client() as fresh:  # no pending session
        r = fresh.post(
            "/login/passkey/finish",
            json={"handle": begin["handle"], "credential": _assert(key, begin)},
        )
        assert r.status_code == 400


def test_reauth_with_passkey_requires_pin(env):
    _, secret = make_admin_with_totp(env)
    with env.client() as c:
        login(c, "boss", code=pyotp.TOTP(secret).now())
        key = _register_passkey(c)
        key.uv = False
        token = _page_csrf(c, "/reauth")
        begin = c.post("/reauth/passkey/begin", headers={"X-CSRF-Token": token}).json()
        r = c.post(
            "/reauth/passkey/finish",
            json={"handle": begin["handle"], "credential": _assert(key, begin)},
            headers={"X-CSRF-Token": token},
        )
        assert r.status_code == 400


# ---- re-auth before changing sign-in methods ------------------------------------------------------


def test_adding_a_passkey_needs_a_recent_sign_in(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    with env.client() as c:
        login(c, "fam")
        env.clock.advance(11 * 60)
        r = c.post("/profile/passkeys/begin", headers={"X-CSRF-Token": _page_csrf(c), **JSON})
        assert r.status_code == 401
        assert r.json()["redirect"].startswith("/reauth?next=")
        r = c.post("/profile/totp/begin", data={"csrf": _page_csrf(c)}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/reauth")
        # Signing in again opens the window.
        r = c.post("/reauth", data={"csrf": _page_csrf(c, "/reauth"), "password": PW, "next": "/profile"})
        assert str(r.url).endswith("/profile")
        assert c.post("/profile/passkeys/begin", headers={"X-CSRF-Token": _page_csrf(c)}).status_code == 200


def test_new_passkey_raises_a_security_alert(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    published = []
    env.core.notifier.publish = lambda ev, title, body="": published.append((ev, title))
    with env.client() as c:
        login(c, "fam")
        _register_passkey(c)
    assert (EventType.SECURITY, "Passkey added: fam") in published


def test_registration_handle_is_bound_to_its_account(env):
    env.core.store.create_user("alice", PW, "household", env.clock.now())
    env.core.store.create_user("mallory", PW, "household", env.clock.now())
    from .test_passkeys import SoftAuthenticator

    with env.client() as a, env.client() as m:
        login(a, "alice")
        login(m, "mallory")
        begin = a.post("/profile/passkeys/begin", headers={"X-CSRF-Token": _page_csrf(a)}).json()
        cred = SoftAuthenticator().create(begin["options"], origin=ORIGIN)
        r = m.post(
            "/profile/passkeys/finish",
            json={"handle": begin["handle"], "credential": cred},
            headers={"X-CSRF-Token": _page_csrf(m)},
        )
        assert r.status_code == 400
    assert env.core.store.passkeys(env.core.store.user_by_name("mallory")["id"]) == []


def test_admin_without_factor_can_still_reach_reauth(env):
    env.core.store.create_user("boss", PW, "admin", env.clock.now())
    with env.client() as c:
        login(c, "boss")
        env.clock.advance(11 * 60)
        r = c.get("/reauth", params={"next": "/profile"}, follow_redirects=False)
        assert r.status_code == 200


# ---- rate limiting ------------------------------------------------------------------------------


def test_flooding_one_limiter_keeps_account_counters():
    deps.account_limiter._hits.clear()
    for _ in range(10):
        deps.account_limiter.hit("mfa:1")
    for i in range(10_050):
        deps.login_limiter.hit(f"ip:2001:db8:{i:x}::1")
    assert deps.account_limiter.hit("mfa:1") is False
    deps.login_limiter._hits.clear()
    deps.account_limiter._hits.clear()


def test_limiter_evicts_least_recent_instead_of_clearing():
    rl = RateLimiter(limit=2, window_s=300, max_keys=100)
    rl.hit("busy", now=0)
    rl.hit("busy", now=0)
    for i in range(500):
        rl.hit(f"k{i}", now=1)
        assert rl.hit("busy", now=1) is False  # the active, blocked key is never dropped
    assert len(rl._hits) <= 100


def test_ipv6_addresses_share_a_64_budget():
    assert rate_key("2001:db8:1:2::1") == rate_key("2001:db8:1:2:ffff:ffff:ffff:ffff")
    assert rate_key("2001:db8:1:2::1") != rate_key("2001:db8:1:3::1")
    assert rate_key("::ffff:192.0.2.7") == rate_key("192.0.2.7") == "ip:192.0.2.7"


def test_too_many_codes_ends_the_pending_sign_in(env):
    make_admin_with_totp(env)
    with env.client() as c:
        c.post("/login", data={"username": "boss", "password": PW, "next": "/"})
        token = csrf(c.get("/login/mfa").text)
        for _ in range(10):
            c.post("/login/mfa", data={"csrf": token, "code": "000000"})
        r = c.post("/login/mfa", data={"csrf": token, "code": "000000"}, follow_redirects=False)
        assert r.headers["location"] == "/login"
        assert c.get("/login/mfa", follow_redirects=False).headers["location"] == "/login"


# ---- hashing off the event loop / guest-link race -------------------------------------------------


def test_password_checks_run_on_the_hash_thread(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    seen = []
    real = env.core.store.check_login

    def spy(*a, **kw):
        seen.append(threading.current_thread().name)
        return real(*a, **kw)

    env.core.store.check_login = spy
    with env.client() as c:
        login(c, "fam")
    assert seen and seen[0].startswith("doorman-hash")


def _link(env, pin="246810"):
    uid = env.core.store.create_user("walker", PW, "scheduled", env.clock.now())
    now = env.clock.now()
    w = Window(kind="once", start_at=now - timedelta(hours=1), end_at=now + timedelta(hours=1))
    link_id, token, pin = env.core.store.create_link(uid, "", w, now, None, pin=pin)
    return uid, link_id, token, pin


def test_pin_attempts_are_counted_against_the_current_row(env):
    _, link_id, _, pin = _link(env)
    results = [env.core.store.redeem_link(link_id, "000000") for _ in range(MAX_PIN_ATTEMPTS)]
    assert results[-1] == "locked" and set(results[:-1]) == {"bad"}
    # Even the right PIN, sent by a request that loaded the link before it locked, is refused.
    assert env.core.store.redeem_link(link_id, pin) == "unusable"


def test_promoting_an_account_revokes_its_guest_links(env):
    uid, link_id, token, pin = _link(env)
    with env.client() as guest:
        guest.post(f"/g/{token}", data={"pin": pin})
        assert guest.get("/", follow_redirects=False).status_code == 200
        _, secret = make_admin_with_totp(env)
        with env.client() as admin:
            login(admin, "boss", code=pyotp.TOTP(secret).now())
            page = admin.get(f"/admin/users/{uid}").text
            admin.post(f"/admin/users/{uid}", data={"csrf": csrf(page), "role": "household"})
        assert env.core.store.link(link_id)["revoked"] == 1
        assert guest.get("/", follow_redirects=False).status_code == 303


# ---- smaller hardening -----------------------------------------------------------------------------


def test_mqtt_commands_are_opt_in():
    assert MqttConfig().allow_commands is False


def test_flash_cookie_uses_host_prefix_when_secure(tmp_path):
    cfg = Config(
        server=ServerConfig(public_origin=ORIGIN, rp_id="testserver", cookie_secure=True, dev_mode=True),
        gpio=GpioConfig(backend="mock"),
        metrics=MetricsConfig(enabled=False),
        db_path=str(tmp_path / "s.sqlite"),
    )
    from fastapi.testclient import TestClient

    app = create_app(cfg, Core(cfg, sender=lambda u, t, b: True))
    with TestClient(app, base_url=ORIGIN) as c:
        r = c.post("/logout", follow_redirects=False)
        assert "__Host-doorman_flash=" in r.headers["set-cookie"]


def test_admin_resetting_own_password_signs_out_other_devices(env):
    uid, secret = make_admin_with_totp(env)
    other_token, _ = env.core.store.create_session(env.clock.now(), user=env.core.store.user(uid))
    with env.client() as c:
        login(c, "boss", code=pyotp.TOTP(secret).now())
        page = c.get(f"/admin/users/{uid}").text
        c.post(f"/admin/users/{uid}/password", data={"csrf": csrf(page), "password": "another-horse-7"})
        assert c.get("/", follow_redirects=False).status_code == 200  # this device stays signed in
    assert env.core.store.session(other_token, env.clock.now()) is None


# ---- follow-up review ------------------------------------------------------------------------------


def test_ntfy_server_redirect_is_not_followed_to_the_lan():
    """Why ntfy hosts are matched by name: Apprise follows a public server's 307 to anywhere."""
    import http.server

    from doorman.notify import apprise_sender

    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.path)
            if self.path != "/internal":
                self.send_response(307)
                self.send_header("Location", f"http://127.0.0.1:{port}/internal")
            else:
                self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        apprise_sender(f"ntfy://127.0.0.1:{port}/t", "t", "b")
    finally:
        srv.shutdown()
    assert "/internal" in hits  # Apprise really follows it...
    assert notify_urls.problem(f"ntfy://127.0.0.1:{port}/t")  # ...so such URLs are refused


def test_send_test_always_has_a_body(env):
    """Apprise refuses an empty body before sending anything."""
    uid = env.core.store.create_user("fam", PW, "household", env.clock.now())
    env.core.store.set_notify_prefs(uid, {"quiet_hours"}, True, "ntfys://ntfy.sh/fam-topic")
    with env.client() as c:
        login(c, "fam")
        r = c.post("/profile/notifications/test", data={"csrf": _page_csrf(c)})
        assert "Test sent" in r.text
    assert len(env.sent) == 2  # shared webhook (no Discord ID) and the personal URL
    assert all(body.strip() for _, body in env.sent)


def test_lockout_looks_like_a_wrong_password(env):
    env.core.store.create_user("pat", PW, "household", env.clock.now())
    hashed = []
    from doorman.auth import passwords

    real = passwords.verify_secret

    def spy(stored, candidate):
        hashed.append(stored)
        return real(stored, candidate)

    passwords.verify_secret = spy
    try:
        with env.client() as c:
            for _ in range(5):
                login(c, "pat", "nope-nope-nope")
            hashed.clear()
            locked = login(c, "pat", "nope-nope-nope")
            unknown = login(c, "nobody-here", "nope-nope-nope")
    finally:
        passwords.verify_secret = real
    assert locked.status_code == unknown.status_code == 401
    assert re.search(r'role="alert">([^<]*)', locked.text).group(1) == re.search(
        r'role="alert">([^<]*)', unknown.text
    ).group(1)
    assert len(hashed) == 2  # one hash each: the locked account isn't answered faster


def test_openapi_schema_not_published(env):
    with env.client() as c:
        assert c.get("/api/v1/openapi.json").status_code == 404


def test_sign_in_answers_busy_when_hash_queue_is_full(env, monkeypatch):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    monkeypatch.setattr(deps, "_hash_pending", deps.HASH_QUEUE_LIMIT)
    with env.client() as c:
        r = c.post("/login", data={"username": "fam", "password": PW, "next": "/"})
        assert r.status_code == 429
    monkeypatch.setattr(deps, "_hash_pending", 0)
    with env.client() as c:
        assert login(c, "fam").status_code == 200
