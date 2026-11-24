"""Sign-in security flows end to end: authenticator app setup, passkey sign-in through the web
endpoints (including stale passkeys), and the reset-mfa recovery command."""

import re

import pyotp
import pytest
from fido2.utils import websafe_decode, websafe_encode

from doorman.__main__ import main as cli
from doorman.auth import totp

from .test_passkeys import SoftAuthenticator
from .test_web import ORIGIN, PW, Env, csrf, login

RP = "testserver"


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def _page_csrf(c, path="/profile"):
    return csrf(c.get(path).text)


def _register_passkey(c, name="Phone"):
    token = _page_csrf(c)
    r = c.post("/profile/passkeys/begin", headers={"X-CSRF-Token": token})
    assert r.status_code == 200, r.text
    auth = SoftAuthenticator()
    cred = auth.create(r.json()["options"], origin=ORIGIN)
    r = c.post(
        "/profile/passkeys/finish",
        json={"handle": r.json()["handle"], "credential": cred, "name": name},
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 200, r.text
    return auth


def _passkey_sign_in(c, auth):
    r = c.post("/login/passkey/begin")
    assert r.status_code == 200, r.text
    begin = r.json()
    return c.post(
        "/login/passkey/finish",
        json={"handle": begin["handle"], "credential": auth.get(begin["options"], rp_id=RP, origin=ORIGIN)},
    )


# ---- authenticator app ---------------------------------------------------------------------------


def test_qr_svg_renders_with_installed_segno():
    svg = totp.qr_svg(totp.provisioning_uri(totp.new_secret(), "alice"))
    assert svg.startswith("<svg") and "#000" in svg


def test_totp_setup_page_renders_and_confirms(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    with env.client() as c:
        login(c, "fam")
        r = c.post("/profile/totp/begin", data={"csrf": _page_csrf(c)})
        assert r.status_code == 200, r.text[:500]
        assert "<svg" in r.text
        secret = re.search(r'<code class="secret">([A-Z2-7]+)</code>', r.text).group(1)
        code = pyotp.TOTP(secret).now()  # doorman checks codes against real time
        r = c.post("/profile/totp/confirm", data={"csrf": csrf(r.text), "code": code})
        assert r.status_code == 200 and "Authenticator app added" in r.text
    assert env.core.store.user_by_name("fam")["totp_secret"] == secret


# ---- passkeys ------------------------------------------------------------------------------------


def test_passkey_sign_in_returns_accepted_credentials(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    with env.client() as c:
        login(c, "fam")
        auth = _register_passkey(c)
    with env.client() as c:
        r = _passkey_sign_in(c, auth)
        assert r.status_code == 200, r.text
        accepted = r.json()["accepted"]
        assert accepted["rpId"] == RP
        assert accepted["allAcceptedCredentialIds"] == [websafe_encode(auth.cred_id)]
        assert websafe_decode(accepted["userId"]).startswith(b"doorman-user-")
        assert c.get("/", follow_redirects=False).status_code == 200


def test_unknown_passkey_is_named_and_signalled(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    stale = SoftAuthenticator()  # e.g. registered on another install with the same site name
    stale.handle = b"doorman-user-1"
    with env.client() as c:
        r = _passkey_sign_in(c, stale)
        assert r.status_code == 400
        body = r.json()
        assert "isn't registered with doorman" in body["detail"]
        assert body["unknown"] == {"rpId": RP, "credentialId": websafe_encode(stale.cred_id)}
        assert c.get("/", follow_redirects=False).status_code == 303  # still signed out


def test_profile_lists_accepted_passkeys_for_the_signal_api(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    with env.client() as c:
        login(c, "fam")
        assert "&#34;allAcceptedCredentialIds&#34;: []" in c.get("/profile").text or (
            '"allAcceptedCredentialIds": []' in c.get("/profile").text
        )
        auth = _register_passkey(c)
        assert websafe_encode(auth.cred_id) in c.get("/profile").text


def test_passkey_from_another_account_is_refused_on_mfa_step(env):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    uid = env.core.store.create_user("boss", PW, "admin", env.clock.now())
    env.core.store.update_user(uid, totp_secret=pyotp.random_base32())
    with env.client() as c:
        login(c, "fam")
        fam_key = _register_passkey(c)
    with env.client() as c:
        r = c.post("/login", data={"username": "boss", "password": PW, "next": "/"})
        assert "/login/mfa" in str(r.url)
        r = _passkey_sign_in(c, fam_key)
        assert r.status_code == 400 and "different account" in r.json()["detail"]
        assert "unknown" not in r.json()


# ---- recovery ------------------------------------------------------------------------------------


def test_reset_mfa_removes_factors_and_sessions(env, tmp_path, capsys):
    env.core.store.create_user("fam", PW, "household", env.clock.now())
    with env.client() as c:
        login(c, "fam")
        _register_passkey(c)
    uid = env.core.store.user_by_name("fam")["id"]
    env.core.store.update_user(uid, totp_secret=pyotp.random_base32())
    assert env.core.store.user_sessions(uid)

    conf = tmp_path / "cli.toml"
    conf.write_text(f'db_path = "{env.core.cfg.db_path}"\n\n[server]\ndev_mode = true\n')
    cli(["--config", str(conf), "reset-mfa", "fam"])

    u = env.core.store.user_by_name("fam")
    assert not u["totp_secret"] and not env.core.store.passkeys(uid)
    assert not env.core.store.user_sessions(uid)
    assert "Removed 1 passkey(s)" in capsys.readouterr().out
