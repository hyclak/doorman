"""Data access for users, sessions, windows, guest links, passkeys, API tokens, prefs and audit.

Writes happen only on real events (logins, settings changes, door actions), keeping SD-card
wear low. Session "last seen" updates are throttled for the same reason.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from doorman.auth import passwords, tokens
from doorman.db import Database
from doorman.schedules import Window, from_row, next_midnight, to_params

ROLES = ("admin", "household", "scheduled", "viewer")
ROLE_LABELS = {
    "admin": "Admin",
    "household": "Household",
    "scheduled": "Scheduled",
    "viewer": "Viewer",
}
ROLE_HELP = {
    "admin": "Manages users, schedules, links and settings. Can always operate the door.",
    "household": "Can operate the door any time.",
    "scheduled": "Can operate the door only inside their access windows.",
    "viewer": "Sees door status and stats, never operates it.",
}
SESSION_DAYS = {"admin": 30, "household": 90, "scheduled": 90, "viewer": 90}
MFA_PENDING_MINUTES = 10
LAST_SEEN_THROTTLE = timedelta(minutes=10)
MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)
MAX_PIN_ATTEMPTS = 5
AUDIT_RETENTION_DAYS = 90


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def parse(v: str | None) -> datetime | None:
    return datetime.fromisoformat(v) if v else None


@dataclass(frozen=True)
class Session:
    id: str
    user_id: int | None
    link_id: int | None
    csrf: str
    mfa_pending: bool
    created_at: datetime
    expires_at: datetime
    last_seen_at: datetime
    reauth_at: datetime | None
    late_close_until: datetime | None
    ip: str
    user_agent: str

    @classmethod
    def from_row(cls, r: sqlite3.Row) -> Session:
        return cls(
            id=r["id"],
            user_id=r["user_id"],
            link_id=r["link_id"],
            csrf=r["csrf"],
            mfa_pending=bool(r["mfa_pending"]),
            created_at=datetime.fromisoformat(r["created_at"]),
            expires_at=datetime.fromisoformat(r["expires_at"]),
            last_seen_at=datetime.fromisoformat(r["last_seen_at"]),
            reauth_at=parse(r["reauth_at"]),
            late_close_until=parse(r["late_close_until"]),
            ip=r["ip"],
            user_agent=r["user_agent"],
        )


class Store:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- users --------------------------------------------------------------------------------

    def create_user(
        self, username: str, password: str, role: str, now: datetime, display_name: str = ""
    ) -> int:
        username = username.strip()
        if not username or len(username) > 64 or not all(c.isalnum() or c in "._-" for c in username):
            raise ValueError("Usernames use letters, numbers, dots, dashes and underscores.")
        if role not in ROLES:
            raise ValueError("Unknown role.")
        if problem := passwords.password_problem(password, username):
            raise ValueError(problem)
        if self.user_by_name(username):
            raise ValueError("That username is taken.")
        return self.db.insert(
            "INSERT INTO users(username, display_name, role, password_hash, created_at) VALUES(?,?,?,?,?)",
            (username, display_name.strip(), role, passwords.hash_secret(password), iso(now)),
        )

    def user(self, user_id: int) -> sqlite3.Row | None:
        return self.db.one("SELECT * FROM users WHERE id = ?", (user_id,))

    def user_by_name(self, username: str) -> sqlite3.Row | None:
        return self.db.one("SELECT * FROM users WHERE username = ?", (username.strip(),))

    def users(self) -> list[sqlite3.Row]:
        return self.db.query(
            "SELECT u.*, (SELECT COUNT(*) FROM passkeys p WHERE p.user_id = u.id) AS passkey_count "
            "FROM users u ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'household' THEN 1 "
            "WHEN 'scheduled' THEN 2 ELSE 3 END, username"
        )

    def update_user(self, user_id: int, **fields: Any) -> None:
        allowed = {"display_name", "role", "discord_user_id", "disabled", "totp_secret", "totp_last_step"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"Can't update {bad}")
        if "role" in fields and fields["role"] not in ROLES:
            raise ValueError("Unknown role.")
        if "discord_user_id" in fields:
            v = str(fields["discord_user_id"]).strip()
            if v and not v.isdigit():
                raise ValueError("A Discord user ID is a long number (Developer Mode → Copy User ID).")
            fields["discord_user_id"] = v
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.db.execute(f"UPDATE users SET {cols} WHERE id = ?", (*fields.values(), user_id))

    def set_password(self, user_id: int, password: str) -> None:
        u = self.user(user_id)
        assert u is not None
        if problem := passwords.password_problem(password, u["username"]):
            raise ValueError(problem)
        self.db.execute(
            "UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL WHERE id = ?",
            (passwords.hash_secret(password), user_id),
        )

    def delete_user(self, user_id: int) -> None:
        with self.db.transaction() as c:
            c.execute(
                "DELETE FROM windows WHERE owner_type = 'link' AND owner_id IN "
                "(SELECT id FROM guest_links WHERE user_id = ?)",
                (user_id,),
            )
            c.execute("DELETE FROM windows WHERE owner_type = 'user' AND owner_id = ?", (user_id,))
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))

    def admin_count(self, exclude: int | None = None) -> int:
        row = self.db.one(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0 AND id IS NOT ?",
            (exclude,),
        )
        return int(row["n"]) if row else 0

    def check_login(self, username: str, password: str, now: datetime) -> tuple[sqlite3.Row | None, str]:
        """Verify a password. Returns (user, error). Applies the per-account lockout."""
        u = self.user_by_name(username)
        if u is None:
            passwords.verify_secret(None, password)  # equalize timing
            return None, "Wrong username or password."
        locked = parse(u["locked_until"])
        if locked and locked > now:
            return None, "Too many failed attempts. Try again later."
        if not passwords.verify_secret(u["password_hash"], password):
            failed = u["failed_logins"] + 1
            lock = iso(now + LOCKOUT) if failed >= MAX_FAILED_LOGINS else None
            self.db.execute(
                "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                (0 if lock else failed, lock, u["id"]),
            )
            if lock:
                return None, "locked"
            return None, "Wrong username or password."
        if u["disabled"]:
            return None, "This account is disabled."
        if passwords.needs_rehash(u["password_hash"]):
            self.db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?", (passwords.hash_secret(password), u["id"])
            )
        return u, ""

    def record_login(self, user_id: int, now: datetime) -> None:
        self.db.execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
            (iso(now), user_id),
        )

    # ---- windows ------------------------------------------------------------------------------

    def windows(self, owner_type: str, owner_id: int | None = None) -> list[Window]:
        rows = self.db.query(
            "SELECT * FROM windows WHERE owner_type = ? AND owner_id IS ? ORDER BY id", (owner_type, owner_id)
        )
        return [from_row(r) for r in rows]

    def add_window(self, owner_type: str, owner_id: int | None, w: Window) -> int:
        p = to_params(w)
        return self.db.insert(
            "INSERT INTO windows(owner_type, owner_id, kind, start_at, end_at, start_time, end_time, days, "
            "valid_from, valid_until, label) VALUES(:ot, :oid, :kind, :start_at, :end_at, :start_time, "
            ":end_time, :days, :valid_from, :valid_until, :label)",
            {"ot": owner_type, "oid": owner_id, **p},
        )

    def delete_window(self, window_id: int, owner_type: str, owner_id: int | None) -> None:
        self.db.execute(
            "DELETE FROM windows WHERE id = ? AND owner_type = ? AND owner_id IS ?",
            (window_id, owner_type, owner_id),
        )

    # ---- passkeys -----------------------------------------------------------------------------

    def passkeys(self, user_id: int) -> list[sqlite3.Row]:
        return self.db.query("SELECT * FROM passkeys WHERE user_id = ? ORDER BY id", (user_id,))

    def passkey_by_credential(self, credential_id: bytes) -> sqlite3.Row | None:
        return self.db.one("SELECT * FROM passkeys WHERE credential_id = ?", (credential_id,))

    def add_passkey(
        self, user_id: int, credential_id: bytes, public_key: bytes, sign_count: int, name: str, now: datetime
    ) -> int:
        return self.db.insert(
            "INSERT INTO passkeys(user_id, credential_id, public_key, sign_count, name, created_at) "
            "VALUES(?,?,?,?,?,?)",
            (user_id, credential_id, public_key, sign_count, name.strip()[:60] or "Passkey", iso(now)),
        )

    def touch_passkey(self, passkey_id: int, sign_count: int, now: datetime) -> None:
        self.db.execute(
            "UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?",
            (sign_count, iso(now), passkey_id),
        )

    def delete_passkey(self, passkey_id: int, user_id: int) -> None:
        self.db.execute("DELETE FROM passkeys WHERE id = ? AND user_id = ?", (passkey_id, user_id))

    def has_second_factor(self, user: sqlite3.Row) -> bool:
        return bool(user["totp_secret"]) or bool(self.passkeys(user["id"]))

    # ---- sessions -----------------------------------------------------------------------------

    def create_session(
        self,
        now: datetime,
        *,
        user: sqlite3.Row | None = None,
        link_id: int | None = None,
        expires_at: datetime | None = None,
        mfa_pending: bool = False,
        late_close_until: datetime | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> tuple[str, Session]:
        token = tokens.new_token()
        if expires_at is None:
            if mfa_pending:
                expires_at = now + timedelta(minutes=MFA_PENDING_MINUTES)
            else:
                assert user is not None
                expires_at = now + timedelta(days=SESSION_DAYS[user["role"]])
        self.db.execute(
            "INSERT INTO sessions(id, user_id, link_id, csrf, mfa_pending, created_at, expires_at, "
            "last_seen_at, reauth_at, late_close_until, ip, user_agent) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                tokens.digest(token),
                user["id"] if user is not None else None,
                link_id,
                tokens.new_token(16),
                int(mfa_pending),
                iso(now),
                iso(expires_at),
                iso(now),
                None if mfa_pending else iso(now),
                iso(late_close_until),
                ip[:64],
                user_agent[:200],
            ),
        )
        s = self.session(token, now)
        assert s is not None
        return token, s

    def session(self, token: str, now: datetime) -> Session | None:
        row = self.db.one("SELECT * FROM sessions WHERE id = ?", (tokens.digest(token),))
        if row is None:
            return None
        s = Session.from_row(row)
        if s.expires_at <= now:
            self.db.execute("DELETE FROM sessions WHERE id = ?", (s.id,))
            return None
        return s

    def touch_session(self, s: Session, now: datetime, role: str | None) -> None:
        """Throttled last-seen update; slides the expiry for non-admin user sessions."""
        if now - s.last_seen_at < LAST_SEEN_THROTTLE:
            return
        expires = s.expires_at
        if role and role != "admin" and not s.mfa_pending and s.link_id is None:
            expires = max(expires, now + timedelta(days=SESSION_DAYS[role]))
        self.db.execute(
            "UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?",
            (iso(now), iso(expires), s.id),
        )

    def complete_mfa(self, s: Session, user: sqlite3.Row, now: datetime) -> None:
        self.db.execute(
            "UPDATE sessions SET mfa_pending = 0, reauth_at = ?, expires_at = ? WHERE id = ?",
            (iso(now), iso(now + timedelta(days=SESSION_DAYS[user["role"]])), s.id),
        )

    def mark_reauth(self, s: Session, now: datetime) -> None:
        self.db.execute("UPDATE sessions SET reauth_at = ? WHERE id = ?", (iso(now), s.id))

    def delete_session(self, session_id: str) -> None:
        self.db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))

    def delete_user_sessions(self, user_id: int, except_id: str | None = None) -> None:
        self.db.execute("DELETE FROM sessions WHERE user_id = ? AND id IS NOT ?", (user_id, except_id))

    def user_sessions(self, user_id: int) -> list[Session]:
        rows = self.db.query(
            "SELECT * FROM sessions WHERE user_id = ? AND mfa_pending = 0 ORDER BY last_seen_at DESC",
            (user_id,),
        )
        return [Session.from_row(r) for r in rows]

    def purge_expired_sessions(self, now: datetime) -> None:
        self.db.execute("DELETE FROM sessions WHERE expires_at <= ?", (iso(now),))

    # ---- guest links --------------------------------------------------------------------------

    def create_link(
        self,
        user_id: int,
        label: str,
        window: Window,
        now: datetime,
        created_by: int | None,
        max_redemptions: int = 1,
        pin: str | None = None,
    ) -> tuple[int, str, str]:
        """Returns (link_id, token, pin). The token and PIN are shown once and never stored."""
        token = tokens.new_token(24)
        pin = pin or tokens.new_pin(6)
        if not (pin.isdigit() and 4 <= len(pin) <= 8):
            raise ValueError("PINs are 4 to 8 digits.")
        if not 1 <= max_redemptions <= 20:
            raise ValueError("Devices must be between 1 and 20.")
        with self.db.transaction() as c:
            cur = c.execute(
                "INSERT INTO guest_links(user_id, label, token_hash, pin_hash, max_redemptions, created_by, "
                "created_at) VALUES(?,?,?,?,?,?,?)",
                (
                    user_id,
                    label.strip()[:80],
                    tokens.digest(token),
                    passwords.hash_secret(pin),
                    max_redemptions,
                    created_by,
                    iso(now),
                ),
            )
            link_id = cur.lastrowid
            assert link_id is not None
            p = to_params(window)
            c.execute(
                "INSERT INTO windows(owner_type, owner_id, kind, start_at, end_at, start_time, end_time, "
                "days, valid_from, valid_until, label) VALUES('link', :oid, :kind, :start_at, :end_at, "
                ":start_time, :end_time, :days, :valid_from, :valid_until, :label)",
                {"oid": link_id, **p},
            )
        return link_id, token, pin

    def link(self, link_id: int) -> sqlite3.Row | None:
        return self.db.one(
            "SELECT l.*, u.username, u.display_name, u.disabled AS user_disabled FROM guest_links l "
            "JOIN users u ON u.id = l.user_id WHERE l.id = ?",
            (link_id,),
        )

    def link_by_token(self, token: str) -> sqlite3.Row | None:
        row = self.db.one("SELECT id FROM guest_links WHERE token_hash = ?", (tokens.digest(token),))
        return self.link(row["id"]) if row else None

    def links(self) -> list[sqlite3.Row]:
        return self.db.query(
            "SELECT l.*, u.username, u.display_name FROM guest_links l JOIN users u ON u.id = l.user_id "
            "ORDER BY l.created_at DESC"
        )

    def link_problem(self, link: sqlite3.Row) -> str | None:
        if link["revoked"]:
            return "This link has been turned off."
        if link["user_disabled"]:
            return "This link's account is disabled."
        if link["failed_attempts"] >= MAX_PIN_ATTEMPTS:
            return "This link is locked after too many wrong PINs. Ask for a new one."
        if link["redemptions"] >= link["max_redemptions"]:
            return "This link has already been used on another device. Ask for a new one."
        return None

    def redeem_link(self, link: sqlite3.Row, pin: str) -> tuple[bool, bool]:
        """Check the PIN. Returns (ok, now_locked)."""
        if passwords.verify_secret(link["pin_hash"], pin.strip()):
            self.db.execute(
                "UPDATE guest_links SET redemptions = redemptions + 1 WHERE id = ?", (link["id"],)
            )
            return True, False
        self.db.execute(
            "UPDATE guest_links SET failed_attempts = failed_attempts + 1 WHERE id = ?", (link["id"],)
        )
        return False, link["failed_attempts"] + 1 >= MAX_PIN_ATTEMPTS

    def revoke_link(self, link_id: int) -> None:
        with self.db.transaction() as c:
            c.execute("UPDATE guest_links SET revoked = 1 WHERE id = ?", (link_id,))
            c.execute("DELETE FROM sessions WHERE link_id = ?", (link_id,))

    def delete_link(self, link_id: int) -> None:
        with self.db.transaction() as c:
            c.execute("DELETE FROM windows WHERE owner_type = 'link' AND owner_id = ?", (link_id,))
            c.execute("DELETE FROM guest_links WHERE id = ?", (link_id,))

    @staticmethod
    def late_close_until(occurrence_end: datetime, now: datetime) -> datetime:
        return max(next_midnight(now), occurrence_end)

    # ---- API tokens ---------------------------------------------------------------------------

    def create_api_token(self, name: str, scopes: set[str], now: datetime) -> str:
        scopes = scopes & {"read", "operate"} or {"read"}
        if not name.strip():
            raise ValueError("Give the token a name, e.g. Home Assistant.")
        token = "dm_" + tokens.new_token(32)
        self.db.insert(
            "INSERT INTO api_tokens(name, token_hash, scopes, created_at) VALUES(?,?,?,?)",
            (name.strip()[:60], tokens.digest(token), ",".join(sorted(scopes)), iso(now)),
        )
        return token

    def api_token(self, token: str, now: datetime) -> sqlite3.Row | None:
        row = self.db.one(
            "SELECT * FROM api_tokens WHERE token_hash = ? AND revoked = 0", (tokens.digest(token),)
        )
        if row is not None:
            last = parse(row["last_used_at"])
            if last is None or now - last > LAST_SEEN_THROTTLE:
                self.db.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (iso(now), row["id"]))
        return row

    def api_tokens(self) -> list[sqlite3.Row]:
        return self.db.query("SELECT * FROM api_tokens WHERE revoked = 0 ORDER BY created_at DESC")

    def revoke_api_token(self, token_id: int) -> None:
        self.db.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ?", (token_id,))

    # ---- notification preferences -------------------------------------------------------------

    def notify_prefs(self, user_id: int) -> sqlite3.Row | None:
        return self.db.one("SELECT * FROM notify_prefs WHERE user_id = ?", (user_id,))

    def set_notify_prefs(self, user_id: int, events: set[str], use_shared: bool, apprise_url: str) -> None:
        apprise_url = apprise_url.strip()
        if apprise_url and "://" not in apprise_url:
            raise ValueError("That doesn't look like a notification URL.")
        self.db.execute(
            "INSERT INTO notify_prefs(user_id, events, use_shared, apprise_url) VALUES(?,?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET events = excluded.events, use_shared = excluded.use_shared, "
            "apprise_url = excluded.apprise_url",
            (user_id, ",".join(sorted(events)), int(use_shared), apprise_url),
        )

    # ---- audit --------------------------------------------------------------------------------

    def audit(
        self,
        now: datetime,
        actor_type: str,
        actor_name: str,
        action: str,
        detail: dict[str, Any] | str = "",
        actor_id: int | None = None,
        ip: str = "",
    ) -> None:
        if isinstance(detail, dict):
            detail = json.dumps(detail, separators=(",", ":"), default=str)
        self.db.execute(
            "INSERT INTO audit(ts, actor_type, actor_id, actor_name, action, detail, ip) "
            "VALUES(?,?,?,?,?,?,?)",
            (iso(now), actor_type, actor_id, actor_name, action, detail, ip),
        )

    def audit_rows(self, limit: int = 200, offset: int = 0, action_prefix: str = "") -> list[sqlite3.Row]:
        return self.db.query(
            "SELECT * FROM audit WHERE action LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (action_prefix + "%", limit, offset),
        )

    def prune_audit(self, now: datetime) -> int:
        cur = self.db.execute(
            "DELETE FROM audit WHERE ts < ?", (iso(now - timedelta(days=AUDIT_RETENTION_DAYS)),)
        )
        return cur.rowcount
