-- doorman initial schema. Timestamps are ISO-8601 strings with UTC offset.

CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name    TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL CHECK (role IN ('admin', 'household', 'scheduled', 'viewer')),
    password_hash   TEXT NOT NULL,
    totp_secret     TEXT,
    totp_last_step  INTEGER NOT NULL DEFAULT 0,
    discord_user_id TEXT NOT NULL DEFAULT '',
    disabled        INTEGER NOT NULL DEFAULT 0,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

CREATE TABLE passkeys (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    name          TEXT NOT NULL DEFAULT 'Passkey',
    created_at    TEXT NOT NULL,
    last_used_at  TEXT
);

CREATE TABLE guest_links (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label           TEXT NOT NULL DEFAULT '',
    token_hash      TEXT NOT NULL UNIQUE,
    pin_hash        TEXT NOT NULL,
    max_redemptions INTEGER NOT NULL DEFAULT 1,
    redemptions     INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    revoked         INTEGER NOT NULL DEFAULT 0,
    created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL
);

-- Allow windows for scheduled users ('user') and guest links ('link'),
-- and "door should be closed" windows ('quiet', owner_id NULL).
CREATE TABLE windows (
    id          INTEGER PRIMARY KEY,
    owner_type  TEXT NOT NULL CHECK (owner_type IN ('user', 'link', 'quiet')),
    owner_id    INTEGER,
    kind        TEXT NOT NULL CHECK (kind IN ('once', 'daily', 'weekly')),
    start_at    TEXT,
    end_at      TEXT,
    start_time  TEXT,
    end_time    TEXT,
    days        TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
    valid_from  TEXT,
    valid_until TEXT,
    label       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX windows_owner ON windows (owner_type, owner_id);

CREATE TABLE sessions (
    id                TEXT PRIMARY KEY,          -- sha256 of the cookie token
    user_id           INTEGER REFERENCES users(id) ON DELETE CASCADE,
    link_id           INTEGER REFERENCES guest_links(id) ON DELETE CASCADE,
    csrf              TEXT NOT NULL,
    mfa_pending       INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,
    reauth_at         TEXT,
    late_close_until  TEXT,                       -- guest links: close-only permission end
    ip                TEXT NOT NULL DEFAULT '',
    user_agent        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL,                  -- comma separated: read, operate
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE notify_prefs (
    user_id     INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    events      TEXT NOT NULL DEFAULT '',        -- comma separated event types
    use_shared  INTEGER NOT NULL DEFAULT 1,      -- shared Discord webhook (+ mention)
    apprise_url TEXT NOT NULL DEFAULT ''         -- personal destination (any Apprise URL)
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL                          -- JSON
);

CREATE TABLE audit (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    actor_type TEXT NOT NULL,                    -- user, link, api, mqtt, external, system
    actor_id   INTEGER,
    actor_name TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_ts ON audit (ts);
