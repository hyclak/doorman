# doorman

A self-hosted garage door controller for a Raspberry Pi: one relay, one reed switch, and a web app
that is safe to put on the internet.

- **Accounts and roles**: Admin, Household, Scheduled and Viewer. Access is denied by default, and
  Scheduled users can operate the door only inside their allow windows (one-off, daily or weekly).
- **Guest links**: a one-time URL plus a PIN, tied to a user and a time block. A guest who signed in
  during the window can still close the door until midnight.
- **Sign-in**: argon2id passwords, optional passkeys (WebAuthn), and TOTP. Admins must have a second
  factor, and changing settings requires signing in again.
- **Door control**: a state-aware button (Open / Close / Crack open) with press-and-hold to confirm
  opening. States are inferred from the reed switch plus timing: Closed, Opening, Open, Closing,
  Partly open, Check door. Movement from the wall button or remote is shown as such.
- **Alerts**: quiet hours (first alert, reminders every *n* minutes, stop after a count or a time),
  door open too long, CPU temperature, under-voltage, and missed backups. Delivered through Discord
  via [Apprise](https://github.com/caronc/apprise), with per-user preferences. doorman never closes
  the door automatically.
- **Integrations**: Pi health stats, Prometheus `/metrics`, JSON logs for Loki, a bearer-token REST
  API, and optional MQTT with Home Assistant discovery.
- **Layout**: works on phones first and scales up to desktop browsers. Installable as a home-screen
  app.

Everything needed to open and close the door runs on the Pi. Nothing depends on another server.

## Hardware

| Signal | BCM pin | Notes |
| --- | --- | --- |
| Relay | 7 | Open-drain style by default: drive low to press, switch back to input to release |
| Reed switch | 18 | Reads 0 when the door is closed |

The pins, polarity, pull resistor and relay mode can all be changed in the `[gpio]` config section.

## Development (macOS or Linux)

Requires Python 3.13. The mock GPIO backend simulates a door, so no Pi is needed.

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -r requirements/dev.txt -e .
```

```bash
.venv/bin/python scripts/dev_seed.py dev/doorman.sqlite
```

```bash
.venv/bin/doorman --config dev.toml serve
```

Open http://localhost:8000. The seed script creates `admin`, `family` (household), `walker`
(scheduled, 11 AM–1 PM daily) and `viewer`, all with the password `correct-horse-1`. The admin
account has a TOTP secret, and the seed script prints it. Get a current code with:

```bash
.venv/bin/python -c "import pyotp; print(pyotp.TOTP('JBSWY3DPEHPK3PXP').now())"
```

In dev mode the door page has buttons to set the simulated reed switch.

Checks (the same ones CI runs):

```bash
.venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests && .venv/bin/mypy && .venv/bin/pytest
```

## Production

doorman targets **Raspberry Pi OS 13 (trixie)**. Runtime dependencies come from Debian packages
(`requirements/apt.txt`). The virtualenv is created with `--system-site-packages`, and only
`apprise` is installed from PyPI, with `--no-deps`. This avoids compiling Rust or C extensions on
ARMv6.

Deployment is handled by an Ansible role (`app_doorman`) kept in a separate repository. It
installs the wheel from a GitHub release, writes `/etc/doorman/doorman.toml` (see
[doorman.example.toml](doorman.example.toml)) and `/etc/doorman/secrets.env`, and runs:

- `doorman serve --json-logs` under systemd as the `doorman` user, with hardening and the watchdog;
- Caddy in front of it for TLS (Route53 DNS-01) on a public port, plus a LAN-only listener for `/metrics`;
- a nightly SQLite backup (`doorman backup`) pushed to the NAS.

Useful commands on the Pi. The role installs `/usr/local/bin/doorman`, a wrapper that runs the CLI
as the service does (the `doorman` user, plus its config, secrets and working directory):

```bash
sudo doorman create-admin <username>
```

```bash
sudo doorman set-password <username>
```

If someone loses their passkey or authenticator app, this removes both and signs them out. They
can then sign in with their password and add new ones:

```bash
sudo doorman reset-mfa <username>
```

```bash
sudo doorman config-check
```

```bash
sudo doorman version
```

### Upgrade notes

- **MQTT commands are off by default.** `mqtt.allow_commands` now defaults to `false`. MQTT commands
  skip schedules and sign-in, so anyone who can publish to `<base_topic>/door/set` can operate the
  door. If Home Assistant operates the door over MQTT, set `allow_commands = true` explicitly, and
  restrict that topic with broker ACLs (and preferably TLS).
- **Alerts go to Admin and Household accounts only.** Viewer and Scheduled accounts no longer see
  notification settings or receive alerts, including any they set up before. Security alerts
  remain admin-only.
- **Personal notification URLs are limited** to Discord, Telegram, Pushover, Pushbullet, Slack and
  ntfy.sh (plus Discord/Slack webhook and ntfy.sh links). Other kinds, including email, generic
  `json://`/`form://` webhooks and self-hosted ntfy servers, are refused when saved and skipped
  when sending. The shared Discord webhook is unaffected.
- **Passkeys** used on their own (without a password) must verify the person with a PIN or
  biometric. A security key without a PIN still works as the second step after a password.
- **Caddy's admin API** should not listen on TCP: set `admin unix//run/caddy/admin.sock` (or
  `admin off`) in the Caddyfile's global options.

### Releases

Pushing a `v*` tag builds the wheel and a Caddy binary for `linux/arm/v6` with the Route53 DNS
module, and attaches both to a GitHub release along with SHA-256 checksums. The release fails if
the tag doesn't match the package version.

Each PR adds its user-visible changes under **Unreleased** in [CHANGELOG.md](CHANGELOG.md). To
release:

1. In a PR, set `__version__` in `src/doorman/__init__.py`. This is the only place the version is
   set, and `pyproject.toml` reads it from there. Use a patch bump for fixes, a minor bump for new
   features or changed defaults.
2. In the same PR, rename **Unreleased** in the changelog to the new version and date, add a fresh
   empty **Unreleased** heading, and update the comparison links at the bottom.
3. Merge, then tag `main` and push the tag:

   ```bash
   git checkout main && git pull && git tag vX.Y.Z && git push origin vX.Y.Z
   ```

4. To deploy, set `app_doorman__version` in Ansible to the new version and run the role.

## REST API

Create a token under **Admin → API tokens** with the `read` and/or `operate` scope, then:

```bash
curl -H "Authorization: Bearer dm_..." https://door.example.com:8443/api/v1/status
```

```bash
curl -X POST -H "Authorization: Bearer dm_..." https://door.example.com:8443/api/v1/door/close
```

`POST /api/v1/door/{open,close,crack}` goes through the same access checks, audit log and
cooldown as the web UI. `GET /api/v1/health` needs no token.

## License

MIT
