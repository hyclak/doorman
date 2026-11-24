# Changelog

Notable changes to doorman. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/). Add an entry under **Unreleased**
in the same PR as the change; it is renamed to the version when releasing (see the README).

## [Unreleased]

### Changed
- The README shows the door page on a desktop browser and a phone, in light and dark mode.

## [0.3.0] - 2026-11-24

### Added
- This changelog. Each PR adds its changes under Unreleased.
- CI fails when the package version has no dated changelog entry (`python scripts/changelog.py check`).
- GitHub releases use the version's changelog entry as their release notes.
- A release checklist in the README.

### Changed
- The package version is set only in `src/doorman/__init__.py`. `pyproject.toml` reads it from there.

## [0.2.1] - 2026-11-24

### Added
- `doorman version` prints the installed version. It works without a config file or secrets.

### Changed
- The example config and README use placeholder hostnames and addresses.
- The example config's `reed_pull` is now `"none"`, with a note on when to use it. `"as-is"` left the
  boot pull-down on, so a reed switch with an external resistor always read as closed.

## [0.2.0] - 2026-11-24

### Security
- Personal notification URLs are limited to fixed-destination services (Discord, Telegram,
  Pushover, Pushbullet, Slack) and ntfy.sh. The check runs on save and again on send. Before this,
  any signed-in user could make the Pi send HTTP requests into the LAN.
- Passkeys used without a password must verify the person with a PIN or biometric.
- Adding or removing a passkey or authenticator app needs a sign-in in the last 10 minutes and raises
  a Security alert.
- Fixed an open redirect after passkey sign-in.
- A locked account answers exactly like a wrong password, so usernames can't be discovered.
- Rate limits keep per-account counters separately and key IPv6 addresses by /64. Sign-in answers
  429 when too many password hashes are queued.
- The OpenAPI schema is no longer published.

### Changed
- Alerts go to Admin and Household accounts only. Security alerts are admin-only.
- **Breaking:** `mqtt.allow_commands` defaults to `false`. Set it to `true` explicitly if Home
  Assistant operates the door over MQTT, and restrict the topic with broker ACLs.
- Password hashing runs on its own worker thread, so the door monitor stays responsive.

### Fixed
- "Send test" for notifications always failed, because Apprise refuses an empty message.

## [0.1.1] - 2026-11-24

### Added
- `doorman reset-mfa <username>` removes a user's passkeys and authenticator app and signs them out.
- Passkey autofill on the sign-in page.

### Fixed
- The authenticator app setup page returned a 500 error.
- Stale passkeys offered by password managers now get a clear error, and password managers are told
  which passkeys are still valid.

## [0.1.0] - 2026-11-21

First release.

[Unreleased]: https://github.com/hyclak/doorman/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/hyclak/doorman/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/hyclak/doorman/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/hyclak/doorman/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/hyclak/doorman/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hyclak/doorman/releases/tag/v0.1.0
