"""Which personal notification URLs users may set.

Apprise can talk to almost anything: ``json://``, ``xml://`` and ``form://`` send an HTTP request
to any host, port and path, with a chosen method. Letting any signed-in user pick one would turn
the Pi into a proxy into the home network (Caddy's admin API, the router, the NAS...). So personal
URLs are limited to services whose destination is fixed: either by Apprise itself, or (for ntfy,
which names its server in the URL) by requiring the public ntfy.sh server.

Checking that a user-chosen host *resolves* to a public address is not enough: Apprise follows
HTTP redirects (a public server can answer 307 to 127.0.0.1), and DNS can answer differently when
Apprise resolves the name again to send. So hosts are matched by name, never by address. The
shared webhook comes from the admin's environment and isn't checked here.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

# Apprise sends these to the provider's own fixed API host; the URL only carries tokens and IDs.
FIXED_SERVICE_SCHEMES = frozenset({"discord", "tgram", "pover", "pbul", "slack"})
# ntfy names its server in the URL; only the public ntfy.sh service is allowed.
NTFY_SCHEMES = frozenset({"ntfy", "ntfys"})
NTFY_HOSTS = frozenset({"ntfy.sh"})
# Links copied straight from these services. Apprise only accepts an https:// URL when it
# recognises it as one of its services (it has no generic https sender), and maps these to the
# Discord, Slack and ntfy plugins.
NATIVE_HTTPS_HOSTS = frozenset({"discord.com", "discordapp.com", "hooks.slack.com", "ntfy.sh"})

ALLOWED_HELP = (
    "Use Discord (discord://), Telegram (tgram://), Pushover (pover://), Pushbullet (pbul://), "
    "Slack (slack://), ntfy.sh (ntfys://ntfy.sh/your-topic), or a Discord webhook, "
    "Slack webhook or ntfy.sh link."
)


def problem(url: str) -> str | None:
    """None if ``url`` may be used as a personal notification URL, else a message for the user."""
    url = url.strip()
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in url) or "\\" in url:
        return "Notification URLs can't contain spaces, backslashes or control characters."
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".")
        port = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return "That doesn't look like a notification URL."
    # Apprise's "redirect" option makes it follow HTTP redirects, which could lead anywhere.
    if any(k.lower() == "redirect" for k, _ in parse_qsl(parts.query, keep_blank_values=True)):
        return "Notification URLs can't set the redirect option."
    scheme = parts.scheme.lower()
    if scheme in FIXED_SERVICE_SCHEMES:
        return None
    if scheme == "https" and host in NATIVE_HTTPS_HOSTS and port is None:
        return None
    if scheme in NTFY_SCHEMES:
        if host in NTFY_HOSTS and port is None:
            return None
        return "ntfy notifications can only use the public ntfy.sh server, e.g. ntfys://ntfy.sh/your-topic."
    return f"That kind of notification URL isn't allowed. {ALLOWED_HELP}"
