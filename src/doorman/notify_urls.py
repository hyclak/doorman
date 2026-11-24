"""Which personal notification URLs users may set.

Apprise can talk to almost anything: ``json://``, ``xml://`` and ``form://`` send an HTTP request
to any host, port and path, with a chosen method. Letting any signed-in user pick one would turn
the Pi into a proxy into the home network (Caddy's admin API, the router, the NAS...). So personal
URLs are limited to services whose destination is fixed by Apprise itself, plus ntfy, whose host
must resolve only to public addresses. The shared webhook comes from the admin's environment and
isn't checked here.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

# Apprise sends these to the provider's own fixed API host; the URL only carries tokens and IDs.
FIXED_SERVICE_SCHEMES = frozenset({"discord", "tgram", "pover", "pbul", "slack"})
# These name their server in the URL, so the host must be a public one.
PUBLIC_HOST_SCHEMES = frozenset({"ntfy", "ntfys"})
# Links copied straight from these services. Apprise only accepts an https:// URL when it
# recognises it as one of its services (it has no generic https sender), and maps these to the
# Discord, Slack and ntfy plugins above.
NATIVE_HTTPS_HOSTS = frozenset({"discord.com", "discordapp.com", "hooks.slack.com", "ntfy.sh"})

ALLOWED_HELP = (
    "Use Discord (discord://), Telegram (tgram://), Pushover (pover://), Pushbullet (pbul://), "
    "Slack (slack://), ntfy on a public server (ntfys://ntfy.sh/your-topic), or a Discord webhook, "
    "Slack webhook or ntfy.sh link."
)


def resolve(host: str) -> list[str]:
    """All addresses ``host`` resolves to (tests replace this)."""
    return [str(info[4][0]) for info in socket.getaddrinfo(host, None)]


def _public(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def problem(url: str) -> str | None:
    """None if ``url`` may be used as a personal notification URL, else a message for the user."""
    url = url.strip()
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in url):
        return "Notification URLs can't contain spaces or control characters."
    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return "That doesn't look like a notification URL."
    scheme = parts.scheme.lower()
    if scheme in FIXED_SERVICE_SCHEMES:
        return None
    if scheme == "https" and host in NATIVE_HTTPS_HOSTS and not parts.port:
        return None
    if scheme not in PUBLIC_HOST_SCHEMES:
        return f"That kind of notification URL isn't allowed. {ALLOWED_HELP}"
    if not host:
        return "Include the ntfy server, e.g. ntfys://ntfy.sh/your-topic."
    try:
        addrs = resolve(host)
    except (OSError, UnicodeError):
        return f"Couldn't find the server {host}. Include the ntfy server, e.g. ntfys://ntfy.sh/your-topic."
    try:
        if not addrs or not all(_public(a) for a in addrs):
            return "Notifications can only go to servers on the public internet."
    except ValueError:
        return "Notifications can only go to servers on the public internet."
    return None
