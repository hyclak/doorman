"""doorman command line: serve, create-admin, set-password, backup, config-check."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
from datetime import UTC, datetime

from doorman import __version__


class JsonFormatter(logging.Formatter):
    """One JSON object per line on stdout → journald → rsyslog → Loki."""

    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False)


def setup_logging(json_logs: bool) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter() if json_logs else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def _password(prompt: str = "Password: ") -> str:
    pw = getpass.getpass(prompt)
    if pw != getpass.getpass("Again: "):
        sys.exit("Passwords don't match.")
    return pw


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="doorman", description="Garage door controller")
    ap.add_argument(
        "--config", help="path to doorman.toml (default: $DOORMAN_CONFIG or /etc/doorman/doorman.toml)"
    )
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the web app")
    s.add_argument("--json-logs", action="store_true", help="log JSON lines (production)")
    c = sub.add_parser("create-admin", help="create an admin account")
    c.add_argument("username")
    p = sub.add_parser("set-password", help="set a user's password (recovery)")
    p.add_argument("username")
    b = sub.add_parser("backup", help="write a consistent snapshot of the database")
    b.add_argument("dest")
    sub.add_parser("config-check", help="validate the configuration and exit")
    args = ap.parse_args(argv)

    from doorman.config import load_config

    cfg = load_config(args.config)

    if args.cmd == "config-check":
        print(
            f"OK: gpio={cfg.gpio.backend} relay=BCM{cfg.gpio.relay_pin} reed=BCM{cfg.gpio.reed_pin} "
            f"origin={cfg.server.public_origin} db={cfg.db_path}"
        )
        return

    if args.cmd == "serve":
        setup_logging(args.json_logs)
        import uvicorn

        from doorman.web.app import create_app

        uvicorn.run(
            create_app(cfg),
            host=cfg.server.host,
            port=cfg.server.port,
            proxy_headers=False,
            server_header=False,
            log_config=None,
            access_log=False,
        )
        return

    from doorman.clock import Clock
    from doorman.db import Database
    from doorman.store import Store

    db = Database(cfg.db_path)
    db.migrate()
    store = Store(db)
    now = Clock(cfg.timezone).now()

    if args.cmd == "create-admin":
        try:
            store.create_user(args.username, _password(), "admin", now)
        except ValueError as e:
            sys.exit(str(e))
        store.audit(now, "system", "cli", "admin.user_created", {"username": args.username, "role": "admin"})
        print(f"Created admin {args.username}. Sign in and add a passkey or authenticator app.")
    elif args.cmd == "set-password":
        u = store.user_by_name(args.username)
        if u is None:
            sys.exit("No such user.")
        try:
            store.set_password(u["id"], _password("New password: "))
        except ValueError as e:
            sys.exit(str(e))
        store.delete_user_sessions(u["id"])
        store.audit(now, "system", "cli", "admin.password_reset", {"user": args.username})
        print("Password set; existing sessions signed out.")
    elif args.cmd == "backup":
        db.backup_to(args.dest)
        print(f"Wrote {args.dest}")


if __name__ == "__main__":
    main()
