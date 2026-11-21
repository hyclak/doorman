"""Create a throwaway dev database with one user per role (development only).

Usage: .venv/bin/python scripts/dev_seed.py dev/doorman.sqlite
Every account's password is "correct-horse-1". The admin gets a TOTP secret printed below
(admins must have a second factor); `python -c "import pyotp; print(pyotp.TOTP('<secret>').now())"`
prints a current code.
"""

from __future__ import annotations

import sys
from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

from doorman.db import Database
from doorman.schedules import ALL_DAYS, Window
from doorman.store import Store

PASSWORD = "correct-horse-1"  # noqa: S105 - dev-only seed value


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "dev/doorman.sqlite")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        sys.exit(f"{path} already exists; delete it first.")
    db = Database(str(path))
    db.migrate()
    store = Store(db)
    now = datetime.now(ZoneInfo("America/New_York"))
    ids = {}
    for name, role, display in [
        ("admin", "admin", "Admin"),
        ("family", "household", "Family member"),
        ("walker", "scheduled", "Dog walker"),
        ("viewer", "viewer", "Viewer"),
    ]:
        ids[name] = store.create_user(name, PASSWORD, role, now, display)
    secret = "JBSWY3DPEHPK3PXP"  # dev-only, well-known example secret
    store.update_user(ids["admin"], totp_secret=secret)
    store.add_window("user", ids["walker"], Window("daily", start_time=time(11), end_time=time(13)))
    store.add_window("quiet", None, Window("weekly", start_time=time(21), end_time=time(6), days=ALL_DAYS))
    print(f"Seeded {path}. Password for every user: {PASSWORD}. Admin TOTP secret: {secret}")


if __name__ == "__main__":
    main()
