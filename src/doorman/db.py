"""Tiny SQLite wrapper with numbered-SQL migrations.

One connection shared across threads behind a lock: the app is a single process with
light traffic, and this keeps memory and SD-card writes low on the Pi Zero.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Any


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
            self._conn.execute("PRAGMA busy_timeout = 5000")

    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def query(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            row: sqlite3.Row | None = self._conn.execute(sql, params).fetchone()
            return row

    def insert(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            assert cur.lastrowid is not None
            return cur.lastrowid

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def migrate(self) -> int:
        """Apply migrations/NNNN_*.sql newer than PRAGMA user_version. Returns the new version."""
        with self._lock:
            current = self._conn.execute("PRAGMA user_version").fetchone()[0]
            files = sorted(
                (p for p in resources.files("doorman.migrations").iterdir() if p.name.endswith(".sql")),
                key=lambda p: p.name,
            )
            for f in files:
                version = int(f.name.split("_", 1)[0])
                if version <= current:
                    continue
                script = f.read_text(encoding="utf-8")
                self._conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {version};\nCOMMIT;")
                current = version
            return int(current)

    def backup_to(self, dest: str | Path) -> None:
        """Consistent online snapshot (safe while the app is running)."""
        target = sqlite3.connect(str(dest))
        try:
            with self._lock:
                self._conn.backup(target)
        finally:
            target.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
