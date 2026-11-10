"""Bounded SQLite outbox. A committed append survives sender/process restart."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager


class DiskSpool:
    def __init__(self, path: str, max_events=20_000, max_bytes=64 * 1024 * 1024):
        self.path = path
        self.max_events = max_events
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self._db() as db:
            # Cap database pages as well as logical payload size (128 MiB).
            db.execute("PRAGMA max_page_count=32768")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL, payload TEXT NOT NULL,
                    size INTEGER NOT NULL, rejected INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS outbox_scope ON outbox(scope, rejected, id);
                CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
                INSERT OR IGNORE INTO counters VALUES ('dropped_full', 0);
            """)
        if os.name != "nt":
            os.chmod(path, 0o600)

    @contextmanager
    def _db(self):
        with self._lock:
            db = sqlite3.connect(self.path, timeout=1.0)
            try:
                db.execute("PRAGMA synchronous=FULL")
                with db:
                    yield db
            finally:
                db.close()

    def append(self, scope: str, event: dict) -> bool:
        # Generate once, before first transmission. Retry never changes this ID.
        payload = json.dumps({**event, "event_uid": str(uuid.uuid4())}, ensure_ascii=False)
        size = len(payload.encode("utf-8"))
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            count, used = db.execute("SELECT count(*), coalesce(sum(size), 0) FROM outbox").fetchone()
            if count >= self.max_events or used + size > self.max_bytes:
                db.execute("UPDATE counters SET value=value+1 WHERE name='dropped_full'")
                return False
            db.execute("INSERT INTO outbox(scope,payload,size) VALUES (?,?,?)", (scope, payload, size))
        return True

    def batch(self, scope: str, limit: int):
        with self._db() as db:
            rows = db.execute(
                "SELECT id,payload FROM outbox WHERE scope=? AND rejected=0 ORDER BY id LIMIT ?",
                (scope, limit),
            ).fetchall()
        return [(row_id, json.loads(payload)) for row_id, payload in rows]

    def complete(self, rows, rejected_indices):
        """Delete accepted rows; quarantine rejects rather than silently discard them."""
        rejected = set(rejected_indices)
        with self._db() as db:
            for index, (row_id, _) in enumerate(rows):
                if index in rejected:
                    db.execute("UPDATE outbox SET rejected=1 WHERE id=?", (row_id,))
                else:
                    db.execute("DELETE FROM outbox WHERE id=?", (row_id,))

    def stats(self, scope: str) -> dict:
        with self._db() as db:
            count, used, rejected = db.execute(
                "SELECT count(*),coalesce(sum(size),0),coalesce(sum(rejected),0) FROM outbox"
            ).fetchone()
            pending = db.execute(
                "SELECT count(*) FROM outbox WHERE scope=? AND rejected=0", (scope,)
            ).fetchone()[0]
            dropped = db.execute("SELECT value FROM counters WHERE name='dropped_full'").fetchone()[0]
        return {"stored": count, "payload_bytes": used, "pending": pending,
                "quarantined": rejected, "retained_other_scope": count - rejected - pending,
                "dropped_full": dropped}
