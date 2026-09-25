"""Cross-worker SQLite admission control for expensive investigation operations."""
from __future__ import annotations
import sqlite3
import time
import uuid
from pathlib import Path


class BusyError(ValueError):
    pass


class OperationLimiter:
    def __init__(self, path: str | Path, max_per_minute: int = 6, concurrency: int = 2):
        self.path = path
        self.max_per_minute = max_per_minute
        self.concurrency = concurrency

    def acquire(self) -> str:
        with sqlite3.connect(str(self.path), timeout=5) as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS operation_leases(id TEXT PRIMARY KEY, started REAL, expires REAL, active INTEGER)')
            conn.execute('BEGIN IMMEDIATE')
            now = time.time()
            conn.execute('DELETE FROM operation_leases WHERE started<? AND expires<?', (now - 60, now))
            active = conn.execute('SELECT COUNT(*) FROM operation_leases WHERE active=1 AND expires>?', (now,)).fetchone()[0]
            recent = conn.execute('SELECT COUNT(*) FROM operation_leases WHERE started>?', (now - 60,)).fetchone()[0]
            if active >= self.concurrency or recent >= self.max_per_minute:
                raise BusyError('Investigation capacity reached; retry in one minute')
            token = str(uuid.uuid4())
            conn.execute('INSERT INTO operation_leases VALUES(?,?,?,1)', (token, now, now + 240))
            return token

    def release(self, token: str) -> None:
        with sqlite3.connect(str(self.path), timeout=5) as conn:
            conn.execute('UPDATE operation_leases SET active=0 WHERE id=?', (token,))
