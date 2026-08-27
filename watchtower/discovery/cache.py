from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class ProviderCache:
    """Small SQLite TTL cache shared by free/public providers."""

    def __init__(self, path: str | Path = ":memory:"):
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS provider_cache(
               cache_key TEXT PRIMARY KEY, provider TEXT, payload TEXT,
               stored_at REAL, expires_at REAL)"""
        )
        self.conn.commit()

    @staticmethod
    def key(provider: str, value: str) -> str:
        digest = hashlib.sha256(value.encode()).hexdigest()
        return f"{provider}:{digest}"

    def get(self, provider: str, value: str) -> Any | None:
        row = self.conn.execute(
            "SELECT payload,expires_at FROM provider_cache WHERE cache_key=?",
            (self.key(provider, value),),
        ).fetchone()
        if not row or row[1] <= time.time():
            return None
        return json.loads(row[0])

    def put(self, provider: str, value: str, payload: Any, ttl: int) -> None:
        now = time.time()
        self.conn.execute(
            "INSERT OR REPLACE INTO provider_cache VALUES(?,?,?,?,?)",
            (self.key(provider, value), provider, json.dumps(payload), now, now + ttl),
        )
        self.conn.commit()
