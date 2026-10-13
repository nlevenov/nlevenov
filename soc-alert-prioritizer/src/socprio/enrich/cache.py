"""SQLite-backed cache so we do not burn API quota on repeat lookups."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path


class IntelCache:
    def __init__(self, path: str, ttl_hours: int = 24) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl_hours * 3600
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS intel_cache ("
            " provider TEXT NOT NULL, indicator TEXT NOT NULL, payload TEXT NOT NULL,"
            " fetched_at REAL NOT NULL, PRIMARY KEY (provider, indicator))"
        )
        self._conn.commit()

    def get(self, provider: str, indicator: str) -> list[dict] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload, fetched_at FROM intel_cache WHERE provider=? AND indicator=?",
                (provider, indicator),
            ).fetchone()
        if row is None or time.time() - row[1] > self.ttl:
            return None
        return json.loads(row[0])

    def put(self, provider: str, indicator: str, payload: list[dict]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO intel_cache VALUES (?, ?, ?, ?)",
                (provider, indicator, json.dumps(payload), time.time()),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()
