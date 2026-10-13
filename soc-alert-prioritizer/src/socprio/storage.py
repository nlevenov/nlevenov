"""SQLite persistence for processed alerts."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from .models import Alert, AssetInfo, IntelHit, Priority, Status, Verdict

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT PRIMARY KEY,
    fingerprint     TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    occurrences     INTEGER NOT NULL DEFAULT 1,
    source          TEXT NOT NULL,
    alert_type      TEXT NOT NULL,
    signature       TEXT,
    severity        REAL NOT NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    hostname        TEXT,
    username        TEXT,
    domain          TEXT,
    url             TEXT,
    file_hash       TEXT,
    ml_probability  REAL,
    risk_score      INTEGER NOT NULL,
    priority        TEXT NOT NULL,
    status          TEXT NOT NULL,
    verdict         TEXT,
    notes           TEXT NOT NULL DEFAULT '',
    intel           TEXT NOT NULL DEFAULT '[]',
    asset           TEXT,
    rule_hits       TEXT NOT NULL DEFAULT '[]',
    tags            TEXT NOT NULL DEFAULT '[]',
    score_breakdown TEXT NOT NULL DEFAULT '{}',
    raw             TEXT NOT NULL DEFAULT '{}',
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_alerts_fingerprint ON alerts (fingerprint, last_seen);
CREATE INDEX IF NOT EXISTS ix_alerts_priority ON alerts (priority, status);
CREATE INDEX IF NOT EXISTS ix_alerts_last_seen ON alerts (last_seen);
"""

_JSON_COLUMNS = ("intel", "asset", "rule_hits", "tags", "score_breakdown", "raw")
_PRIORITY_ORDER = "CASE priority WHEN 'critical' THEN 4 WHEN 'high' THEN 3 " \
                  "WHEN 'medium' THEN 2 ELSE 1 END"
_SORTS = {
    "risk": f"risk_score DESC, {_PRIORITY_ORDER} DESC, last_seen DESC",
    "recent": "last_seen DESC",
    "oldest": "last_seen ASC",
}
OPEN_STATUSES = (Status.NEW.value, Status.INVESTIGATING.value, Status.MONITORING.value)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


class AlertStore:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ----------------------------------------------------------- write path
    def save(self, alert: Alert) -> None:
        row = self._to_row(alert)
        columns = ", ".join(row)
        placeholders = ", ".join(f":{c}" for c in row)
        with self._tx() as conn:
            conn.execute(f"INSERT OR REPLACE INTO alerts ({columns}) VALUES ({placeholders})", row)

    def find_recent_duplicate(self, fingerprint: str, since: datetime) -> Alert | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM alerts WHERE fingerprint = ? AND last_seen >= ? "
                f"AND (status IN ({','.join('?' * len(OPEN_STATUSES))}) "
                "     OR (status = 'closed' AND verdict IS NULL AND tags LIKE '%auto-closed%')) "
                "ORDER BY last_seen DESC LIMIT 1",
                (fingerprint, _iso(since), *OPEN_STATUSES),
            ).fetchone()
        return self._from_row(row) if row else None

    def update(self, alert_id: str, *, status: Status | None = None,
               verdict: Verdict | None = None, notes: str | None = None) -> Alert | None:
        changes: dict[str, Any] = {}
        if status is not None:
            changes["status"] = status.value
        if verdict is not None:
            changes["verdict"] = verdict.value
        if notes is not None:
            changes["notes"] = notes
        if changes:
            changes["updated_at"] = _iso(datetime.now(timezone.utc))
            assignments = ", ".join(f"{k} = :{k}" for k in changes)
            with self._tx() as conn:
                conn.execute(f"UPDATE alerts SET {assignments} WHERE id = :id",
                             {**changes, "id": alert_id})
        return self.get(alert_id)

    # ------------------------------------------------------------ read path
    def get(self, alert_id: str) -> Alert | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._from_row(row) if row else None

    def query(self, *, priority: list[str] | None = None, status: list[str] | None = None,
              alert_type: str | None = None, search: str | None = None,
              since: datetime | None = None, sort: str = "risk", limit: int = 100,
              offset: int = 0) -> tuple[list[Alert], int]:
        where, params = self._filters(priority, status, alert_type, search, since)
        order = _SORTS.get(sort, _SORTS["risk"])
        with self._lock:
            total = self._conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY {order} LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
        return [self._from_row(r) for r in rows], total

    @staticmethod
    def _filters(priority, status, alert_type, search, since) -> tuple[str, list[Any]]:
        clauses, params = [], []
        if priority:
            clauses.append(f"priority IN ({','.join('?' * len(priority))})")
            params += priority
        if status:
            clauses.append(f"status IN ({','.join('?' * len(status))})")
            params += status
        if alert_type:
            clauses.append("alert_type = ?")
            params.append(alert_type)
        if since:
            clauses.append("last_seen >= ?")
            params.append(_iso(since))
        if search:
            like = f"%{search}%"
            clauses.append("(signature LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR hostname LIKE ?"
                           " OR username LIKE ? OR domain LIKE ? OR id LIKE ?)")
            params += [like] * 7
        return ("WHERE " + " AND ".join(clauses)) if clauses else "", params

    def labelled(self) -> tuple[list[Alert], list[bool]]:
        """Alerts with an analyst verdict, for retraining."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alerts WHERE verdict IS NOT NULL").fetchall()
        alerts = [self._from_row(r) for r in rows]
        return alerts, [a.verdict == Verdict.TRUE_POSITIVE for a in alerts]

    def frame(self, since: datetime | None = None) -> pd.DataFrame:
        sql = ("SELECT id, last_seen, first_seen, occurrences, source, alert_type, signature,"
               " severity, src_ip, dst_ip, dst_port, hostname, username, domain, risk_score,"
               " priority, status, verdict, ml_probability FROM alerts")
        params: list[Any] = []
        if since:
            sql += " WHERE last_seen >= ?"
            params.append(_iso(since))
        with self._lock:
            frame = pd.read_sql_query(sql, self._conn, params=params)
        for column in ("last_seen", "first_seen"):
            frame[column] = pd.to_datetime(frame[column], utc=True, format="ISO8601")
        return frame

    def stats(self, hours: int = 24) -> dict[str, Any]:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        frame = self.frame(since)
        all_open = self.query(status=list(OPEN_STATUSES), limit=1)[1]
        if frame.empty:
            return {"window_hours": hours, "total": 0, "events": 0, "open": all_open,
                    "by_priority": {p.value: 0 for p in Priority}, "by_status": {},
                    "by_type": {}, "top_sources": [], "timeline": [],
                    "noise_reduction": 0.0, "mean_score": 0.0}

        by_priority = frame["priority"].value_counts().to_dict()
        timeline = (
            frame.set_index("last_seen")
            .groupby("priority")
            .resample("1h")["id"].count()
            .rename("count").reset_index()
        )
        top_sources = (
            frame.dropna(subset=["src_ip"])
            .groupby("src_ip")
            .agg(alerts=("id", "count"), max_score=("risk_score", "max"))
            .sort_values(["max_score", "alerts"], ascending=False)
            .head(8).reset_index().to_dict(orient="records")
        )
        events = int(frame["occurrences"].sum())
        actionable = int(frame["priority"].isin(["critical", "high"]).sum())
        return {
            "window_hours": hours,
            "total": int(len(frame)),
            "events": events,
            "open": all_open,
            "by_priority": {p.value: int(by_priority.get(p.value, 0)) for p in Priority},
            "by_status": {k: int(v) for k, v in frame["status"].value_counts().items()},
            "by_type": {k: int(v) for k, v in frame["alert_type"].value_counts().items()},
            "top_sources": top_sources,
            "timeline": [
                {"time": r["last_seen"].isoformat(), "priority": r["priority"],
                 "count": int(r["count"])}
                for r in timeline.to_dict(orient="records")
            ],
            # share of raw events that did NOT end up as a high/critical item
            "noise_reduction": round(1 - actionable / events, 4) if events else 0.0,
            "mean_score": round(float(frame["risk_score"].mean()), 1),
        }

    def close(self) -> None:
        self._conn.close()

    # -------------------------------------------------------------- mapping
    @staticmethod
    def _to_row(alert: Alert) -> dict[str, Any]:
        return {
            "id": alert.id,
            "fingerprint": alert.fingerprint,
            "timestamp": _iso(alert.timestamp),
            "first_seen": _iso(alert.first_seen),
            "last_seen": _iso(alert.last_seen),
            "occurrences": alert.occurrences,
            "source": alert.source,
            "alert_type": alert.alert_type,
            "signature": alert.signature,
            "severity": alert.severity,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "src_port": alert.src_port,
            "dst_port": alert.dst_port,
            "protocol": alert.protocol,
            "hostname": alert.hostname,
            "username": alert.username,
            "domain": alert.domain,
            "url": alert.url,
            "file_hash": alert.file_hash,
            "ml_probability": alert.ml_probability,
            "risk_score": alert.risk_score,
            "priority": alert.priority.value,
            "status": alert.status.value,
            "verdict": alert.verdict.value if alert.verdict else None,
            "notes": alert.notes,
            "intel": json.dumps([h.model_dump() for h in alert.intel]),
            "asset": alert.asset.model_dump_json() if alert.asset else None,
            "rule_hits": json.dumps(alert.rule_hits),
            "tags": json.dumps(alert.tags),
            "score_breakdown": json.dumps(alert.score_breakdown),
            "raw": json.dumps(alert.raw, default=str),
            "updated_at": _iso(datetime.now(timezone.utc)),
        }

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Alert:
        data = dict(row)
        for column in _JSON_COLUMNS:
            data[column] = json.loads(data[column]) if data[column] else None
        data["intel"] = [IntelHit(**h) for h in data["intel"] or []]
        data["asset"] = AssetInfo(**data["asset"]) if data["asset"] else None
        data["rule_hits"] = data["rule_hits"] or []
        data["tags"] = data["tags"] or []
        data["score_breakdown"] = data["score_breakdown"] or {}
        data["raw"] = data["raw"] or {}
        data.pop("updated_at", None)
        return Alert(**data)
