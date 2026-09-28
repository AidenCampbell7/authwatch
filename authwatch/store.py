"""
SQLite persistence for events and alerts.

Why SQLite: the whole point of this tool is that it runs anywhere with no
setup. A single file database means `git clone && python -m authwatch` works
on a laptop. The schema is plain SQL and the queries are ANSI, so moving to
Postgres later is a connection-string change plus a driver, not a rewrite.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from .detections import Alert
from .parser import AuthEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    timestamp   TEXT    NOT NULL,
    host        TEXT    NOT NULL,
    pid         INTEGER NOT NULL,
    user        TEXT    NOT NULL,
    source_ip   TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    method      TEXT    NOT NULL,
    success     INTEGER NOT NULL,
    invalid_user INTEGER NOT NULL,
    UNIQUE (timestamp, host, pid, user, source_ip, port)
);

CREATE INDEX IF NOT EXISTS idx_events_ip   ON events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_time ON events (timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    rule        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    summary     TEXT NOT NULL,
    detail      TEXT NOT NULL,
    UNIQUE (rule, timestamp, source_ip, summary)
);

CREATE INDEX IF NOT EXISTS idx_alerts_sev  ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts (timestamp);
"""


class Store:
    def __init__(self, path: str | Path = "data/authwatch.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---------------- writes ----------------

    def insert_events(self, events: Iterable[AuthEvent]) -> int:
        """
        Insert events, ignoring duplicates.

        The UNIQUE constraint plus INSERT OR IGNORE makes ingestion idempotent:
        re-running against the same log file does not double-count, which
        matters because log files get re-read after rotation.
        """
        rows = [
            (e.timestamp.isoformat(), e.host, e.pid, e.user, e.source_ip,
             e.port, e.method, int(e.success), int(e.invalid_user))
            for e in events
        ]
        with self._connect() as conn:
            before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            conn.executemany(
                """INSERT OR IGNORE INTO events
                   (timestamp, host, pid, user, source_ip, port, method, success, invalid_user)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                rows,
            )
            after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return after - before

    def insert_alerts(self, alerts: Sequence[Alert]) -> int:
        with self._connect() as conn:
            before = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            conn.executemany(
                """INSERT OR IGNORE INTO alerts
                   (rule, severity, timestamp, source_ip, summary, detail)
                   VALUES (?,?,?,?,?,?)""",
                [a.as_row() for a in alerts],
            )
            after = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return after - before

    # ---------------- reads ----------------

    def alerts(self, severity: str | None = None, limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM alerts"
        params: list = []
        if severity:
            sql += " WHERE severity = ?"
            params.append(severity)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d["detail"])
            out.append(d)
        return out

    def stats(self) -> dict:
        with self._connect() as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            failed = conn.execute("SELECT COUNT(*) FROM events WHERE success = 0").fetchone()[0]
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            by_sev = {
                r["severity"]: r["n"] for r in conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
                ).fetchall()
            }
            top_ips = [
                dict(r) for r in conn.execute(
                    """SELECT source_ip, COUNT(*) AS failures
                       FROM events WHERE success = 0
                       GROUP BY source_ip ORDER BY failures DESC LIMIT 5"""
                ).fetchall()
            ]
        return {
            "total_events": total_events,
            "failed_events": failed,
            "total_alerts": total_alerts,
            "alerts_by_severity": by_sev,
            "top_failure_sources": top_ips,
        }
