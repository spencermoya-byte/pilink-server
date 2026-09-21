"""SQLite persistence for thermostat telemetry, state, and events.

A single file under ``~/.pilink/`` holds the raw telemetry time-series, the latest
per-device snapshot (via query), node online/offline status, an events log (state
changes, fail-safes, dropped frames), and a small key/value table for singletons
like the coulomb accumulator. The connection is opened with ``check_same_thread``
disabled and guarded by a lock, so the paho network thread and the control loop
can share one :class:`Store` safely.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time

from thermostat.ingest import Telemetry

_TELEMETRY_COLS = (
    "device_id", "fw", "uptime_s", "rssi", "temp_f", "humidity",
    "solar_v", "solar_ma", "solar_mw", "batt_v", "batt_ma", "batt_mw",
    "batt_pct", "batt_rate",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS telemetry (
    ts REAL NOT NULL,
    device_id TEXT NOT NULL,
    fw TEXT, uptime_s REAL, rssi REAL,
    temp_f REAL, humidity REAL,
    solar_v REAL, solar_ma REAL, solar_mw REAL,
    batt_v REAL, batt_ma REAL, batt_mw REAL,
    batt_pct REAL, batt_rate REAL
);
CREATE INDEX IF NOT EXISTS idx_telemetry_dev_ts ON telemetry (device_id, ts);
CREATE TABLE IF NOT EXISTS events (
    ts REAL NOT NULL, device_id TEXT, kind TEXT NOT NULL, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS node_status (
    device_id TEXT PRIMARY KEY, online INTEGER NOT NULL, ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);
"""


def _row_to_telemetry(row: sqlite3.Row) -> Telemetry:
    return Telemetry(**{c: row[c] for c in _TELEMETRY_COLS})


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # busy_timeout lets the server + ingest service share the file: a writer
        # that finds the DB locked retries for up to 5 s instead of erroring.
        self._conn.execute("PRAGMA busy_timeout=5000")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created.

        CREATE TABLE IF NOT EXISTS silently leaves an older table alone, so a Pi
        that has been logging since before the fuel gauge landed would otherwise
        fail on INSERT with 'no such column'.
        """
        have = {r["name"] for r in self._conn.execute("PRAGMA table_info(telemetry)")}
        for col in ("batt_pct", "batt_rate"):
            if col not in have:
                self._conn.execute(f"ALTER TABLE telemetry ADD COLUMN {col} REAL")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ── telemetry ───────────────────────────────────────────────────────────────
    def insert_telemetry(self, t: Telemetry, ts: float | None = None) -> None:
        ts = time.time() if ts is None else ts
        cols = ", ".join(("ts", *_TELEMETRY_COLS))
        placeholders = ", ".join(["?"] * (len(_TELEMETRY_COLS) + 1))
        values = [ts, *(getattr(t, c) for c in _TELEMETRY_COLS)]
        with self._lock:
            self._conn.execute(
                f"INSERT INTO telemetry ({cols}) VALUES ({placeholders})", values)
            self._conn.commit()

    def latest_telemetry(self, device_id: str) -> Telemetry | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM telemetry WHERE device_id=? ORDER BY ts DESC LIMIT 1",
                (device_id,)).fetchone()
        return _row_to_telemetry(row) if row is not None else None

    def latest_telemetry_ts(self, device_id: str) -> float | None:
        """Timestamp of the most recent stored reading (freshness signal)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT ts FROM telemetry WHERE device_id=? ORDER BY ts DESC LIMIT 1",
                (device_id,)).fetchone()
        return row["ts"] if row is not None else None

    def telemetry_history(self, device_id: str, *, since: float | None = None,
                          until: float | None = None,
                          limit: int | None = None) -> list[dict]:
        query = "SELECT * FROM telemetry WHERE device_id=?"
        args: list = [device_id]
        if since is not None:
            query += " AND ts >= ?"
            args.append(since)
        if until is not None:
            query += " AND ts <= ?"
            args.append(until)
        query += " ORDER BY ts ASC"
        if limit is not None:
            query += " LIMIT ?"
            args.append(limit)
        with self._lock:
            rows = self._conn.execute(query, args).fetchall()
        return [dict(r) for r in rows]

    def prune_telemetry(self, before_ts: float) -> int:
        """Delete raw telemetry older than ``before_ts``; returns rows removed."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM telemetry WHERE ts < ?", (before_ts,))
            self._conn.commit()
            return cur.rowcount

    # ── events ──────────────────────────────────────────────────────────────────
    def record_event(self, device_id: str | None, kind: str,
                     detail: str = "", ts: float | None = None) -> None:
        ts = time.time() if ts is None else ts
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (ts, device_id, kind, detail) VALUES (?,?,?,?)",
                (ts, device_id, kind, detail))
            self._conn.commit()

    def events(self, *, device_id: str | None = None, kind: str | None = None,
               limit: int | None = None) -> list[dict]:
        query = "SELECT * FROM events"
        clauses: list[str] = []
        args: list = []
        if device_id is not None:
            clauses.append("device_id=?")
            args.append(device_id)
        if kind is not None:
            clauses.append("kind=?")
            args.append(kind)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY ts DESC"
        if limit is not None:
            query += " LIMIT ?"
            args.append(limit)
        with self._lock:
            rows = self._conn.execute(query, args).fetchall()
        return [dict(r) for r in rows]

    # ── node status ─────────────────────────────────────────────────────────────
    def set_node_status(self, device_id: str, online: bool,
                        ts: float | None = None) -> None:
        ts = time.time() if ts is None else ts
        with self._lock:
            self._conn.execute(
                "INSERT INTO node_status (device_id, online, ts) VALUES (?,?,?) "
                "ON CONFLICT(device_id) DO UPDATE SET "
                "online=excluded.online, ts=excluded.ts",
                (device_id, 1 if online else 0, ts))
            self._conn.commit()

    def get_node_status(self, device_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT online, ts FROM node_status WHERE device_id=?",
                (device_id,)).fetchone()
        if row is None:
            return None
        return {"online": bool(row["online"]), "ts": row["ts"]}

    # ── key/value state ─────────────────────────────────────────────────────────
    def set_state(self, key: str, value) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO state (key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)))
            self._conn.commit()

    def get_state(self, key: str, default=None):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row is not None else default
