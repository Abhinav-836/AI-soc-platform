"""
SQLite persistence for events, alerts, response actions, blocked IPs and
analyst-added IOCs.

Before this, alerts lived in a Python list (gone on restart, capped at 1000),
/api/v1/events always returned [], and changing an alert's status was only
broadcast over the WebSocket, never saved. SQLite needs no server, so it
works the same in the desktop app, Docker and tests.
"""
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from src.core.logger import LoggerMixin
from src.core.paths import writable
from src.core.time_utils import iso, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    event_type TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    user TEXT,
    hostname TEXT,
    source_type TEXT,
    flagged INTEGER DEFAULT 0,
    ingested TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst ON events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(hostname);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    severity TEXT,
    status TEXT,
    score REAL,
    rule_id TEXT,
    category TEXT,
    src_ip TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS responses (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    playbook TEXT,
    alert_id TEXT,
    status TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_responses_status ON responses(status);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    blocked_at TEXT NOT NULL,
    expires_at TEXT,
    mode TEXT,
    reason TEXT,
    alert_id TEXT
);

CREATE TABLE IF NOT EXISTS iocs (
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,
    confidence REAL,
    description TEXT,
    added_at TEXT,
    PRIMARY KEY (type, value)
);
"""

ALERT_STATUSES = ("new", "investigating", "contained", "resolved", "false_positive")


class SOCStore(LoggerMixin):
    def __init__(self, path: Union[str, Path, None] = None, max_events: int = 50000):
        self.path = Path(path) if path else writable("data/soc.db")
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_events = max_events
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        if str(self.path) != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA.replace(
            "CREATE INDEX IF NOT EXISTS idx_events_host ON events(hostname);", ""))
        columns = {r[1] for r in self.conn.execute("PRAGMA table_info(events)")}
        if "ingested" not in columns:  # databases created by an earlier v2 build
            self.conn.execute("ALTER TABLE events ADD COLUMN ingested TEXT")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(hostname)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ingested ON events(ingested)")
        self.conn.commit()
        self._inserts = 0

    # ------------------------------------------------------------- events
    def add_events(self, events: Iterable[Dict[str, Any]]):
        rows = [(
            e["event_id"], e.get("@timestamp") or iso(), e.get("event_type"), e.get("src_ip"), e.get("dst_ip"),
            e.get("user"), e.get("hostname"), e.get("source_type"), int(bool(e.get("_flagged"))),
            e.get("ingested_at") or iso(),
            json.dumps({k: v for k, v in e.items() if not k.startswith("_")}, default=str),
        ) for e in events]
        if not rows:
            return
        with self._lock:
            self.conn.executemany(
                "INSERT OR REPLACE INTO events (id, ts, event_type, src_ip, dst_ip, user, hostname, source_type,"
                " flagged, ingested, data) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
            self.conn.commit()
            self._inserts += len(rows)
            if self._inserts >= 1000:  # prune occasionally, not on every insert
                self._inserts = 0
                self.conn.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY ingested DESC LIMIT -1 OFFSET ?)",
                    (self.max_events,))
                self.conn.commit()

    def mark_flagged(self, event_ids: Iterable[str]):
        ids = list(event_ids)
        if not ids:
            return
        with self._lock:
            self.conn.executemany("UPDATE events SET flagged = 1 WHERE id = ?", [(i,) for i in ids])
            self.conn.commit()

    def recent_events(self, limit: int = 100, event_type: Optional[str] = None, ip: Optional[str] = None,
                      search: Optional[str] = None, flagged_only: bool = False) -> List[Dict[str, Any]]:
        where, args = [], []
        if event_type:
            where.append("event_type = ?")
            args.append(event_type)
        if ip:
            where.append("(src_ip = ? OR dst_ip = ?)")
            args += [ip, ip]
        if search:
            where.append("data LIKE ?")
            args.append(f"%{search}%")
        if flagged_only:
            where.append("flagged = 1")
        sql = "SELECT data, flagged FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts DESC LIMIT ?"
        with self._lock:
            rows = self.conn.execute(sql, (*args, limit)).fetchall()
        return [{**json.loads(r["data"]), "flagged": bool(r["flagged"])} for r in rows]

    def event_counts(self, since: str, by: str = "event_type") -> Dict[str, int]:
        """Events received since `since` (ingestion time, so imported old logs count too)."""
        column = {"event_type": "event_type", "source": "source_type"}[by]
        with self._lock:
            rows = self.conn.execute(
                f"SELECT {column}, COUNT(*) FROM events WHERE ingested >= ? GROUP BY {column}", (since,)).fetchall()
        return {r[0] or "unknown": r[1] for r in rows}

    def event_volume(self, since: str) -> List[Dict[str, Any]]:
        """Events per minute by source since `since`."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT substr(ingested, 1, 16) m, source_type, COUNT(*) FROM events WHERE ingested >= ?"
                " GROUP BY m, source_type ORDER BY m", (since,)).fetchall()
        out: Dict[str, Dict[str, Any]] = {}
        for minute, source, count in rows:
            out.setdefault(minute, {"minute": minute})[source or "unknown"] = count
        return list(out.values())

    def entity(self, value: str, limit: int = 200) -> Dict[str, Any]:
        """Everything known about one IP, host name or user."""
        with self._lock:
            events = self.conn.execute(
                "SELECT data, flagged FROM events WHERE src_ip = ? OR dst_ip = ? OR hostname = ? OR user = ?"
                " ORDER BY ts DESC LIMIT ?", (value, value, value, value, limit)).fetchall()
            totals = self.conn.execute(
                "SELECT COUNT(*), MIN(ts), MAX(ts), SUM(flagged) FROM events WHERE src_ip = ? OR dst_ip = ?"
                " OR hostname = ? OR user = ?", (value, value, value, value)).fetchone()
            by_type = self.conn.execute(
                "SELECT event_type, COUNT(*) FROM events WHERE src_ip = ? OR dst_ip = ? OR hostname = ? OR user = ?"
                " GROUP BY event_type ORDER BY 2 DESC", (value, value, value, value)).fetchall()
            alerts = self.conn.execute(
                "SELECT data FROM alerts WHERE src_ip = ? OR data LIKE ? ORDER BY updated_at DESC LIMIT 100",
                (value, f'%"{value}"%')).fetchall()
        parsed = [{**json.loads(r["data"]), "flagged": bool(r["flagged"])} for r in events]
        peers: Dict[str, int] = {}
        for e in parsed:
            for field in ("src_ip", "dst_ip"):
                other = e.get(field)
                if other and other != value:
                    peers[other] = peers.get(other, 0) + 1
        return {
            "value": value, "events_total": totals[0] or 0, "first_seen": totals[1], "last_seen": totals[2],
            "flagged_events": int(totals[3] or 0), "by_type": {r[0]: r[1] for r in by_type},
            "alerts": [json.loads(r["data"]) for r in alerts],
            "top_peers": sorted(({"ip": k, "events": v} for k, v in peers.items()), key=lambda x: -x["events"])[:10],
            "events": parsed,
        }

    def count_events(self) -> int:
        with self._lock:
            return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # ------------------------------------------------------------- alerts
    def save_alert(self, alert: Dict[str, Any]):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO alerts (id, created_at, updated_at, severity, status, score, rule_id,"
                " category, src_ip, data) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (alert["id"], alert["created_at"], alert.get("updated_at", alert["created_at"]), alert.get("severity"),
                 alert.get("status", "new"), alert.get("score", 0), alert.get("rule_id"), alert.get("category"),
                 (alert.get("entity") or {}).get("src_ip"), json.dumps(alert, default=str)))
            self.conn.commit()

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute("SELECT data FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    def list_alerts(self, limit: int = 100, offset: int = 0, severity: Optional[str] = None,
                    status: Optional[str] = None, search: Optional[str] = None,
                    open_only: bool = False) -> Dict[str, Any]:
        where, args = [], []
        if severity:
            where.append("severity = ?")
            args.append(severity)
        if status:
            where.append("status = ?")
            args.append(status)
        if open_only:
            where.append("status IN ('new', 'investigating')")
        if search:
            where.append("data LIKE ?")
            args.append(f"%{search}%")
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self.conn.execute(f"SELECT COUNT(*) FROM alerts{clause}", args).fetchone()[0]
            rows = self.conn.execute(
                f"SELECT data FROM alerts{clause} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (*args, limit, offset)).fetchall()
        return {"alerts": [json.loads(r["data"]) for r in rows], "total": total}

    def alert_stats(self) -> Dict[str, Any]:
        with self._lock:
            by_sev = dict(self.conn.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE status IN ('new','investigating') GROUP BY severity"
            ).fetchall())
            by_status = dict(self.conn.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status").fetchall())
            total = self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            top = self.conn.execute(
                "SELECT src_ip, COUNT(*) c FROM alerts WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY c DESC LIMIT 8"
            ).fetchall()
            cats = dict(self.conn.execute("SELECT category, COUNT(*) FROM alerts GROUP BY category").fetchall())
        return {
            "total": total,
            "open": by_status.get("new", 0) + by_status.get("investigating", 0),
            "open_by_severity": by_sev,
            "by_status": by_status,
            "by_category": cats,
            "top_sources": [{"ip": r[0], "alerts": r[1]} for r in top],
        }

    def alert_timeline(self, since: str) -> List[Dict[str, Any]]:
        """Alerts per minute (by creation) since `since`."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT substr(created_at, 1, 16) m, severity, COUNT(*) FROM alerts WHERE created_at >= ?"
                " GROUP BY m, severity ORDER BY m", (since,)).fetchall()
        out: Dict[str, Dict[str, Any]] = {}
        for minute, severity, count in rows:
            out.setdefault(minute, {"minute": minute, "total": 0})
            out[minute][severity] = count
            out[minute]["total"] += count
        return list(out.values())

    # ------------------------------------------------------------- responses
    def save_response(self, item: Dict[str, Any]):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO responses (id, created_at, updated_at, playbook, alert_id, status, data)"
                " VALUES (?,?,?,?,?,?,?)",
                (item["id"], item["created_at"], item.get("updated_at", item["created_at"]), item.get("playbook"),
                 item.get("alert_id"), item.get("status"), json.dumps(item, default=str)))
            self.conn.commit()

    def get_response(self, response_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute("SELECT data FROM responses WHERE id = ?", (response_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    def list_responses(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        sql, args = "SELECT data FROM responses", []
        if status:
            sql += " WHERE status = ?"
            args.append(status)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        with self._lock:
            rows = self.conn.execute(sql, (*args, limit)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    # ------------------------------------------------------------- blocked IPs
    def add_block(self, ip: str, mode: str, reason: str, alert_id: Optional[str], expires_at: Optional[str]):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, expires_at, mode, reason, alert_id)"
                " VALUES (?,?,?,?,?,?)", (ip, iso(), expires_at, mode, reason, alert_id))
            self.conn.commit()

    def remove_block(self, ip: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
            self.conn.commit()
            return cur.rowcount > 0

    def list_blocks(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
        return [dict(r) for r in rows]

    def expired_blocks(self) -> List[str]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT ip FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at < ?", (iso(),)).fetchall()
        return [r[0] for r in rows]

    # ------------------------------------------------------------- IOCs
    def add_ioc(self, ioc_type: str, value: str, source: str, confidence: float, description: str = ""):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO iocs (type, value, source, confidence, description, added_at)"
                " VALUES (?,?,?,?,?,?)", (ioc_type, value, source, confidence, description, iso()))
            self.conn.commit()

    def remove_ioc(self, ioc_type: str, value: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM iocs WHERE type = ? AND value = ?", (ioc_type, value))
            self.conn.commit()
            return cur.rowcount > 0

    def list_iocs(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM iocs ORDER BY added_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------- admin
    def reset(self):
        """Delete all events, alerts and responses (blocked IPs and IOCs are kept)."""
        with self._lock:
            for table in ("events", "alerts", "responses"):
                self.conn.execute(f"DELETE FROM {table}")
            self.conn.commit()

    def close(self):
        with self._lock:
            self.conn.close()


def since_minutes(minutes: int) -> str:
    from datetime import timedelta
    return iso(utcnow() - timedelta(minutes=minutes))
