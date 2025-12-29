
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import logging

from config import Config
from services import log_reader


def to_json_safe(obj: Any) -> Any:
    if isinstance(obj, datetime):
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=timezone.utc)
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_json_safe(v) for v in obj]
    return obj


class MetricsDB:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        logger = logging.getLogger(__name__)
        logger.info("DEBUG: Using DB path: %s", self.db_path)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY,
                    source TEXT NOT NULL,
                    ts TEXT,
                    src_ip TEXT,
                    event_type TEXT,
                    username TEXT,
                    password TEXT,
                    path TEXT,
                    fingerprint TEXT UNIQUE,
                    raw_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_offsets (
                    file_path TEXT PRIMARY KEY,
                    offset INTEGER DEFAULT 0
                )
            """)
            conn.commit()

    def _get_fingerprint(self, event: Dict[str, Any]) -> str:
        # Deterministic fingerprint to dedup
        ts_str = to_json_safe(event.get('timestamp'))
        key = f"{event.get('source')}|{ts_str}|{event.get('ip')}|{event.get('event')}|{event.get('username')}|{event.get('path')}"
        return hashlib.sha256(key.encode()).hexdigest()

    def ingest_events(self, events: List[Dict[str, Any]]):
        logger = logging.getLogger(__name__)
        with sqlite3.connect(self.db_path) as conn:
            initial_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            inserted = 0
            for event in events:
                fingerprint = self._get_fingerprint(event)
                try:
                    ts_str = to_json_safe(event.get('timestamp'))
                    raw_json = json.dumps(to_json_safe(event), ensure_ascii=False)
                    conn.execute("""
                        INSERT OR IGNORE INTO events (source, ts, src_ip, event_type, username, password, path, fingerprint, raw_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.get('source'),
                        ts_str,
                        event.get('ip'),
                        event.get('event'),
                        event.get('username'),
                        event.get('password'),
                        event.get('path'),
                        fingerprint,
                        raw_json
                    ))
                    inserted += 1
                except Exception as e:
                    logger.warning("Failed to insert event: %s", str(e))
            conn.commit()
            final_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            ignored_duplicates = inserted - (final_count - initial_count)
            logger.info("DEBUG: Ingested %d events, inserted_rows=%d, ignored_duplicates=%d, total_DB_rows=%d", len(events), final_count - initial_count, ignored_duplicates, final_count)

    def get_metrics(self) -> Dict[str, Any]:
        with sqlite3.connect(self.db_path) as conn:
            # Total events
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            # HTTP attempts
            http_attempts = conn.execute("SELECT COUNT(*) FROM events WHERE source = 'HTTP' AND event_type = 'http_request'").fetchone()[0]
            # SSH attempts
            ssh_attempts = conn.execute("SELECT COUNT(*) FROM events WHERE source = 'SSH' AND event_type IN ('cowrie.login.failed', 'cowrie.login.success')").fetchone()[0]
            # Unique IPs
            unique_ips_http = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events WHERE source = 'HTTP' AND src_ip IS NOT NULL").fetchone()[0]
            unique_ips_ssh = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events WHERE source = 'SSH' AND src_ip IS NOT NULL").fetchone()[0]
            unique_ips_total = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip IS NOT NULL").fetchone()[0]
            # Last update
            last_ts = conn.execute("SELECT MAX(ts) FROM events").fetchone()[0]
            # Debug group by
            group_by = conn.execute("SELECT source, event_type, COUNT(*) FROM events GROUP BY source, event_type").fetchall()
            logger = logging.getLogger(__name__)
            logger.info("DEBUG: Event types group by: %s", group_by)
        return {
            "total_events": total_events,
            "http_attempts": http_attempts,
            "ssh_attempts": ssh_attempts,
            "unique_ips_http": unique_ips_http,
            "unique_ips_ssh": unique_ips_ssh,
            "unique_ips": unique_ips_total,
            "last_update": last_ts or "n/a"
        }

    def _get_offset(self, file_path: str) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT offset FROM file_offsets WHERE file_path = ?", (file_path,)).fetchone()
            return row[0] if row else 0

    def _update_offset(self, file_path: str, offset: int):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO file_offsets (file_path, offset) VALUES (?, ?)", (file_path, offset))
            conn.commit()

    def _load_json_lines_incremental(self, path: Path, max_lines: int, offset: int) -> List[Dict[str, Any]]:
        """Load JSONL from offset."""
        if not path.exists() or not path.is_file():
            return []
        buf: Deque[Dict[str, Any]] = deque(maxlen=max_lines)
        try:
            with path.open("rb") as handle:
                handle.seek(offset)
                remaining = handle.read()
                lines = remaining.decode("utf-8", errors="ignore").splitlines()
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        buf.append(json.loads(line))
                    except Exception:
                        continue
                    if len(buf) >= max_lines:
                        break
        except Exception:
            return []
        return list(buf)

    def ingest_from_logs(self, config: Config):
        logger = logging.getLogger(__name__)
        # HTTP
        http_path = config.http_log_path
        logger.info("DEBUG: Ingesting HTTP log: path=%s, exists=%s, size=%d", http_path, http_path.exists(), http_path.stat().st_size if http_path.exists() else 0)
        offset = self._get_offset(str(http_path))
        http_raw = self._load_json_lines_incremental(http_path, config.max_events * 2, offset)
        http_events = log_reader.normalize_http_events(http_raw)
        self.ingest_events(http_events)
        self._update_offset(str(http_path), http_path.stat().st_size if http_path.exists() else 0)
        logger.info("DEBUG: Parsed HTTP events=%d", len(http_events))
        
        # SSH
        ssh_path = config.ssh_log_path
        logger.info("DEBUG: Ingesting SSH log: path=%s, exists=%s, size=%d", ssh_path, ssh_path.exists(), ssh_path.stat().st_size if ssh_path.exists() else 0)
        offset = self._get_offset(str(ssh_path))
        ssh_raw = self._load_json_lines_incremental(ssh_path, config.max_events * 2, offset)
        ssh_events = log_reader.normalize_ssh_events(ssh_raw)
        self.ingest_events(ssh_events)
        self._update_offset(str(ssh_path), ssh_path.stat().st_size if ssh_path.exists() else 0)
        logger.info("DEBUG: Parsed SSH events=%d", len(ssh_events))

    def get_recent_events(self, limit: int = 500) -> List[Dict[str, Any]]:
        return self.get_events_page(limit=limit)

    def get_recent_events_by_source(self, source: str, limit: int = 500) -> List[Dict[str, Any]]:
        sql = "SELECT id, raw_json FROM events WHERE source = ? ORDER BY id DESC LIMIT ?"
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(sql, (source, limit)).fetchall()
            events = []
            for row in rows:
                try:
                    payload = json.loads(row[1])
                    if isinstance(payload, dict):
                        payload["id"] = row[0]
                        events.append(payload)
                except Exception:
                    pass
            return events

    def get_events_page(self, limit: int = 500, before_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT id, raw_json FROM events"
        params: List[Any] = []
        if before_id is not None:
            sql += " WHERE id < ?"
            params.append(before_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(sql, params).fetchall()
            events = []
            for row in rows:
                try:
                    payload = json.loads(row[1])
                    if isinstance(payload, dict):
                        payload["id"] = row[0]
                        events.append(payload)
                except Exception:
                    pass
            return events


def get_metrics_db(config: Config) -> MetricsDB:
    db_path = config.playback_db_path.parent / "telemetry.db"
    return MetricsDB(db_path)
