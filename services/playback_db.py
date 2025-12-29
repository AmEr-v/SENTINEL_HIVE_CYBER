from __future__ import annotations

import datetime
import json
import logging
import queue
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import Config


class PlaybackDB:
	"""SQLite-backed storage for replaying SSH lines."""

	def __init__(self, config: Config):
		self.config = config
		self.queue: "queue.Queue[Tuple[str, str]]" = queue.Queue(maxsize=5000)
		self._writer_thread: Optional[threading.Thread] = None
		self._last_cleanup_ts = 0.0

	def ensure_db(self) -> None:
		self.config.playback_db_path.parent.mkdir(parents=True, exist_ok=True)
		conn = sqlite3.connect(self.config.playback_db_path)
		try:
			cur = conn.cursor()
			cur.execute(
				"""
				CREATE TABLE IF NOT EXISTS ssh_lines (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					ts TEXT,
					line TEXT
				)
				"""
			)
			cur.execute("CREATE INDEX IF NOT EXISTS idx_ssh_lines_ts ON ssh_lines(ts)")
			cur.execute(
				"""
				CREATE TABLE IF NOT EXISTS log_offsets (
					file_path TEXT PRIMARY KEY,
					offset INTEGER DEFAULT 0
				)
				"""
			)
			conn.commit()
		except Exception:
			try:
				conn.rollback()
			except Exception:
				pass
		finally:
			conn.close()

	def cleanup_old_rows(self, conn: Optional[sqlite3.Connection] = None) -> None:
		if self.config.playback_retention_days <= 0:
			return
		cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=self.config.playback_retention_days)
		cutoff_ts = cutoff.replace(tzinfo=datetime.timezone.utc).isoformat()
		owned = False
		if conn is None:
			conn = sqlite3.connect(self.config.playback_db_path)
			owned = True
		try:
			conn.execute("DELETE FROM ssh_lines WHERE ts < ?", (cutoff_ts,))
			conn.commit()
		except Exception:
			try:
				conn.rollback()
			except Exception:
				pass
		finally:
			if owned:
				conn.close()

	def _get_offset(self, conn: sqlite3.Connection, file_path: str) -> int:
		row = conn.execute("SELECT offset FROM log_offsets WHERE file_path = ?", (file_path,)).fetchone()
		return row[0] if row else 0

	def _update_offset(self, conn: sqlite3.Connection, file_path: str, offset: int) -> None:
		conn.execute(
			"INSERT OR REPLACE INTO log_offsets (file_path, offset) VALUES (?, ?)",
			(file_path, offset),
		)

	def ingest_from_ssh_log(self, max_lines: int = 0) -> int:
		ssh_path = self.config.ssh_log_path
		if not ssh_path.exists() or not ssh_path.is_file():
			return 0
		inserted = 0
		with sqlite3.connect(self.config.playback_db_path) as conn:
			offset = self._get_offset(conn, str(ssh_path))
			try:
				with ssh_path.open("rb") as handle:
					handle.seek(offset)
					data = handle.read()
					new_offset = handle.tell()
			except Exception:
				return 0
			lines = data.decode("utf-8", errors="ignore").splitlines()
			if max_lines > 0 and len(lines) > max_lines:
				lines = lines[-max_lines:]
			rows: List[Tuple[str, str]] = []
			for line in lines:
				raw = line.strip()
				if not raw:
					continue
				ts = None
				try:
					entry = json.loads(raw)
					raw_ts = entry.get("timestamp") or entry.get("time")
					if raw_ts:
						from services.log_reader import _parse_time
						parsed = _parse_time(raw_ts)
						if parsed:
							ts = parsed.isoformat()
				except Exception:
					pass
				if not ts:
					ts = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
				rows.append((ts, raw))
			if rows:
				try:
					conn.executemany("INSERT INTO ssh_lines (ts, line) VALUES (?, ?)", rows)
					conn.commit()
					inserted = len(rows)
				except Exception:
					try:
						conn.rollback()
					except Exception:
						pass
			self._update_offset(conn, str(ssh_path), new_offset)
			conn.commit()
		if inserted:
			logging.getLogger(__name__).info("Ingested %d SSH log lines into playback DB", inserted)
		return inserted

	def _writer_loop(self) -> None:
		conn = sqlite3.connect(self.config.playback_db_path, check_same_thread=False)
		conn.execute("PRAGMA journal_mode=WAL;")
		buffer: List[Tuple[str, str]] = []
		last_flush = time.time()
		self._last_cleanup_ts = last_flush
		while True:
			try:
				item = self.queue.get(timeout=1.0)
			except queue.Empty:
				item = None

			now = time.time()
			if item is not None:
				buffer.append(item)

			if buffer and (len(buffer) >= 50 or now - last_flush >= 1.0):
				try:
					conn.executemany("INSERT INTO ssh_lines (ts, line) VALUES (?, ?)", buffer)
					conn.commit()
				except Exception:
					try:
						conn.rollback()
					except Exception:
						pass
				buffer.clear()
				last_flush = now

			if self.config.playback_retention_days > 0 and now - self._last_cleanup_ts >= 3600:
				try:
					self.cleanup_old_rows(conn)
				except Exception:
					pass
				self._last_cleanup_ts = now

	def start(self) -> None:
		if self._writer_thread and self._writer_thread.is_alive():
			return
		self.ensure_db()
		self.cleanup_old_rows()
		self.ingest_from_ssh_log()
		self._writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
		self._writer_thread.start()

	def enqueue_line(self, line: str) -> None:
		ts = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
		try:
			self.queue.put_nowait((ts, line))
		except queue.Full:
			pass

	def get_db_connection(self) -> sqlite3.Connection:
		conn = sqlite3.connect(self.config.playback_db_path)
		conn.row_factory = sqlite3.Row
		return conn

	def get_range(self) -> Dict[str, Any]:
		conn = self.get_db_connection()
		try:
			row = conn.execute("SELECT MIN(ts) as min_ts, MAX(ts) as max_ts, COUNT(*) as cnt FROM ssh_lines").fetchone()
			return {"min_ts": row[0], "max_ts": row[1], "count": row[2]}
		finally:
			conn.close()

	def query_rows(self, start: Optional[str], end: Optional[str], limit: int) -> List[Dict[str, Any]]:
		clauses: List[str] = []
		params: List[Any] = []
		if start:
			clauses.append("ts >= ?")
			params.append(start)
		if end:
			clauses.append("ts <= ?")
			params.append(end)
		where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
		sql = f"SELECT ts, line FROM ssh_lines {where} ORDER BY ts ASC LIMIT ?"
		params.append(limit)
		conn = self.get_db_connection()
		try:
			rows = conn.execute(sql, params).fetchall()
			return [{"ts": r[0], "line": r[1]} for r in rows]
		finally:
			conn.close()
