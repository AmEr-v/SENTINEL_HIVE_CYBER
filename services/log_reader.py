from __future__ import annotations

import datetime
import json
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from config import Config


UTC = datetime.timezone.utc


def _parse_time(raw: Optional[str]) -> Optional[datetime.datetime]:
	"""Parse ISO-ish timestamps from log entries into UTC datetimes."""
	if not raw:
		return None
	try:
		value = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
		return datetime.datetime.fromisoformat(value).astimezone(UTC)
	except Exception:
		return None


def _load_json_lines(path: Path, max_lines: int) -> List[Dict[str, Any]]:
	"""Load up to max_lines JSONL records from disk (tail-safe)."""
	if not path.exists() or not path.is_file():
		return []
	buf: Deque[Dict[str, Any]] = deque(maxlen=max_lines)
	try:
		with path.open("r", encoding="utf-8") as handle:
			for line in handle:
				line = line.strip()
				if not line:
					continue
				try:
					buf.append(json.loads(line))
				except Exception:
					continue
	except Exception:
		return []
	return list(buf)


def normalize_http_events(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
	"""Normalize HTTP exporter records into a unified shape."""
	normalized: List[Dict[str, Any]] = []
	for entry in raw_events:
		ts = _parse_time(entry.get("time"))
		normalized.append(
			{
				"timestamp": ts,
				"source": "HTTP",
				"event": entry.get("event", "http_request"),
				"ip": entry.get("remote_addr", "unknown"),
				"method": entry.get("method"),
				"path": entry.get("path"),
				"query": entry.get("query_string"),
				"username": entry.get("username"),
				"password": entry.get("password"),
				"user_agent": entry.get("headers", {}).get("User-Agent"),
			},
		)
	return normalized


def normalize_ssh_events(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
	"""Normalize Cowrie JSON log records into a unified shape."""
	normalized: List[Dict[str, Any]] = []
	for entry in raw_events:
		event_id = entry.get("eventid", "")
		if not event_id.startswith("cowrie.login."):
			continue
		ts = _parse_time(entry.get("timestamp"))
		normalized.append(
			{
				"timestamp": ts,
				"source": "SSH",
				"event": event_id,
				"ip": entry.get("src_ip", "unknown"),
				"username": entry.get("username"),
				"password": entry.get("password"),
				"message": entry.get("message"),
			},
		)
	return normalized


def collect_http_events(config: Config) -> List[Dict[str, Any]]:
	http_raw = _load_json_lines(config.http_log_path, config.max_events * 2)
	http_events = normalize_http_events(http_raw)
	http_events.sort(
		key=lambda e: e.get("timestamp") or datetime.datetime.min.replace(tzinfo=UTC),
		reverse=True,
	)
	return http_events[: config.max_events]


def collect_ssh_events(config: Config) -> List[Dict[str, Any]]:
	ssh_raw = _load_json_lines(config.ssh_log_path, config.max_events * 2)
	ssh_events = normalize_ssh_events(ssh_raw)
	ssh_events.sort(
		key=lambda e: e.get("timestamp") or datetime.datetime.min.replace(tzinfo=UTC),
		reverse=True,
	)
	return ssh_events[: config.max_events]


def combine_events(http_events: List[Dict[str, Any]], ssh_events: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
	combined = http_events + ssh_events
	combined.sort(key=lambda e: e.get("timestamp") or datetime.datetime.min.replace(tzinfo=UTC), reverse=True)
	return combined[:limit]


def serialize_event(event: Dict[str, Any]) -> Dict[str, Any]:
	"""Render an event dict ready for JSON output."""
	serialized = dict(event)
	ts = serialized.get("timestamp")
	if isinstance(ts, datetime.datetime):
		serialized["timestamp"] = ts.isoformat()
	return serialized
