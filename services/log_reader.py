from __future__ import annotations

import datetime
import json
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple
import logging

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
	logger = logging.getLogger(__name__)
	abs_path = path.resolve()
	logger.info("DEBUG: File path: %s", abs_path)
	exists = path.exists()
	size = path.stat().st_size if exists else 0
	logger.info("DEBUG: File exists: %s, size: %d bytes", exists, size)
	if not exists or not path.is_file():
		logger.warning("DEBUG: File does not exist or is not a file")
		return []
	buf: Deque[Dict[str, Any]] = deque(maxlen=max_lines)
	lines_read = 0
	first_lines = []
	last_lines: Deque[str] = deque(maxlen=3)
	try:
		with path.open("r", encoding="utf-8") as handle:
			for line_num, line in enumerate(handle, 1):
				line = line.strip()
				if not line:
					continue
				lines_read += 1
				if lines_read <= 3:
					first_lines.append(line[:200] + "..." if len(line) > 200 else line)
				last_lines.append(line[:200] + "..." if len(line) > 200 else line)
				try:
					buf.append(json.loads(line))
				except Exception as e:
					logger.warning("DEBUG: Skipping invalid JSON line %d: %s (error: %s)", line_num, line[:100], str(e))
					continue
	except Exception as e:
		logger.exception("DEBUG: Failed to read JSON lines from %s", path)
		return []
	items = list(buf)
	logger.info("DEBUG: Lines read: %d, parsed items: %d", lines_read, len(items))
	if first_lines:
		logger.info("DEBUG: First 3 lines: %s", first_lines)
	if last_lines:
		logger.info("DEBUG: Last 3 lines: %s", list(last_lines))
	return items


def normalize_http_events(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
	"""Normalize HTTP exporter records into a unified shape."""
	logger = logging.getLogger(__name__)
	normalized: List[Dict[str, Any]] = []
	parsed_ok = 0
	parsed_failed = 0
	ip_fields_used = set()
	no_ip_count = 0
	examples = []
	for entry in raw_events:
		try:
			ts = _parse_time(entry.get("time") or entry.get("timestamp") or entry.get("@timestamp"))
			# IP may be in various fields depending on exporter
			ip = entry.get("remote_addr") or entry.get("src_ip") or entry.get("client_ip") or entry.get("ip") or entry.get("remoteAddr") or "unknown"
			if ip != "unknown":
				ip_fields_used.add("remote_addr" if entry.get("remote_addr") else "src_ip" if entry.get("src_ip") else "client_ip" if entry.get("client_ip") else "ip" if entry.get("ip") else "remoteAddr")
			else:
				no_ip_count += 1
			normalized.append(
				{
					"timestamp": ts,
					"source": "HTTP",
					"event": entry.get("event", "http_request"),
					"ip": ip,
					"method": entry.get("method"),
					"path": entry.get("path"),
					"query": entry.get("query_string"),
					"username": entry.get("username"),
					"password": entry.get("password"),
					"user_agent": entry.get("headers", {}).get("User-Agent"),
				},
			)
			parsed_ok += 1
			if len(examples) < 3:
				examples.append(normalized[-1])
		except Exception as e:
			logger.warning("DEBUG: Failed to normalize HTTP entry: %s (error: %s)", entry, str(e))
			parsed_failed += 1
	logger.info("DEBUG: HTTP parsed_ok=%d, parsed_failed=%d, no_ip_count=%d, ip_fields_used=%s", parsed_ok, parsed_failed, no_ip_count, list(ip_fields_used))
	if examples:
		logger.info("DEBUG: HTTP examples: %s", examples)
	logger.info("Normalized HTTP events=%d", len(normalized))
	return normalized


def normalize_ssh_events(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
	"""Normalize Cowrie JSON log records into a unified shape."""
	logger = logging.getLogger(__name__)
	normalized: List[Dict[str, Any]] = []
	parsed_ok = 0
	parsed_failed = 0
	ip_fields_used = set()
	no_ip_count = 0
	examples = []
	event_ids_seen = set()
	for entry in raw_events:
		try:
			event_id = entry.get("eventid", "")
			event_ids_seen.add(event_id)
			if not event_id.startswith("cowrie.login."):
				continue
			ts = _parse_time(entry.get("timestamp") or entry.get("time"))
			ip = entry.get("src_ip") or entry.get("srcip") or entry.get("ip") or "unknown"
			if ip != "unknown":
				ip_fields_used.add("src_ip" if entry.get("src_ip") else "srcip" if entry.get("srcip") else "ip")
			else:
				no_ip_count += 1
			normalized.append(
				{
					"timestamp": ts,
					"source": "SSH",
					"event": event_id,
					"ip": ip,
					"username": entry.get("username"),
					"password": entry.get("password"),
					"message": entry.get("message"),
				},
			)
			parsed_ok += 1
			if len(examples) < 3:
				examples.append(normalized[-1])
		except Exception as e:
			logger.warning("DEBUG: Failed to normalize SSH entry: %s (error: %s)", entry, str(e))
			parsed_failed += 1
	logger.info("DEBUG: SSH parsed_ok=%d, parsed_failed=%d, no_ip_count=%d, ip_fields_used=%s, event_ids_seen=%s", parsed_ok, parsed_failed, no_ip_count, list(ip_fields_used), list(event_ids_seen))
	if examples:
		logger.info("DEBUG: SSH examples: %s", examples)
	logger.info("Normalized SSH events=%d", len(normalized))
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
	def to_json_safe(obj: Any) -> Any:
		if isinstance(obj, datetime.datetime):
			if obj.tzinfo is None:
				obj = obj.replace(tzinfo=UTC)
			return obj.isoformat()
		if isinstance(obj, dict):
			return {k: to_json_safe(v) for k, v in obj.items()}
		if isinstance(obj, list):
			return [to_json_safe(v) for v in obj]
		return obj
	return to_json_safe(event)
