from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from config import Config
from services.log_reader import _parse_time


def list_cowrie_sessions(config: Config) -> List[Dict[str, Any]]:
	"""Return session summaries for recorded Cowrie connections."""
	ssh_log_path = config.ssh_log_path
	if not ssh_log_path.exists():
		return []
	sessions: List[Dict[str, Any]] = []
	try:
		with ssh_log_path.open("r", encoding="utf-8") as handle:
			for line in handle:
				line = line.strip()
				if not line:
					continue
				try:
					entry = json.loads(line)
				except Exception:
					continue
				if entry.get("eventid") != "cowrie.session.connect":
					continue
				session_id = entry.get("session")
				src_ip = entry.get("src_ip")
				ts = _parse_time(entry.get("timestamp"))
				if not session_id or not src_ip or not ts:
					continue
				tty_path = config.cowrie_tty_path / session_id
				if not tty_path.exists():
					continue
				sessions.append({"timestamp": ts.isoformat(), "session": session_id, "ip": src_ip})
	except Exception:
		return []
	sessions.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
	return sessions


def safe_session_id(session_id: str) -> Optional[str]:
	if not session_id:
		return None
	if "/" in session_id or "\\" in session_id:
		return None
	if ".." in session_id:
		return None
	return session_id


def stream_playlog(config: Config, session_id: str) -> Generator[str, None, None]:
	safe_id = safe_session_id(session_id)
	if not safe_id:
		yield "Invalid session id\n"
		return
	tty_path = config.cowrie_tty_path / safe_id
	if not tty_path.exists():
		yield "Session file missing on disk\n"
		return
	if not config.playlog_bin.exists():
		yield "playlog binary not found\n"
		return
	proc = None
	try:
		proc = subprocess.Popen(
			[str(config.playlog_bin), str(tty_path)],
			stdout=subprocess.PIPE,
			stderr=subprocess.STDOUT,
			text=True,
			bufsize=1,
		)
		if not proc.stdout:
			yield "Failed to start replay\n"
			return
		for line in proc.stdout:
			yield line
	finally:
		if proc and proc.poll() is None:
			proc.terminate()
			try:
				proc.wait(timeout=2)
			except Exception:
				proc.kill()
