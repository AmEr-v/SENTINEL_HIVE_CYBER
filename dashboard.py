"""Simple Flask dashboard to view honeypot HTTP and SSH attack logs.

This app reads two log sources:
- HTTP honeypot JSON lines log (default: ~/http-honeypot.log)
- Cowrie SSH JSON lines log (default: ~/cowrie/var/log/cowrie/cowrie.json)

Override paths via env vars:
- HTTP_LOG_PATH
- SSH_LOG_PATH
Use MAX_EVENTS to cap records returned to the UI.
"""

import datetime
import json
import os
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template_string


app = Flask(__name__)


HTTP_LOG_PATH = Path(
		os.getenv("HTTP_LOG_PATH", str(Path.home() / "http-honeypot.log"))
).expanduser()

SSH_LOG_PATH = Path(
		os.getenv(
				"SSH_LOG_PATH",
				str(Path.home() / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"),
		)
).expanduser()

MAX_EVENTS = int(os.getenv("MAX_EVENTS", "500"))


def _parse_time(raw: Optional[str]) -> Optional[datetime.datetime]:
		"""Parse ISO timestamps and normalize to UTC."""
		if not raw:
				return None
		try:
				if raw.endswith("Z"):
						raw = raw.replace("Z", "+00:00")
				return datetime.datetime.fromisoformat(raw).astimezone(datetime.timezone.utc)
		except Exception:
				return None


def _load_json_lines(path: Path, max_lines: int) -> List[Dict[str, Any]]:
		"""Read newline-delimited JSON with a bounded buffer."""
		if not path.exists() or not path.is_file():
				return []
		buffer: deque = deque(maxlen=max_lines)
		try:
				with path.open("r", encoding="utf-8") as handle:
						for line in handle:
								line = line.strip()
								if not line:
										continue
								try:
										buffer.append(json.loads(line))
								except Exception:
										continue
		except Exception:
				return []
		return list(buffer)


def _normalize_http_events(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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
						}
				)
		return normalized


def _normalize_ssh_events(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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
						}
				)
		return normalized


def _collect_events() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
		http_raw = _load_json_lines(HTTP_LOG_PATH, MAX_EVENTS * 2)
		ssh_raw = _load_json_lines(SSH_LOG_PATH, MAX_EVENTS * 2)

		http_events = _normalize_http_events(http_raw)
		ssh_events = _normalize_ssh_events(ssh_raw)

		combined: List[Dict[str, Any]] = http_events + ssh_events
		combined.sort(
				key=lambda e: e.get("timestamp") or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc),
				reverse=True,
		)
		combined = combined[:MAX_EVENTS]

		unique_ips = {e.get("ip") for e in combined if e.get("ip")}

		stats = {
				"total_events": len(combined),
				"http_events": len(http_events),
				"ssh_events": len(ssh_events),
				"unique_ips": len(unique_ips),
				"last_update": datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat(),
		}
		return combined, stats


def _serialize_event(event: Dict[str, Any]) -> Dict[str, Any]:
		serialized = dict(event)
		ts = serialized.get("timestamp")
		if isinstance(ts, datetime.datetime):
				serialized["timestamp"] = ts.isoformat()
		return serialized


@app.route("/")
def index():
		events, stats = _collect_events()
		return render_template_string(
				INDEX_TEMPLATE,
				stats=stats,
				events=[_serialize_event(e) for e in events],
				http_log=str(HTTP_LOG_PATH),
				ssh_log=str(SSH_LOG_PATH),
				max_events=MAX_EVENTS,
		)


@app.route("/api/events")
def api_events():
		events, stats = _collect_events()
		payload = {
				"events": [_serialize_event(e) for e in events],
				"stats": stats,
				"log_paths": {"http": str(HTTP_LOG_PATH), "ssh": str(SSH_LOG_PATH)},
		}
		return jsonify(payload)


INDEX_TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Sentinel Hive Dashboard</title>
	<style>
		:root {
			--bg: #0b1220;
			--panel: #0f172a;
			--card: #111827;
			--accent: #22d3ee;
			--accent-2: #f97316;
			--text: #e5e7eb;
			--muted: #94a3b8;
			--danger: #f87171;
			--success: #34d399;
			--font: 'JetBrains Mono', 'SFMono-Regular', Menlo, Consolas, monospace;
		}
		* { box-sizing: border-box; }
		body {
			margin: 0;
			background: radial-gradient(circle at 20% 20%, #0f2038, var(--bg));
			color: var(--text);
			font-family: var(--font);
			min-height: 100vh;
		}
		header {
			padding: 18px 22px;
			display: flex;
			align-items: center;
			justify-content: space-between;
			border-bottom: 1px solid #1f2937;
			background: linear-gradient(90deg, #0f172a, #0b1220);
			position: sticky;
			top: 0;
			z-index: 10;
		}
		.brand { letter-spacing: 3px; text-transform: uppercase; color: var(--accent); font-weight: 700; }
		.sub { color: var(--muted); font-size: 12px; margin-top: 4px; }
		main { padding: 20px 22px 50px 22px; max-width: 1200px; margin: auto; }
		.grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
		.card {
			background: var(--card);
			border: 1px solid #1f2937;
			padding: 14px 16px;
			border-radius: 10px;
			box-shadow: 0 0 25px #0b122055;
		}
		.card h3 { margin: 0 0 6px 0; font-size: 14px; letter-spacing: 1px; color: var(--muted); text-transform: uppercase; }
		.card .value { font-size: 26px; font-weight: 700; color: var(--text); }
		.badge { display: inline-block; padding: 4px 8px; border-radius: 6px; border: 1px solid #1f2937; color: var(--muted); font-size: 11px; text-transform: uppercase; }
		.badge.warn { border-color: var(--accent-2); color: var(--accent-2); }
		.badge.ok { border-color: var(--success); color: var(--success); }
		table { width: 100%; border-collapse: collapse; font-size: 12px; }
		th, td { padding: 8px 10px; border-bottom: 1px solid #1f2937; text-align: left; }
		th { color: var(--muted); letter-spacing: 1px; text-transform: uppercase; font-size: 11px; }
		tr:hover td { background: #0f172a; }
		.chip { display: inline-block; padding: 2px 6px; border-radius: 4px; border: 1px solid #1f2937; font-size: 11px; }
		.chip.http { border-color: var(--accent); color: var(--accent); }
		.chip.ssh { border-color: var(--accent-2); color: var(--accent-2); }
		.pill { background: #1f2937; border-radius: 20px; padding: 4px 10px; font-size: 11px; color: var(--muted); }
		.muted { color: var(--muted); }
		.footer { margin-top: 18px; color: var(--muted); font-size: 12px; display: flex; gap: 12px; flex-wrap: wrap; }
		.log-path { font-family: var(--font); font-size: 11px; color: #cbd5e1; }
		.table-wrap { overflow-x: auto; background: var(--panel); border: 1px solid #1f2937; border-radius: 10px; padding: 6px; }
		.actions { display: flex; gap: 8px; align-items: center; }
		button {
			background: var(--accent);
			color: #0b1220;
			border: none;
			padding: 8px 12px;
			border-radius: 6px;
			cursor: pointer;
			font-weight: 700;
			letter-spacing: 0.5px;
		}
		button.secondary { background: #1f2937; color: var(--text); }
		@media (max-width: 640px) {
			header { flex-direction: column; align-items: flex-start; gap: 8px; }
			main { padding: 16px; }
			th, td { white-space: nowrap; }
		}
	</style>
</head>
<body>
	<header>
		<div>
			<div class="brand">Sentinel Hive / Threat Desk</div>
			<div class="sub">Live honeypot telemetry from SSH and HTTP traps</div>
		</div>
		<div class="actions">
			<button id="refresh">Refresh now</button>
			<span class="pill" id="last-update">Last update: --</span>
		</div>
	</header>

	<main>
		<div class="grid">
			<div class="card">
				<h3>Total Events</h3>
				<div class="value" id="stat-total">{{ stats.total_events }}</div>
				<div class="muted">Max returned: {{ max_events }}</div>
			</div>
			<div class="card">
				<h3>HTTP Attempts</h3>
				<div class="value" id="stat-http">{{ stats.http_events }}</div>
				<span class="badge warn">Edge honeypot</span>
			</div>
			<div class="card">
				<h3>SSH Attempts</h3>
				<div class="value" id="stat-ssh">{{ stats.ssh_events }}</div>
				<span class="badge warn">Cowrie</span>
			</div>
			<div class="card">
				<h3>Unique IPs</h3>
				<div class="value" id="stat-ips">{{ stats.unique_ips }}</div>
				<span class="badge ok">Deduplicated</span>
			</div>
		</div>

		<div style="margin: 18px 0 10px 0; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
			<div class="muted">Live feed of SSH and HTTP attack attempts</div>
			<div class="actions">
				<span class="pill">HTTP log: <span class="log-path">{{ http_log }}</span></span>
				<span class="pill">SSH log: <span class="log-path">{{ ssh_log }}</span></span>
			</div>
		</div>

		<div class="table-wrap">
			<table id="events-table">
				<thead>
					<tr>
						<th>Time (UTC)</th>
						<th>Source</th>
						<th>Event</th>
						<th>IP</th>
						<th>Username</th>
						<th>Password</th>
						<th>Path / Message</th>
					</tr>
				</thead>
				<tbody id="events-body"></tbody>
			</table>
		</div>

		<div class="footer">
			<span>Data auto-refreshes every 10s.</span>
			<span>Configure paths with HTTP_LOG_PATH and SSH_LOG_PATH environment variables.</span>
			<span>Current cap: {{ max_events }} events.</span>
		</div>
	</main>

	<script>
		const tbody = document.getElementById('events-body');
		const lastUpdate = document.getElementById('last-update');
		const statTotal = document.getElementById('stat-total');
		const statHttp = document.getElementById('stat-http');
		const statSsh = document.getElementById('stat-ssh');
		const statIps = document.getElementById('stat-ips');

		function renderRow(evt) {
			const tr = document.createElement('tr');
			const cells = [
				evt.timestamp ? new Date(evt.timestamp).toISOString().replace('T', ' ').replace('Z', '') : '—',
				`<span class="chip ${evt.source === 'HTTP' ? 'http' : 'ssh'}">${evt.source}</span>`,
				evt.event || 'n/a',
				evt.ip || 'n/a',
				evt.username || '—',
				evt.password || '—',
				evt.path || evt.message || evt.query || '—',
			];
			cells.forEach(c => {
				const td = document.createElement('td');
				td.innerHTML = c;
				tr.appendChild(td);
			});
			return tr;
		}

		async function loadEvents() {
			try {
				const res = await fetch('/api/events');
				const data = await res.json();
				tbody.innerHTML = '';
				data.events.forEach(evt => tbody.appendChild(renderRow(evt)));
				statTotal.textContent = data.stats.total_events;
				statHttp.textContent = data.stats.http_events;
				statSsh.textContent = data.stats.ssh_events;
				statIps.textContent = data.stats.unique_ips;
				lastUpdate.textContent = 'Last update: ' + data.stats.last_update;
			} catch (err) {
				lastUpdate.textContent = 'Failed to refresh: ' + err;
			}
		}

		document.getElementById('refresh').addEventListener('click', loadEvents);
		loadEvents();
		setInterval(loadEvents, 10000);
	</script>
</body>
</html>
"""


def _str_to_bool(value: str) -> bool:
		return value.lower() in {"1", "true", "yes", "on"}


if __name__ == "__main__":
		host = os.getenv("HOST", "0.0.0.0")
		port = int(os.getenv("PORT", "5000"))
		debug = _str_to_bool(os.getenv("FLASK_DEBUG", "false"))
		app.run(host=host, port=port, debug=debug)
