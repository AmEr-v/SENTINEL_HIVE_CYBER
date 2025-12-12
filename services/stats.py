from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests

from config import Config
from services import log_reader

UTC = datetime.timezone.utc


def ssh_source_label(config: Config) -> str:
	parsed = urlparse(config.cowrie_exporter_stats_url)
	host = parsed.hostname or config.cowrie_exporter_stats_url
	return f"Cowrie Exporter ({host})"


def format_stats_for_output(stats: Dict[str, Any]) -> Dict[str, Any]:
	def _v(val: Any) -> Any:
		return val if val is not None else "n/a"
	return {k: _v(v) for k, v in stats.items()}


def _fetch_cowrie_stats(config: Config) -> Dict[str, Any]:
	result: Dict[str, Any] = {"ssh_attempts": None, "ssh_unique_ips": None, "ssh_ip_set": None}
	if not config.cowrie_api_token:
		return result
	try:
		resp = requests.get(
			config.cowrie_exporter_stats_url,
			headers={"X-API-Token": config.cowrie_api_token},
			timeout=3,
		)
		if resp.status_code != 200:
			return result
		data = resp.json()
		attempts = data.get("login_attempts")
		result["ssh_attempts"] = attempts if isinstance(attempts, int) else None
		ips_list = data.get("top_ips") or data.get("ips") or []
		ip_set = {ip for ip in ips_list if ip}
		if ip_set:
			result["ssh_ip_set"] = ip_set
			result["ssh_unique_ips"] = len(ip_set)
		else:
			unique_ips = data.get("unique_ips")
			if isinstance(unique_ips, int):
				result["ssh_unique_ips"] = unique_ips
	except Exception:
		return result
	return result


def _fetch_http_stats(config: Config, http_events: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
	result: Dict[str, Any] = {"attempts": None, "unique_ips": None, "ip_set": None}
	if config.http_exporter_base_url and config.http_api_token:
		try:
			resp = requests.get(
				f"{config.http_exporter_base_url}/stats/http",
				headers={"X-API-Token": config.http_api_token},
				timeout=3,
			)
			if resp.status_code == 200:
				data = resp.json()
				attempts = data.get("requests") or data.get("count")
				result["attempts"] = attempts if isinstance(attempts, int) else None
				ips_list = data.get("ips") or data.get("top_ips") or []
				ip_set = {ip for ip in ips_list if ip}
				if ip_set:
					result["ip_set"] = ip_set
					result["unique_ips"] = len(ip_set)
				else:
					unique_ips = data.get("unique_ips")
					if isinstance(unique_ips, int):
						result["unique_ips"] = unique_ips
				if result["attempts"] is not None or result["unique_ips"] is not None or result["ip_set"]:
					return result
		except Exception:
			pass

	if http_events is None:
		http_events = log_reader.collect_http_events(config)
	ip_set: Set[str] = {e.get("ip") for e in http_events if e.get("ip")}
	result["ip_set"] = ip_set
	result["unique_ips"] = len(ip_set)
	result["attempts"] = len(http_events)
	return result


def compute_dashboard_stats(config: Config, http_events: List[Dict[str, Any]]) -> Dict[str, Any]:
	http_stats = _fetch_http_stats(config, http_events)
	ssh_stats = _fetch_cowrie_stats(config)

	ssh_attempts_raw = ssh_stats.get("ssh_attempts")
	ssh_attempts = ssh_attempts_raw if isinstance(ssh_attempts_raw, int) else 0
	ssh_unique_ips = ssh_stats.get("ssh_unique_ips")
	ssh_ip_set = ssh_stats.get("ssh_ip_set") or set()

	http_attempts_raw = http_stats.get("attempts")
	http_attempts = http_attempts_raw if isinstance(http_attempts_raw, int) else 0
	http_unique_ips = http_stats.get("unique_ips")
	http_ip_set = http_stats.get("ip_set") or set()

	if ssh_ip_set and http_ip_set:
		unique_union = len(ssh_ip_set.union(http_ip_set))
		unique_display: Any = unique_union
	elif ssh_ip_set:
		unique_display = len(ssh_ip_set)
	elif http_ip_set:
		unique_display = len(http_ip_set)
	else:
		ssh_u = ssh_unique_ips if isinstance(ssh_unique_ips, int) else None
		http_u = http_unique_ips if isinstance(http_unique_ips, int) else None
		if ssh_u is not None or http_u is not None:
			unique_display = f"SSH: {ssh_u or 0} | HTTP: {http_u or 0}"
		else:
			unique_display = None

	ssh_events_display = ssh_attempts if ssh_attempts_raw is not None else (0 if config.cowrie_api_token else None)

	stats = {
		"total_events": ssh_attempts + http_attempts,
		"http_events": http_attempts,
		"ssh_events": ssh_events_display,
		"unique_ips": unique_display,
		"unique_ips_http": http_unique_ips if http_unique_ips is not None else (len(http_ip_set) if http_ip_set else None),
		"unique_ips_ssh": ssh_unique_ips if ssh_unique_ips is not None else (len(ssh_ip_set) if ssh_ip_set else None),
		"last_update": datetime.datetime.utcnow().replace(tzinfo=UTC).isoformat(),
	}
	return stats
