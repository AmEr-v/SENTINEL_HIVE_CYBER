from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Set
import logging
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
	# Prefer Cowrie exporter API when token/URL provided, but fall back to log parsing
	if config.cowrie_api_token and config.cowrie_exporter_stats_url:
		try:
			resp = requests.get(
				config.cowrie_exporter_stats_url,
				headers={"X-API-Token": config.cowrie_api_token},
				timeout=3,
			)
			if resp.status_code == 200:
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
				return result
		except Exception:
			logging.getLogger(__name__).exception("Cowrie exporter API fetch failed; falling back to logs")
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
	logging.getLogger(__name__).info("Parsed HTTP events=%d unique_ips=%d", len(http_events), len(ip_set))
	return result


def compute_dashboard_stats(config: Config, http_events: List[Dict[str, Any]], ssh_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
	logger = logging.getLogger(__name__)
	from services.metrics_db import get_metrics_db
	db = get_metrics_db(config)
	# Ingest latest events
	if http_events:
		db.ingest_events(http_events)
	if ssh_events:
		db.ingest_events(ssh_events)
	# Get metrics from DB
	metrics = db.get_metrics()
	logger.info("Computed metrics: %s", metrics)
	return metrics
