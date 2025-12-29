from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request

from config import Config
from services import log_reader, stats


def create_dashboard_blueprint(config: Config) -> Blueprint:
	bp = Blueprint("dashboard", __name__)

	def _collect_events_with_stats(limit: int, before_id: int | None = None):
		from services.metrics_db import get_metrics_db
		db = get_metrics_db(config)
		events = db.get_events_page(limit=limit, before_id=before_id)
		computed_stats = db.get_metrics()
		return events, computed_stats, []

	@bp.route("/")
	def index():
		events, computed_stats, _ = _collect_events_with_stats(config.max_events)
		return render_template(
			"dashboard.html",
			stats=stats.format_stats_for_output(computed_stats),
			events=[log_reader.serialize_event(e) for e in events],
			http_log=str(config.http_log_path),
			ssh_source=stats.ssh_source_label(config),
			max_events=config.max_events,
		)

	@bp.route("/api/events")
	def api_events():
		before_id = request.args.get("before_id")
		try:
			before_id_val = int(before_id) if before_id is not None else None
		except Exception:
			before_id_val = None
		try:
			limit = int(request.args.get("limit", str(config.max_events)))
		except Exception:
			limit = config.max_events
		limit = max(1, min(limit, 5000))
		events, computed_stats, _ = _collect_events_with_stats(limit, before_id_val)
		next_before_id = events[-1].get("id") if events else None
		payload = {
			"events": [log_reader.serialize_event(e) for e in events],
			"stats": stats.format_stats_for_output(computed_stats),
			"logs": {"http": str(config.http_log_path), "ssh": str(config.ssh_log_path)},
			"next_before_id": next_before_id,
		}
		return jsonify(payload)

	@bp.route("/api/http-events")
	def api_http_events():
		from services.metrics_db import get_metrics_db
		db = get_metrics_db(config)
		events = db.get_recent_events_by_source("HTTP", config.max_events)
		source_label = "VM ingest" if events else "Local log"
		if not events:
			events = log_reader.collect_http_events(config)
		metrics = db.get_metrics()
		last_update = metrics.get("last_update")
		if not last_update or last_update == "n/a":
			ts_values = [e.get("timestamp") for e in events if e.get("timestamp")]
			if ts_values:
				last_ts = max(ts_values)
				last_update = last_ts.isoformat() if hasattr(last_ts, "isoformat") else str(last_ts)
		payload = {
			"events": [log_reader.serialize_event(e) for e in events],
			"stats": {
				"count": len(events),
				"last_update": last_update or "n/a",
			},
			"log_path": str(config.http_log_path),
			"source": source_label,
		}
		return jsonify(payload)

	@bp.route("/api/metrics")
	def api_metrics():
		from services.metrics_db import get_metrics_db
		db = get_metrics_db(config)
		return jsonify(db.get_metrics())

	@bp.route("/api/ingest", methods=["POST"])
	def api_ingest():
		data = request.get_json()
		if not data or not isinstance(data, list):
			return jsonify({"error": "Expected list of events"}), 400
		from services.metrics_db import get_metrics_db
		db = get_metrics_db(config)
		events = []
		for item in data:
			if isinstance(item, dict):
				if "event" not in item and "event_type" in item:
					item["event"] = item["event_type"]
				if isinstance(item.get("raw"), dict):
					raw = item["raw"]
					if "path" not in item and raw.get("path"):
						item["path"] = raw.get("path")
					if "method" not in item and raw.get("method"):
						item["method"] = raw.get("method")
					if "query" not in item and raw.get("query_string"):
						item["query"] = raw.get("query_string")
					if "user_agent" not in item:
						headers = raw.get("headers") or {}
						if isinstance(headers, dict) and headers.get("User-Agent"):
							item["user_agent"] = headers.get("User-Agent")
				events.append(item)
		db.ingest_events(events)
		return jsonify({"ingested": len(events)}), 200

	return bp
