from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request

from config import Config
from services import stats


def create_dashboard_blueprint(config: Config) -> Blueprint:
	bp = Blueprint("dashboard", __name__)

	def _collect_events_with_stats():
		from services.metrics_db import get_metrics_db
		db = get_metrics_db(config)
		events = db.get_recent_events(config.max_events)
		computed_stats = db.get_metrics()
		return events, computed_stats, []

	@bp.route("/")
	def index():
		events, computed_stats, _ = _collect_events_with_stats()
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
		events, computed_stats, _ = _collect_events_with_stats()
		payload = {
			"events": [log_reader.serialize_event(e) for e in events],
			"stats": stats.format_stats_for_output(computed_stats),
			"logs": {"http": str(config.http_log_path), "ssh": str(config.ssh_log_path)},
		}
		return jsonify(payload)

	@bp.route("/api/http-events")
	def api_http_events():
		events = log_reader.collect_http_events(config)
		payload = {
			"events": [log_reader.serialize_event(e) for e in events],
			"stats": {
				"count": len(events),
				"last_update": stats.compute_dashboard_stats(config, events, log_reader.collect_ssh_events(config))["last_update"],
			},
			"log_path": str(config.http_log_path),
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
				events.append(item)
		db.ingest_events(events)
		return jsonify({"ingested": len(events)}), 200

	return bp
