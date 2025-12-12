from __future__ import annotations

from flask import Blueprint, jsonify, render_template

from config import Config
from services import log_reader, stats


def create_dashboard_blueprint(config: Config) -> Blueprint:
	bp = Blueprint("dashboard", __name__)

	def _collect_events_with_stats():
		http_events = log_reader.collect_http_events(config)
		ssh_events = log_reader.collect_ssh_events(config)
		combined = log_reader.combine_events(http_events, ssh_events, config.max_events)
		computed_stats = stats.compute_dashboard_stats(config, http_events)
		return combined, computed_stats, http_events

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
				"last_update": stats.compute_dashboard_stats(config, events)["last_update"],
			},
			"log_path": str(config.http_log_path),
		}
		return jsonify(payload)

	@bp.route("/api/ssh-events")
	def api_ssh_events():
		events = log_reader.collect_ssh_events(config)
		payload = {
			"events": [log_reader.serialize_event(e) for e in events],
			"stats": {
				"count": len(events),
				"last_update": stats.compute_dashboard_stats(config, log_reader.collect_http_events(config))["last_update"],
			},
			"log_path": str(config.ssh_log_path),
		}
		return jsonify(payload)

	return bp
