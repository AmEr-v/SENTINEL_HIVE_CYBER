from __future__ import annotations

from flask import Blueprint, jsonify

from config import Config
from services import log_reader, stats
from services.sim_telemetry import SimTelemetry


def create_sim_blueprint(config: Config, sim: SimTelemetry) -> Blueprint:
	bp = Blueprint("sim", __name__)

	def _payload():
		http_events = log_reader.collect_http_events(config)
		ssh_events = log_reader.collect_ssh_events(config)
		computed_stats = stats.format_stats_for_output(stats.compute_dashboard_stats(config, http_events, ssh_events))
		return sim.payload(computed_stats)

	@bp.route("/api/sim/telemetry")
	def api_sim_telemetry():
		return jsonify(_payload())

	@bp.route("/api/global-nodes")
	def api_global_nodes():
		data = sim.tick_world()
		return jsonify({"global_nodes": data.get("global_nodes", []), "active_count": len(data.get("global_nodes", []))})

	@bp.route("/api/telemetry-widgets")
	def api_telemetry_widgets():
		return api_sim_telemetry()

	return bp
