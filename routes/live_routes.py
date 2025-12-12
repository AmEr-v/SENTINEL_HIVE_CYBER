from __future__ import annotations

from flask import Blueprint, render_template

from config import Config


def create_live_blueprint(config: Config) -> Blueprint:
	bp = Blueprint("live", __name__)

	@bp.route("/live-http")
	def live_http():
		return render_template("live_http.html", http_log=str(config.http_log_path), max_events=config.max_events)

	@bp.route("/live-ssh")
	def live_ssh():
		return render_template("live_ssh.html", ssh_log=str(config.ssh_log_path), max_events=config.max_events)

	return bp
