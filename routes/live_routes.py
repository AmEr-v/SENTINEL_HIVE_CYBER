from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from flask import Blueprint, render_template

from config import Config


def create_live_blueprint(config: Config) -> Blueprint:
	bp = Blueprint("live", __name__)

	def _exporter_ui_meta(url: str) -> tuple[str, str]:
		parsed = urlparse(url)
		if not parsed.hostname:
			parsed = urlparse(f"http://{url}")
		host = parsed.hostname or url
		if parsed.port:
			host = f"{host}:{parsed.port}"
		path = parsed.path or "/"
		if parsed.query:
			qs = parse_qs(parsed.query)
			if "token" in qs:
				path = f"{path}?token=***"
			else:
				path = f"{path}?{parsed.query}"
		return host, path

	@bp.route("/live-http")
	def live_http():
		return render_template("live_http.html", http_log=str(config.http_log_path), max_events=config.max_events)

	@bp.route("/live-ssh")
	def live_ssh():
		exporter_host, exporter_path = _exporter_ui_meta(config.exporter_ssh_stream_url)
		return render_template(
			"live_ssh.html",
			ssh_log=str(config.ssh_log_path),
			max_events=config.max_events,
			exporter_host=exporter_host,
			exporter_path=exporter_path,
		)

	return bp
