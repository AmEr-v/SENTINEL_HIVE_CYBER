from __future__ import annotations

from flask import Blueprint, Response, jsonify, render_template

from config import Config
from services.cowrie_sessions import list_cowrie_sessions, stream_playlog


def create_session_blueprint(config: Config) -> Blueprint:
	bp = Blueprint("sessions", __name__)

	@bp.route("/ssh-session-replay")
	def ssh_session_replay():
		return render_template("session_replay.html")

	@bp.route("/api/ssh-sessions")
	def api_ssh_sessions():
		sessions = list_cowrie_sessions(config)
		return jsonify({"sessions": sessions})

	@bp.route("/api/ssh-session-replay/<session_id>")
	def api_ssh_session_replay(session_id: str):
		return Response(stream_playlog(config, session_id), mimetype="text/plain")

	return bp
