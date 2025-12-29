from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request

from config import Config
from services.playback_db import PlaybackDB


def create_playback_blueprint(config: Config, playback_db: PlaybackDB) -> Blueprint:
	bp = Blueprint("playback", __name__)

	@bp.route("/replay-ssh")
	def replay_ssh():
		return render_template("replay_ssh.html", max_events=config.max_events)

	@bp.route("/api/replay/range")
	def api_replay_range():
		playback_db.ingest_from_ssh_log()
		return jsonify(playback_db.get_range())

	@bp.route("/api/replay/query")
	def api_replay_query():
		playback_db.ingest_from_ssh_log()
		start = request.args.get("start")
		end = request.args.get("end")
		try:
			limit = int(request.args.get("limit", "1000"))
		except Exception:
			limit = 1000
		limit = max(1, min(limit, 5000))
		rows = playback_db.query_rows(start, end, limit)
		return jsonify({"rows": rows})

	return bp
