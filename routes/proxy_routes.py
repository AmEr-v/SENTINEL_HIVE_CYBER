from __future__ import annotations

from flask import Blueprint, Response, stream_with_context

from config import Config
from services.playback_db import PlaybackDB
from services.sse_proxy import stream_exporter_sse


def create_proxy_blueprint(config: Config, playback_db: PlaybackDB) -> Blueprint:
	bp = Blueprint("proxy", __name__)

	@bp.route("/ssh-stream-proxy")
	def ssh_stream_proxy():
		headers = {
			"Cache-Control": "no-cache",
			"Connection": "keep-alive",
			"X-Accel-Buffering": "no",
			"Content-Type": "text/event-stream",
		}
		return Response(
			stream_with_context(stream_exporter_sse(config, playback_db.enqueue_line)),
			headers=headers,
		)

	return bp
